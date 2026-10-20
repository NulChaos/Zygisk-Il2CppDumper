// Memory dumper for games whose libil2cpp.so has stripped/renamed il2cpp_* exports.
// Writes to <game_data_dir>/files/:
//   global-metadata.dat   (decrypted metadata found in memory, magic restored)
//   libil2cpp_dump.so     (libil2cpp.so image as mapped in memory)
//   dump_info.txt         (base address to give Il2CppDumper)

#include "mem_dump.h"
#include "log.h"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cinttypes>
#include <string>
#include <vector>
#include <algorithm>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <cerrno>

struct MapRegion {
    uint64_t start, end;
    char perms[5];
    std::string path;
};

static std::vector<MapRegion> read_maps() {
    std::vector<MapRegion> out;
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return out;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        MapRegion r{};
        char path[768] = {0};
        unsigned long long s, e;
        if (sscanf(line, "%llx-%llx %4s %*s %*s %*s %767[^\n]", &s, &e, r.perms, path) >= 3) {
            r.start = s;
            r.end = e;
            const char *p = path;
            while (*p == ' ') p++;
            r.path = p;
            out.push_back(r);
        }
    }
    fclose(f);
    return out;
}

// Safe read via process_vm_readv on our own pid: returns bytes read, never faults,
// and works even when the game marks itself non-dumpable (which locks /proc/self/mem).
static ssize_t safe_read(int /*unused*/, uint64_t addr, void *buf, size_t len) {
    size_t done = 0;
    const size_t PAGE = 4096;
    while (done < len) {
        size_t n = std::min(len - done, (size_t) (1 << 20));
        iovec local{(uint8_t *) buf + done, n};
        iovec remote{(void *) (addr + done), n};
        ssize_t r = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        if (r > 0) {
            done += r;
            continue;
        }
        // hit an unreadable page: try to skip it page by page
        if (n <= PAGE) break;
        size_t skip = PAGE - ((addr + done) % PAGE);
        memset((uint8_t *) buf + done, 0, std::min(skip, len - done));
        done += std::min(skip, len - done);
    }
    return (ssize_t) done;
}

static bool write_region(int memfd, uint64_t start, uint64_t end, const std::string &outPath,
                         const uint8_t *patchMagic) {
    FILE *o = fopen(outPath.c_str(), "wb");
    if (!o) {
        LOGE("memdump: cannot open %s", outPath.c_str());
        return false;
    }
    const size_t CH = 1 << 20;
    std::vector<uint8_t> buf(CH);
    bool first = true;
    for (uint64_t a = start; a < end; a += CH) {
        size_t want = (size_t) std::min<uint64_t>(CH, end - a);
        ssize_t got = safe_read(memfd, a, buf.data(), want);
        if (got < (ssize_t) want) {
            // unreadable gap: zero-fill
            if (got < 0) got = 0;
            memset(buf.data() + got, 0, want - got);
        }
        if (first && patchMagic) memcpy(buf.data(), patchMagic, 4);
        first = false;
        fwrite(buf.data(), 1, want, o);
    }
    fclose(o);
    return true;
}

// Heuristic header check for il2cpp metadata (v24+):
// [0]=magic [1]=version [2]=stringLiteralOffset [3]=stringLiteralSize
// [4]=stringLiteralDataOffset [5]=stringLiteralDataSize [6]=stringOffset
static bool looks_like_metadata(const int32_t *h, uint64_t avail) {
    int32_t ver = h[1];
    if (ver < 24 || ver > 39) return false;
    int32_t slo = h[2], sls = h[3], sldo = h[4], slds = h[5], so = h[6];
    if (slo < 0xC0 || slo > 0x400 || (slo & 3)) return false;
    if (sls <= 0 || slds <= 0) return false;
    if (sldo != slo + sls) return false;
    if (so != sldo + slds) return false;
    if ((uint64_t) so > avail) return false;
    return true;
}

void mem_dump(const char *game_data_dir) {
    std::string outDir = std::string(game_data_dir) + "/files/";
    int memfd = -1;
    {
        uint8_t probe[4];
        iovec l{probe, 4}, r{(void *) &probe, 4};
        if (process_vm_readv(getpid(), &l, 1, &r, 1, 0) != 4) {
            LOGE("memdump: process_vm_readv not permitted (errno %d)", errno);
            return;
        }
    }
    auto maps = read_maps();
    LOGI("memdump: %zu map regions", maps.size());

    // 1) libil2cpp.so image from memory
    uint64_t soStart = 0, soEnd = 0;
    for (auto &r: maps) {
        if (r.path.find("libil2cpp.so") != std::string::npos) {
            if (!soStart || r.start < soStart) soStart = r.start;
            if (r.end > soEnd) soEnd = r.end;
        }
    }
    // include the trailing anonymous .bss mapping if adjacent
    for (auto &r: maps) {
        if (r.start == soEnd && r.path.empty()) soEnd = r.end;
    }
    if (soStart) {
        write_region(memfd, soStart, soEnd, outDir + "libil2cpp_dump.so", nullptr);
        LOGI("memdump: libil2cpp.so 0x%" PRIx64 "-0x%" PRIx64 " written", soStart, soEnd);
    } else {
        LOGW("memdump: libil2cpp.so not in maps");
    }

    // 2) scan readable regions for metadata header
    const uint8_t MAGIC[4] = {0xAF, 0x1B, 0xB1, 0xFA};
    int found = 0;
    std::vector<uint8_t> buf(1 << 20);
    std::string info;
    for (auto &r: maps) {
        if (found >= 3) break;
        if (r.perms[0] != 'r') continue;
        if (r.path.rfind("/dev/", 0) == 0 || r.path.find("[vvar]") != std::string::npos ||
            r.path.find("[vectors]") != std::string::npos ||
            r.path.find(".so") != std::string::npos || r.path.find(".apk") != std::string::npos ||
            r.path.find(".oat") != std::string::npos || r.path.find(".art") != std::string::npos ||
            r.path.find(".odex") != std::string::npos || r.path.find(".vdex") != std::string::npos ||
            r.path.find(".jar") != std::string::npos || r.path.find("dalvik") != std::string::npos)
            continue;
        uint64_t size = r.end - r.start;
        if (size < 0x10000) continue;
        for (uint64_t a = r.start; a < r.end && found < 3; a += buf.size()) {
            size_t want = (size_t) std::min<uint64_t>(buf.size(), r.end - a);
            ssize_t got = safe_read(memfd, a, buf.data(), want);
            if (got < 32) break;
            for (ssize_t i = 0; i + 32 <= got; i += 4) {
                auto h = (const int32_t *) (buf.data() + i);
                uint64_t here = a + i;
                if (!looks_like_metadata(h, r.end - here)) continue;
                bool magicOk = memcmp(buf.data() + i, MAGIC, 4) == 0;
                // metadata size = furthest (offset + size) pair in the header
                uint64_t avail = r.end - here, metaEnd = 0;
                int32_t hdrSize = h[2];
                if (i + hdrSize > got) continue;  // header split across chunks; rare
                for (int k = 2; k + 1 < hdrSize / 4; k += 2) {
                    int64_t off = h[k], sz = h[k + 1];
                    if (off < hdrSize || sz < 0 || (uint64_t) (off + sz) > avail) break;
                    metaEnd = std::max<uint64_t>(metaEnd, (uint64_t) (off + sz));
                }
                if (metaEnd < 0x1000) continue;
                char name[64];
                snprintf(name, sizeof(name), found == 0 ? "global-metadata.dat"
                                                        : "global-metadata_%d.dat", found);
                write_region(memfd, here, here + metaEnd, outDir + name, MAGIC);
                char line[256];
                snprintf(line, sizeof(line),
                         "%s: addr=0x%" PRIx64 " size=%" PRIu64 " version=%d magic=%s region=%s\n",
                         name, here, metaEnd, h[1], magicOk ? "intact" : "WIPED(restored)",
                         r.path.empty() ? "[anon]" : r.path.c_str());
                info += line;
                LOGI("memdump: %s", line);
                found++;
                if (found >= 3) break;
            }
        }
    }

    char hdr[256];
    snprintf(hdr, sizeof(hdr), "libil2cpp base: 0x%" PRIx64 "\nmetadata candidates: %d\n",
             soStart, found);
    info = std::string(hdr) + info;
    FILE *f = fopen((outDir + "dump_info.txt").c_str(), "w");
    if (f) {
        fputs(info.c_str(), f);
        fclose(f);
    }
    LOGI("memdump: done, %d metadata candidate(s)", found);
}

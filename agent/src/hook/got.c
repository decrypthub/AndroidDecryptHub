// GOT/PLT relocation parsing, slot replacement, and in-memory symbol lookup.
// Kept independent from capture policy: callers provide module, symbol, and wrapper.

#include "got.h"
#include "../bootstrap/agent_internal.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>

// ---- GOT/PLT hook engine (E.8.1) -----------------------------------------
// Replace the GOT slot that holds `orig` with `wrapper` in modules matching name.
// Linear scan over non-exec segments (incl. RELRO). Hooks EXACTLY the first match
// (lowest address = the real .got.plt/RELRO slot); replacing duplicate copies in
// other data segments corrupts the original's own call path, so we stop at one.
// Parse a maps perms string ("r--p"/"rw-p") into an mprotect flag set.
static int perms_to_prot(const char *perms) {
    int prot = 0;
    if (perms[0] == 'r') prot |= PROT_READ;
    if (perms[1] == 'w') prot |= PROT_WRITE;
    if (perms[2] == 'x') prot |= PROT_EXEC;
    return prot;
}

// Swap one slot: temporarily make its page writable, publish the new pointer with a
// full barrier, then RESTORE the page's original protection. RELRO (r--) is put back
// read-only so we neither weaken the linker's RELRO hardening nor leave a rw-flipped
// page that an integrity self-check could flag. Returns 1 on success, 0 if not writable.
static int got_write_slot(void **slot, void *newval, int orig_prot, long pagesz) {
    void *page = (void *)((unsigned long long)slot & ~((unsigned long long)pagesz - 1));
    if (mprotect(page, pagesz, PROT_READ | PROT_WRITE) != 0) return 0;
    *slot = newval;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);   // publish before restoring protection
    mprotect(page, pagesz, orig_prot);         // RELRO r-- goes back to r--
    return 1;
}

// Debug/verification: last successfully-hooked slot + its original maps perms, so a
// self-test can confirm the page protection was restored (RELRO r-- stays r--).
static unsigned long long g_dbg_slot = 0;
static char g_dbg_orig_perms[8] = "";

// Read the maps perms string ("r--p") of the mapping containing `addr`. "?" if unmapped.
static void perms_of_addr(unsigned long long addr, char *out, int outsz) {
    snprintf(out, outsz, "?");
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return;
    char line[512];
    while (fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8];
        if (sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s", sa, ea, perms) < 3) continue;
        unsigned long long s = strtoull(sa, NULL, 16), e = strtoull(ea, NULL, 16);
        if (addr >= s && addr < e) { snprintf(out, outsz, "%s", perms); break; }
    }
    fclose(m);
}

// ---- relocation-slot cross-verification (v2.x audit P1) --------------------
// got_replace used to patch ANY readable non-exec word equal to `orig`. On a large obfuscated
// .so a coincidental data word == the function address would be clobbered into a wrapper ->
// memory corruption / crash. These helpers enumerate the module's REAL GOT/PLT relocation
// slots (.rela.plt + .rela.dyn) so we only ever patch genuine relocation entries.
#define RSET_MAX 262144   // per-module reloc-slot cap (~2 MiB transient); truncation -> fallback

static unsigned long long module_base_of(const char *basename) {
    unsigned long long base = 0;
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return 0;
    char line[512];
    while (fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8], off[32], dev[16], path[400] = "";
        unsigned long long inode = 0;
        if (sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s %31s %15s %llu %399[^\n]", sa, ea, perms, off, dev, &inode, path) < 6) continue;
        char *pp = path; while (*pp == ' ') pp++;
        const char *bn = strrchr(pp, '/'); bn = bn ? bn + 1 : pp;
        if (strcmp(bn, basename) != 0) continue;
        if (strcmp(off, "0") && strcmp(off, "00000000")) continue;   // mapping at file offset 0
        unsigned long long s = strtoull(sa, NULL, 16);
        if (base == 0 || s < base) base = s;
    }
    fclose(m);
    return base;
}

// Fill out[] with absolute reloc-slot addresses of the module based at `base`. Returns count,
// -1 if ELF/dynamic unparsable, or RSET_MAX on truncation (caller treats as untrusted).
// Elf64_Rela = { r_offset(8), r_info(8), r_addend(8) } = 24 bytes.
static int reloc_slots(unsigned long long base, unsigned long long *out, int max) {
    if (!base) return -1;
    unsigned char *p = (unsigned char *)base;
    if (memcmp(p, "\x7f""ELF", 4) != 0) return -1;
    unsigned long long phoff = *(unsigned long long *)(p + 32);
    unsigned short phentsize = *(unsigned short *)(p + 54);
    unsigned short phnum = *(unsigned short *)(p + 56);
    unsigned long long dyn_vaddr = 0;
    for (int i = 0; i < phnum; i++) {
        unsigned char *ph = p + phoff + (unsigned long long)i * phentsize;
        if (*(unsigned int *)ph == 2) { dyn_vaddr = *(unsigned long long *)(ph + 16); break; }  // PT_DYNAMIC
    }
    if (!dyn_vaddr) return -1;
    unsigned long long jmprel = 0, pltrelsz = 0, rela = 0, relasz = 0, relaent = 24;
    unsigned long long *d = (unsigned long long *)(base + dyn_vaddr);
    for (; d[0] != 0; d += 2) {                 // Elf64_Dyn: {d_tag, d_val}
        if (d[0] == 23) jmprel = d[1];          // DT_JMPREL   (.rela.plt)
        else if (d[0] == 2)  pltrelsz = d[1];   // DT_PLTRELSZ
        else if (d[0] == 7)  rela = d[1];       // DT_RELA     (.rela.dyn)
        else if (d[0] == 8)  relasz = d[1];     // DT_RELASZ
        else if (d[0] == 9)  relaent = d[1];    // DT_RELAENT
    }
    if (relaent == 0) relaent = 24;
    int n = 0;
    unsigned long long regions[2][2] = { { jmprel, pltrelsz }, { rela, relasz } };
    for (int r = 0; r < 2; r++) {
        unsigned long long off = regions[r][0], sz = regions[r][1];
        if (!off || !sz) continue;
        if (off < base) off += base;                 // link-time vaddr -> runtime
        for (unsigned long long e = off; e + relaent <= off + sz; e += relaent) {
            if (n >= max) return RSET_MAX;           // truncated -> untrusted
            unsigned long long r_offset = *(unsigned long long *)e;
            out[n++] = r_offset < base ? base + r_offset : r_offset;
        }
    }
    return n;
}

static int slot_in_set(unsigned long long a, const unsigned long long *set, int n) {
    for (int i = 0; i < n; i++) if (set[i] == a) return 1;
    return 0;
}

// Hook the real slot in EVERY matching caller module (not just the first). Exactly one
// slot PER module (lowest-address RELRO/.got.plt slot) — hooking duplicate copies in a
// module's other data segments would corrupt that module's own call path and deadlock
// the trampoline. Returns total slots replaced. Generalizes over multiple callers; for
// a filter that matches a single module it reduces to hooking that one slot.
int idh_got_replace(const char *module_substr, void *orig, void *wrapper) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return -1;
    char line[512];
    int replaced = 0;
    long pagesz = sysconf(_SC_PAGESIZE);
    char cur_mod[400] = "";
    int hooked_this_mod = 0;
    unsigned long long *rset = NULL; int nrset = -1;   // cur_mod reloc slots (-1 = unavailable)
    while (fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8], off[32], dev[16], path[400] = "";
        unsigned long long inode = 0;
        int nf = sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s %31s %15s %llu %399[^\n]", sa, ea, perms, off, dev, &inode, path);
        if (nf < 6 || perms[0] != 'r') continue;
        char *pp = path; while (*pp == ' ') pp++;
        // Only file-backed ELF modules (absolute path) hold GOT/reloc slots. Skip anonymous
        // / [stack] / [anon:*] / JIT regions — matters when module_substr=="" (scan all
        // modules): reloc validation is unavailable for pathless regions, so the value-match
        // fallback could clobber a coincidental data word == orig. Named-module callers are
        // unaffected (their matches were already absolute paths).
        if (pp[0] != '/') continue;
        if (!strstr(pp, module_substr)) continue;
        if (strcmp(pp, cur_mod) != 0) {
            snprintf(cur_mod, sizeof(cur_mod), "%s", pp); hooked_this_mod = 0;
            // (re)compute this module's real relocation slots, so we never clobber a
            // coincidental data word == orig. If unparsable/truncated, fall back (logged).
            free(rset); rset = NULL; nrset = -1;
            const char *bn = strrchr(cur_mod, '/'); bn = bn ? bn + 1 : cur_mod;
            unsigned long long mb = module_base_of(bn);
            if (mb) {
                rset = (unsigned long long *)malloc(sizeof(unsigned long long) * RSET_MAX);
                if (rset) {
                    nrset = reloc_slots(mb, rset, RSET_MAX);
                    if (nrset < 0 || nrset >= RSET_MAX) { free(rset); rset = NULL; nrset = -1; }
                }
            }
            if (nrset < 0) LOGI("got_replace: reloc validation unavailable for %s — value-match fallback", bn);
        }
        if (hooked_this_mod) continue;                    // one slot per module already done
        if (strstr(perms, "x")) continue;
        int orig_prot = perms_to_prot(perms);
        unsigned long long start = strtoull(sa, NULL, 16), end = strtoull(ea, NULL, 16);
        if (end <= start) continue;
        for (unsigned long long a = start; a + sizeof(void *) <= end && !hooked_this_mod; a += sizeof(void *)) {
            void **slot = (void **)a;
            if (*slot != orig) continue;
            // cross-verify this is a genuine relocation slot (skip coincidental data words).
            // When reloc parsing was unavailable (nrset<0) we accept the value match as before.
            if (nrset >= 0 && !slot_in_set(a, rset, nrset)) continue;
            if (got_write_slot(slot, wrapper, orig_prot, pagesz)) {
                replaced++; hooked_this_mod = 1;
                g_dbg_slot = a; snprintf(g_dbg_orig_perms, sizeof(g_dbg_orig_perms), "%s", perms);
            }
        }
    }
    free(rset);
    fclose(m);
    return replaced;
}

// got_replace matches a reloc slot by its CURRENTLY-BOUND VALUE (slot == orig). That only
// works once the dynamic linker has lazily bound the slot, i.e. after the app has already
// called that symbol at least once — for rarely-invoked entry points (RSA/AEAD one-shot
// APIs vs. the streaming Update() calls that fire constantly) capture_start typically runs
// BEFORE any such call, so the slot still points at the PLT resolver stub and value-match
// finds nothing even though the symbol is genuinely imported. Fix: resolve the slot from the
// module's OWN relocation table by symbol NAME (r_info -> that module's .dynsym/.dynstr),
// which is correct whether or not the slot has been bound yet.
static long long sleb128_decode(unsigned char **pp, unsigned char *end) {
    unsigned char *p = *pp;
    unsigned long long result = 0;
    int shift = 0;
    unsigned char byte;
    do {
        if (p >= end) { *pp = p; return 0; }
        byte = *p++;
        result |= ((unsigned long long)(byte & 0x7f)) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < 64 && (byte & 0x40)) result |= (~0ULL << shift);
    *pp = p;
    return (long long)result;
}

// AOSP system libs (incl. libjavacrypto.so) pack .rela.dyn (GLOB_DAT-relocated symbols, e.g.
// EVP_PKEY_encrypt/EVP_AEAD_CTX_seal) via DT_ANDROID_RELA in bionic's "APS2" SLEB128
// group-delta format instead of a plain Elf64_Rela array — that's the default for every
// modern NDK-built .so, not a device quirk, so it has to be handled for broad coverage.
// Mirrors bionic/linker/linker_reloc_iterator.h's packed_reloc_iterator.
static void *find_packed_reloc_slot(unsigned long long base, unsigned long long android_rela,
                                     unsigned long long android_relasz,
                                     unsigned long long symtab, unsigned long long strtab,
                                     const char *sym_name) {
    if (!android_rela || android_relasz < 4) return NULL;
    unsigned char *p = (unsigned char *)android_rela;
    unsigned char *end = p + android_relasz;
    if (memcmp(p, "APS2", 4) != 0) return NULL;
    p += 4;
    long long relocation_count = sleb128_decode(&p, end);
    unsigned long long r_offset = (unsigned long long)sleb128_decode(&p, end);
    long long group_size = 0, group_flags = 0, group_index = 0;
    unsigned long long group_r_offset_delta = 0, group_r_info = 0;
    unsigned long long r_info = 0;
    for (long long i = 0; i < relocation_count && p <= end; i++) {
        if (group_index == group_size) {
            group_size = sleb128_decode(&p, end);
            group_flags = sleb128_decode(&p, end);
            group_r_offset_delta = 0;
            if (group_flags & 2) group_r_offset_delta = (unsigned long long)sleb128_decode(&p, end);
            if (group_flags & 1) group_r_info = (unsigned long long)sleb128_decode(&p, end);
            if ((group_flags & 8) && (group_flags & 4)) sleb128_decode(&p, end);  // group addend delta, unused
            group_index = 0;
        }
        if (group_flags & 2) r_offset += group_r_offset_delta;
        else r_offset += (unsigned long long)sleb128_decode(&p, end);
        if (group_flags & 1) r_info = group_r_info;
        else r_info = (unsigned long long)sleb128_decode(&p, end);
        if ((group_flags & 8) && !(group_flags & 4)) sleb128_decode(&p, end);  // per-element addend delta, unused
        group_index++;
        unsigned int sym_idx = (unsigned int)(r_info >> 32);   // ELF64_R_SYM
        if (sym_idx != 0) {
            unsigned char *symrec = (unsigned char *)(symtab + (unsigned long long)sym_idx * 24);  // Elf64_Sym
            unsigned int st_name = *(unsigned int *)symrec;
            const char *name = (const char *)(strtab + st_name);
            if (strcmp(name, sym_name) == 0) {
                unsigned long long slot_addr = r_offset < base ? base + r_offset : r_offset;
                return (void *)slot_addr;
            }
        }
    }
    return NULL;
}

static void *find_reloc_slot_by_symbol(unsigned long long base, const char *sym_name) {
    if (!base) return NULL;
    unsigned char *p = (unsigned char *)base;
    if (memcmp(p, "\x7f""ELF", 4) != 0) return NULL;
    unsigned long long phoff = *(unsigned long long *)(p + 32);
    unsigned short phentsize = *(unsigned short *)(p + 54);
    unsigned short phnum = *(unsigned short *)(p + 56);
    unsigned long long dyn_vaddr = 0;
    for (int i = 0; i < phnum; i++) {
        unsigned char *ph = p + phoff + (unsigned long long)i * phentsize;
        if (*(unsigned int *)ph == 2) { dyn_vaddr = *(unsigned long long *)(ph + 16); break; }  // PT_DYNAMIC
    }
    if (!dyn_vaddr) return NULL;
    unsigned long long jmprel = 0, pltrelsz = 0, rela = 0, relasz = 0, relaent = 24, symtab = 0, strtab = 0;
    unsigned long long android_rela = 0, android_relasz = 0;
    unsigned long long *d = (unsigned long long *)(base + dyn_vaddr);
    for (; d[0] != 0; d += 2) {
        if (d[0] == 23) jmprel = d[1];        // DT_JMPREL
        else if (d[0] == 2)  pltrelsz = d[1]; // DT_PLTRELSZ
        else if (d[0] == 7)  rela = d[1];     // DT_RELA
        else if (d[0] == 8)  relasz = d[1];   // DT_RELASZ
        else if (d[0] == 9)  relaent = d[1];  // DT_RELAENT
        else if (d[0] == 6)  symtab = d[1];   // DT_SYMTAB
        else if (d[0] == 5)  strtab = d[1];   // DT_STRTAB
        else if (d[0] == 0x60000011ULL) android_rela = d[1];    // DT_ANDROID_RELA
        else if (d[0] == 0x60000012ULL) android_relasz = d[1];  // DT_ANDROID_RELASZ
    }
    if (relaent == 0) relaent = 24;
    if (!symtab || !strtab) return NULL;
    if (symtab < base) symtab += base;
    if (strtab < base) strtab += base;
    unsigned long long regions[2][2] = { { jmprel, pltrelsz }, { rela, relasz } };
    for (int r = 0; r < 2; r++) {
        unsigned long long off = regions[r][0], sz = regions[r][1];
        if (!off || !sz) continue;
        if (off < base) off += base;
        for (unsigned long long e = off; e + relaent <= off + sz; e += relaent) {
            unsigned long long r_offset = *(unsigned long long *)e;
            unsigned long long r_info   = *(unsigned long long *)(e + 8);
            unsigned int sym_idx = (unsigned int)(r_info >> 32);   // ELF64_R_SYM
            if (sym_idx == 0) continue;
            unsigned char *symrec = (unsigned char *)(symtab + (unsigned long long)sym_idx * 24);  // Elf64_Sym
            unsigned int st_name = *(unsigned int *)symrec;
            const char *name = (const char *)(strtab + st_name);
            if (strcmp(name, sym_name) != 0) continue;
            unsigned long long slot_addr = r_offset < base ? base + r_offset : r_offset;
            return (void *)slot_addr;
        }
    }
    if (android_rela) {
        if (android_rela < base) android_rela += base;
        void *slot = find_packed_reloc_slot(base, android_rela, android_relasz, symtab, strtab, sym_name);
        if (slot) return slot;
    }
    return NULL;
}

// Same module-scan shape as got_replace, but resolves the slot by symbol name instead of by
// value — works for symbols whose PLT slot hasn't been lazily bound yet. One slot per
// matching module (mirrors got_replace's one-slot-per-module rule).
int idh_got_replace_by_name(const char *module_substr, const char *sym_name, void *wrapper) {
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return -1;
    char line[512];
    int replaced = 0;
    long pagesz = sysconf(_SC_PAGESIZE);
    char cur_mod[400] = "";
    while (fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8], off[32], dev[16], path[400] = "";
        unsigned long long inode = 0;
        int nf = sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s %31s %15s %llu %399[^\n]", sa, ea, perms, off, dev, &inode, path);
        if (nf < 6) continue;
        char *pp = path; while (*pp == ' ') pp++;
        if (pp[0] != '/') continue;
        if (!strstr(pp, module_substr)) continue;
        if (strcmp(pp, cur_mod) == 0) continue;   // already handled this module (multiple mappings per .so)
        snprintf(cur_mod, sizeof(cur_mod), "%s", pp);
        const char *bn = strrchr(cur_mod, '/'); bn = bn ? bn + 1 : cur_mod;
        unsigned long long mb = module_base_of(bn);
        if (!mb) continue;
        void *slot_addr = find_reloc_slot_by_symbol(mb, sym_name);
        if (!slot_addr) continue;
        char permsOf[8]; perms_of_addr((unsigned long long)slot_addr, permsOf, sizeof(permsOf));
        if (permsOf[0] == '?') continue;   // slot address not actually mapped — refuse to touch it
        int orig_prot = perms_to_prot(permsOf);
        if (got_write_slot((void **)slot_addr, wrapper, orig_prot, pagesz)) {
            replaced++;
            g_dbg_slot = (unsigned long long)slot_addr;
            snprintf(g_dbg_orig_perms, sizeof(g_dbg_orig_perms), "%s", permsOf);
        }
    }
    fclose(m);
    return replaced;
}

// --- self-test target: hook the agent's own close() (plain syscall wrapper) ---
static void *g_orig_close = NULL;
static volatile int g_close_hits = 0;
static int my_close(int fd) {
    __atomic_add_fetch(&g_close_hits, 1, __ATOMIC_RELAXED);
    typedef int (*close_t)(int);
    return ((close_t)g_orig_close)(fd);
}

void idh_cmd_gothook_selftest(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    void *libc = dlopen("libc.so", RTLD_NOW);
    void *orig = libc ? dlsym(libc, "close") : NULL;
    g_orig_close = orig;
    g_dbg_slot = 0; g_dbg_orig_perms[0] = 0;
    int replaced = orig ? idh_got_replace("libidh_agent.so", orig, (void *)my_close) : -1;
    // While still hooked: read the hooked slot's page perms. got_write_slot restores the
    // page's original protection after publishing, so RELRO (r--) must read back r-- —
    // proving we don't leave the page rw-flipped (weakened RELRO / integrity-check bait).
    char slotPerms[8] = "?"; if (g_dbg_slot) perms_of_addr(g_dbg_slot, slotPerms, sizeof(slotPerms));
    int restored = (g_dbg_orig_perms[0] && strncmp(slotPerms, g_dbg_orig_perms, 3) == 0) ? 1 : 0;
    int before = g_close_hits;
    // trigger a controlled close() from agent code -> routes through the hooked GOT slot
    int tfd = open("/proc/self/stat", O_RDONLY);
    if (tfd >= 0) close(tfd);
    int after = g_close_hits;
    if (replaced > 0 && orig) idh_got_replace("libidh_agent.so", (void *)my_close, orig);  // restore
    char out[320];
    snprintf(out, sizeof(out),
        "{\"t\":\"cmdResult\",\"id\":\"%s\",\"op\":\"gothook_selftest\",\"ok\":true,\"replaced\":%d,\"hitsBefore\":%d,\"hitsAfter\":%d,\"fired\":%s,\"origPerms\":\"%s\",\"slotPerms\":\"%s\",\"protRestored\":%s}\n",
        idj, replaced, before, after, (after > before) ? "true" : "false", g_dbg_orig_perms, slotPerms, restored ? "true" : "false");
    send_line(fd, out);
    LOGI("gothook_selftest: replaced=%d hits=%d fired=%d", replaced, after - before, after > before);
}

// Resolve an exported symbol in an already-loaded module by parsing its in-memory
// dynamic symbol table (namespace-independent; works when dlopen is blocked).
static void *resolve_sym_ex(const char *mod_substr, const char *symbol, int prefix) {
    unsigned long long base = 0;
    FILE *m = fopen("/proc/self/maps", "r");
    if (!m) return NULL;
    char line[512];
    while (fgets(line, sizeof(line), m)) {
        char sa[32], ea[32], perms[8], off[32], dev[16], path[400] = "";
        unsigned long long inode = 0;
        if (sscanf(line, "%31[0-9a-f]-%31[0-9a-f] %7s %31s %15s %llu %399[^\n]", sa, ea, perms, off, dev, &inode, path) < 6) continue;
        char *pp = path; while (*pp == ' ') pp++;
        const char *bn = strrchr(pp, '/'); bn = bn ? bn + 1 : pp;
        if (strcmp(bn, mod_substr) != 0) continue;                   // exact basename match
        if (strcmp(off, "0") && strcmp(off, "00000000")) continue;   // want the mapping at file offset 0 (ELF header)
        unsigned long long s = strtoull(sa, NULL, 16);
        if (base == 0 || s < base) base = s;
    }
    fclose(m);
    if (!base) return NULL;
    unsigned char *p = (unsigned char *)base;
    if (memcmp(p, "\x7f""ELF", 4) != 0) return NULL;
    unsigned long long phoff = *(unsigned long long *)(p + 32);
    unsigned short phentsize = *(unsigned short *)(p + 54);
    unsigned short phnum = *(unsigned short *)(p + 56);
    unsigned long long dyn_vaddr = 0;
    for (int i = 0; i < phnum; i++) {
        unsigned char *ph = p + phoff + (unsigned long long)i * phentsize;
        if (*(unsigned int *)ph == 2) { dyn_vaddr = *(unsigned long long *)(ph + 16); break; }  // PT_DYNAMIC
    }
    if (!dyn_vaddr) return NULL;
    unsigned long long symtab = 0, strtab = 0, hash = 0, gnuhash = 0;
    unsigned long long *d = (unsigned long long *)(base + dyn_vaddr);
    for (; d[0] != 0; d += 2) {                // Elf64_Dyn: {d_tag, d_val}
        if (d[0] == 6) symtab = d[1];          // DT_SYMTAB
        else if (d[0] == 5) strtab = d[1];     // DT_STRTAB
        else if (d[0] == 4) hash = d[1];       // DT_HASH
        else if (d[0] == 0x6ffffef5ULL) gnuhash = d[1]; // DT_GNU_HASH
    }
    if (!symtab || !strtab) return NULL;
    if (symtab < base) symtab += base;         // link-time vaddr -> runtime
    if (strtab < base) strtab += base;
    if (hash && hash < base) hash += base;
    if (gnuhash && gnuhash < base) gnuhash += base;

    // Dynsym count, preferred sources in order of rigor:
    //  1) DT_HASH: nchain (= number of dynsym entries) is the 2nd word.
    //  2) DT_GNU_HASH: walk the last bucket's chain until the terminator bit.
    //  3) fallback: (strtab - symtab)/sizeof(Elf64_Sym) — assumes .dynstr abuts .dynsym.
    long count = 0;
    if (hash) {
        count = (long)((unsigned int *)hash)[1];         // nchain
    } else if (gnuhash) {
        unsigned int *gh = (unsigned int *)gnuhash;
        unsigned int nbuckets = gh[0], symoffset = gh[1], bloom_size = gh[2];
        unsigned long long *bloom = (unsigned long long *)&gh[4];   // ELF64: 8-byte bloom words
        unsigned int *buckets = (unsigned int *)&bloom[bloom_size];
        unsigned int *chain = &buckets[nbuckets];
        unsigned int last = 0;
        for (unsigned int i = 0; i < nbuckets; i++) if (buckets[i] > last) last = buckets[i];
        if (last < symoffset) count = symoffset;
        else { while (!(chain[last - symoffset] & 1)) last++; count = (long)last + 1; }
    } else {
        if (strtab <= symtab) return NULL;
        count = (long)((strtab - symtab) / 24);
    }
    if (count <= 0 || count > 300000) {
        if (strtab <= symtab) return NULL;               // last-resort sanity fallback
        count = (long)((strtab - symtab) / 24);
        if (count <= 0 || count > 300000) return NULL;
    }
    for (long i = 0; i < count; i++) {
        unsigned char *sym = (unsigned char *)(symtab + (unsigned long long)i * 24);
        unsigned int st_name = *(unsigned int *)sym;
        unsigned long long st_value = *(unsigned long long *)(sym + 8);
        const char *name = (const char *)(strtab + st_name);
        if (st_value && (prefix ? strncmp(name, symbol, strlen(symbol)) == 0 : strcmp(name, symbol) == 0))
            return (void *)(base + st_value);
    }
    return NULL;
}
// Exact-match resolver (original behavior) + a prefix variant, plus C-ABI wrappers used by
// the C++ LSPlant shim (java_lsplant.cpp) for ART symbol resolution (some ART symbols must be
// matched by prefix because the mangled std::__1 allocator spelling varies across ROMs).
void *idh_resolve_sym(const char *mod, const char *sym) { return resolve_sym_ex(mod, sym, 0); }
void *idh_resolve_sym_prefix(const char *mod, const char *pre) { return resolve_sym_ex(mod, pre, 1); }

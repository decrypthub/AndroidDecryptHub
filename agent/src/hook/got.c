// GOT/PLT relocation parsing, slot replacement, and in-memory symbol lookup.
// Kept independent from capture policy: callers provide module, symbol, and wrapper.

#include "got.h"
#include "../bootstrap/agent_internal.h"

#include <dlfcn.h>
#include <link.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

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

// Swap one pointer-sized slot that lives in a read-only mapping (RELRO / const data): the
// page is made writable, the new value published with a full barrier, then the mapping's
// original protection is restored. Used by the JNIEnv function-table hooks, whose entries
// are const data in libart. Returns 1 on success, 0 when the address is unmapped or the
// page could not be made writable.
int adh_swap_pointer_in_ro_page(void **slot, void *newval) {
    if (!slot) return 0;
    long pagesz = sysconf(_SC_PAGESIZE);
    if (pagesz <= 0) pagesz = 4096;
    char perms[8];
    perms_of_addr((unsigned long long)(uintptr_t)slot, perms, sizeof(perms));
    if (perms[0] == '?') return 0;
    if (perms[1] == 'w') {                 // already writable: plain aligned store
        *slot = newval;
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        return 1;
    }
    return got_write_slot(slot, newval, perms_to_prot(perms), pagesz);
}

// Patch raw code bytes in place: make every page covering [addr, addr+len) writable (keeping X),
// memcpy, flush the instruction cache and restore the original protection. Used to write a saved
// original prologue back over an inline hook without asking Dobby to free its trampoline pool
// (DobbyDestroy makes later DobbyHook calls in the same process unreliable on this build).
int adh_patch_code_bytes(void *addr, const void *bytes, size_t len) {
    if (!addr || !bytes || !len) return 0;
    long pagesz = sysconf(_SC_PAGESIZE);
    if (pagesz <= 0) pagesz = 4096;
    uintptr_t start = (uintptr_t)addr;
    uintptr_t page_start = start & ~((uintptr_t)pagesz - 1);
    uintptr_t end = start + len - 1;
    uintptr_t page_end = end & ~((uintptr_t)pagesz - 1);
    size_t span = (size_t)(page_end - page_start) + (size_t)pagesz;
    char perms[8];
    perms_of_addr(start, perms, sizeof(perms));
    if (perms[0] == '?') return 0;
    int orig_prot = perms_to_prot(perms);
    if (mprotect((void *)page_start, span, orig_prot | PROT_WRITE) != 0) return 0;
    memcpy(addr, bytes, len);
    __builtin___clear_cache((char *)addr, (char *)addr + len);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return mprotect((void *)page_start, span, orig_prot) == 0;
}

// Copy the /proc/self/maps permission string ("r--p") of the mapping containing addr, or
// "?" when the address is unmapped. Callers use this to prove a page that had to be made
// writable for a slot swap was restored to its original protection.
void adh_perms_of_addr(void *addr, char *out, int out_size) {
    if (!out || out_size <= 0) return;
    perms_of_addr((unsigned long long)(uintptr_t)addr, out, out_size);
}

// ---- relocation-slot cross-verification (v2.x audit P1) --------------------
// got_replace used to patch ANY readable non-exec word equal to `orig`. On a large obfuscated
// .so a coincidental data word == the function address would be clobbered into a wrapper ->
// memory corruption / crash. These helpers enumerate the module's REAL GOT/PLT relocation
// slots (.rela.plt + .rela.dyn) so we only ever patch genuine relocation entries.
#define RSET_MAX 262144   // per-module reloc-slot cap (~2 MiB transient); truncation -> fallback

// Module base lookup. Accepts a basename ("libadhdetect.so") or a full /proc/self/maps
// path: the reloc scan below feeds it a maps path while the command layer passes a bare
// module name, and both must resolve to the same module (regression: passing a path made
// the by-name GOT replacement silently match nothing -> "hooked:0" with ok:true).
static unsigned long long module_base_of(const char *name) {
    if (!name || !name[0]) return 0;
    // Asking for OUR own module by name must never resolve to a different mapping that shares the
    // name (the memfd load path is "jit-cache", which ART's own JIT cache also uses): answer with
    // our own base. Derived per call - a second copy in the same process must resolve to itself.
    Dl_info self;
    if (dladdr((void *)(uintptr_t)adh_self_module_name, &self) && self.dli_fbase) {
        const char *mine = self.dli_fname ? strrchr(self.dli_fname, '/') : NULL;
        mine = mine ? mine + 1 : (self.dli_fname && self.dli_fname[0] ? self.dli_fname : "");
        const char *wanted = strrchr(name, '/');
        wanted = wanted ? wanted + 1 : name;
        if (mine[0] && strcmp(mine, wanted) == 0) return (unsigned long long)(uintptr_t)self.dli_fbase;
    }
    const char *slash = strrchr(name, '/');
    const char *wanted = slash ? slash + 1 : name;
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
        if (strcmp(bn, wanted) != 0) continue;
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
int adh_got_replace(const char *module_substr, void *orig, void *wrapper) {
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

// AOSP system libs (the JCE provider's native library among them) pack .rela.dyn (GLOB_DAT-relocated
// symbols, e.g. EVP_PKEY_encrypt/EVP_AEAD_CTX_seal) via DT_ANDROID_RELA in bionic's "APS2" SLEB128
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

// Find one relocation slot by symbol name and return its current resolved value. Used by the
// native hook manager when the target symbol is imported rather than defined by the module.
// Is addr one of this module's relocation (GOT) slots? A patched data slot that a relocation writes
// is a GOT entry - and patching it also changes what &symbol resolves to inside that module - while
// anything else is plain data (a vtable, a callback table). Reported per slot so the operator can
// see which kind they just rewrote. Only the unpacked relocation tables are consulted; a slot that
// lives in a packed (DT_ANDROID_RELA) table is reported as data.
int adh_got_is_slot(const char *module, void *addr) {
    if (!module || !module[0] || !addr) return 0;
    unsigned long long base = module_base_of(module);
    if (!base) return 0;
    unsigned char *p = (unsigned char *)base;
    if (memcmp(p, "\x7f" "ELF", 4) != 0) return 0;
    unsigned long long phoff = *(unsigned long long *)(p + 32);
    unsigned short phentsize = *(unsigned short *)(p + 54);
    unsigned short phnum = *(unsigned short *)(p + 56);
    unsigned long long dyn_vaddr = 0;
    for (int i = 0; i < phnum; i++) {
        unsigned char *ph = p + phoff + (unsigned long long)i * phentsize;
        if (*(unsigned int *)ph == 2) { dyn_vaddr = *(unsigned long long *)(ph + 16); break; }
    }
    if (!dyn_vaddr) return 0;
    unsigned long long jmprel = 0, pltrelsz = 0, rela = 0, relasz = 0, relaent = 24;
    unsigned long long *d = (unsigned long long *)(base + dyn_vaddr);
    for (; d[0] != 0; d += 2) {
        if (d[0] == 23) jmprel = d[1];
        else if (d[0] == 2) pltrelsz = d[1];
        else if (d[0] == 7) rela = d[1];
        else if (d[0] == 8) relasz = d[1];
        else if (d[0] == 9) relaent = d[1];
    }
    if (relaent == 0) relaent = 24;
    unsigned long long regions[2][2] = { { jmprel, pltrelsz }, { rela, relasz } };
    for (int r = 0; r < 2; r++) {
        unsigned long long off = regions[r][0], sz = regions[r][1];
        if (!off || !sz) continue;
        if (off < base) off += base;
        for (unsigned long long e = off; e + relaent <= off + sz; e += relaent) {
            unsigned long long r_offset = *(unsigned long long *)e;
            unsigned long long r_info = *(unsigned long long *)(e + 8);
            unsigned long long slot_addr = r_offset < base ? base + r_offset : r_offset;
            if (slot_addr != (unsigned long long)(uintptr_t)addr) continue;
            // Only the linker-managed import slots count as "GOT": R_AARCH64_GLOB_DAT (1025) and
            // R_AARCH64_JUMP_SLOT (1026). A data pointer that merely has a R_AARCH64_RELATIVE (1027)
            // fixup - e.g. a vtable - is plain data, and reporting it as GOT would be wrong.
            unsigned int type = (unsigned int)(r_info & 0xffffffffu);
            return (type == 1025u || type == 1026u) ? 1 : 0;
        }
    }
    return 0;
}

int adh_got_slot_value(const char *module, const char *symbol, void **slot_out, void **value_out) {
    if (slot_out) *slot_out = NULL;
    if (value_out) *value_out = NULL;
    if (!module || !symbol || !module[0] || !symbol[0]) return 0;
    unsigned long long base = module_base_of(module);
    if (!base) return 0;
    void *slot = find_reloc_slot_by_symbol(base, symbol);
    if (!slot) return 0;
    if (slot_out) *slot_out = slot;
    if (value_out) *value_out = *(void **)slot;
    return 1;
}
// Exact module-name matching: full path compares exactly; a bare basename compares the
// mapping's basename exactly (never a substring, so "libc" does not match "libcrypto.so").
static int module_path_matches(const char *path, const char *wanted) {
    if (!path || !wanted || !wanted[0]) return 0;
    if (strchr(wanted, '/')) return strcmp(path, wanted) == 0;
    const char *bn = strrchr(path, '/');
    bn = bn ? bn + 1 : path;
    return strcmp(bn, wanted) == 0;
}

// Same module-scan shape as got_replace, but resolves the slot by symbol name instead of by
// value — works for symbols whose PLT slot hasn't been lazily bound yet. Returns the number
// of matching modules actually replaced; the first replaced slot's address and previous value
// are returned through slot_out/value_out so callers can keep a matching trampoline.
int adh_got_replace_by_name_ex(const char *module_name, const char *sym_name, void *wrapper,
                               void **slot_out, void **value_out,
                               char *perms_before_out, size_t perms_before_size) {
    if (slot_out) *slot_out = NULL;
    if (value_out) *value_out = NULL;
    if (perms_before_out && perms_before_size) perms_before_out[0] = 0;
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
        if (!module_path_matches(pp, module_name)) continue;
        if (strcmp(pp, cur_mod) == 0) continue;   // already handled this module (multiple mappings per .so)
        snprintf(cur_mod, sizeof(cur_mod), "%s", pp);
        unsigned long long mb = module_base_of(cur_mod);
        if (!mb) continue;
        void *slot_addr = find_reloc_slot_by_symbol(mb, sym_name);
        if (!slot_addr) continue;
        char permsOf[8]; perms_of_addr((unsigned long long)slot_addr, permsOf, sizeof(permsOf));
        if (permsOf[0] == '?') continue;   // slot address not actually mapped — refuse to touch it
        int orig_prot = perms_to_prot(permsOf);
        void *old_value = *(void **)slot_addr;
        if (got_write_slot((void **)slot_addr, wrapper, orig_prot, pagesz)) {
            if (replaced == 0) {
                if (slot_out) *slot_out = slot_addr;
                if (value_out) *value_out = old_value;
                if (perms_before_out && perms_before_size)
                    snprintf(perms_before_out, perms_before_size, "%s", permsOf);
            }
            replaced++;
            g_dbg_slot = (unsigned long long)slot_addr;
            snprintf(g_dbg_orig_perms, sizeof(g_dbg_orig_perms), "%s", permsOf);
        }
    }
    fclose(m);
    return replaced;
}

int adh_got_replace_by_name(const char *module_name, const char *sym_name, void *wrapper) {
    return adh_got_replace_by_name_ex(module_name, sym_name, wrapper, NULL, NULL, NULL, 0);
}

// --- self-test target: hook the agent's own close() (plain syscall wrapper) ---
static void *g_orig_close = NULL;
static volatile int g_close_hits = 0;
static int my_close(int fd) {
    __atomic_add_fetch(&g_close_hits, 1, __ATOMIC_RELAXED);
    typedef int (*close_t)(int);
    return ((close_t)g_orig_close)(fd);
}

// Our own module name as it appears in /proc/self/maps. Derived from dladdr rather than hardcoded:
// the agent may be loaded from a memfd (zygisk memfd loading), in which case the path is
// "/memfd:jit-cache (deleted)" and a hardcoded "libadh_agent.so" lookup would find nothing.
// Resolved on EVERY call (no permanent cache): the agent can be loaded more than once in one
// process (self-load + zygisk), each copy seeing its own path, so a cached name would point one
// copy at the other. The buffer is thread-local for the same reason.
// Fallback self-name. Obfuscated on purpose: the target can read its own memory, so a plain
// literal here would hand a scanner our library name for free. Both the table and the key are
// volatile - without that an optimizing compiler folds the decode loop back into the plaintext.
static const volatile unsigned char k_self_name_enc[] = { 0x36, 0x33, 0x38, 0x3b, 0x3e, 0x32, 0x05, 0x3b, 0x3d, 0x3f, 0x34, 0x2e, 0x74, 0x29, 0x35 };
static const volatile unsigned char k_self_name_key = 0x5a;
static const char *self_name_fallback(void) {
    static __thread char plain[32];
    const size_t n = sizeof(k_self_name_enc);
    if (n + 1 > sizeof(plain)) { plain[0] = 0; return plain; }
    for (size_t i = 0; i < n; i++) plain[i] = (char)(k_self_name_enc[i] ^ k_self_name_key);
    plain[n] = 0;
    return plain;
}

const char *adh_self_module_name(void) {
    static __thread char cached[128];
    cached[0] = 0;
    Dl_info self;
    if (dladdr((void *)(uintptr_t)adh_self_module_name, &self) && self.dli_fname && self.dli_fname[0]) {
        const char *slash = strrchr(self.dli_fname, '/');
        snprintf(cached, sizeof(cached), "%s", slash ? slash + 1 : self.dli_fname);
        return cached;
    }
    snprintf(cached, sizeof(cached), "%s", self_name_fallback());
    return cached;
}

#ifndef NT_GNU_BUILD_ID
#define NT_GNU_BUILD_ID 3
#endif

// Everything we can learn about one mapped image from its phdr table: the [start,end) address range
// and the GNU build ID. Both come from a single pass over the phdrs, so a dl_iterate_phdr callback
// can describe each candidate without re-entering dl_iterate_phdr (bionic's recursive lock makes the
// nested form work, but it is undocumented and quadratic).
struct image_desc {
    const void *base;
    unsigned long long start;
    unsigned long long end;
    unsigned char build_id[64];
    size_t build_id_len;
    int found;
};

static void describe_phdrs(struct image_desc *d, const ElfW(Phdr) *ph, int phnum) {
    unsigned long long lo = ~0ULL, hi = 0;
    for (int i = 0; i < phnum; i++) {
        if (ph[i].p_type != PT_LOAD || !ph[i].p_memsz) continue;
        unsigned long long s = (unsigned long long)ph[i].p_vaddr;
        unsigned long long e = s + (unsigned long long)ph[i].p_memsz;
        if (s < lo) lo = s;
        if (e > hi) hi = e;
    }
    if (!hi || lo == ~0ULL) return;
    d->start = (unsigned long long)(uintptr_t)d->base + lo;
    d->end = (unsigned long long)(uintptr_t)d->base + hi;
    d->found = 1;
    // Notes live in PT_NOTE, which bionic maps together with the first PT_LOAD; walk them in memory.
    for (int i = 0; i < phnum && !d->build_id_len; i++) {
        if (ph[i].p_type != PT_NOTE || !ph[i].p_memsz) continue;
        const unsigned char *p = (const unsigned char *)((uintptr_t)d->base + (uintptr_t)ph[i].p_vaddr);
        size_t size = (size_t)ph[i].p_memsz;
        size_t off = 0;
        while (off + 12 <= size) {
            uint32_t namesz = 0, descsz = 0, type = 0;
            memcpy(&namesz, p + off, 4);
            memcpy(&descsz, p + off + 4, 4);
            memcpy(&type, p + off + 8, 4);
            off += 12;
            size_t name_off = ((size_t)namesz + 3u) & ~3u;
            size_t desc_off = ((size_t)descsz + 3u) & ~3u;
            if (off + name_off + desc_off > size) break;
            if (type == NT_GNU_BUILD_ID && namesz >= 3 && memcmp(p + off, "GNU", 3) == 0 && descsz) {
                size_t n = (size_t)descsz < sizeof(d->build_id) ? (size_t)descsz : sizeof(d->build_id);
                memcpy(d->build_id, p + off + name_off, n);
                d->build_id_len = n;
            }
            off += name_off + desc_off;
        }
    }
}

static int image_desc_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct image_desc *d = (struct image_desc *)data;
    if ((const void *)(uintptr_t)info->dlpi_addr != d->base) return 0;
    describe_phdrs(d, info->dlpi_phdr, (int)info->dlpi_phnum);
    return 1;
}

static void image_describe(const void *base, struct image_desc *d) {
    memset(d, 0, sizeof(*d));
    d->base = base;
    if (base) dl_iterate_phdr(image_desc_cb, d);
}

int adh_image_bounds_of(const void *base, unsigned long long *start, unsigned long long *end) {
    if (!base) return 0;
    struct image_desc d;
    image_describe(base, &d);
    if (!d.found) return 0;
    if (start) *start = d.start;
    if (end) *end = d.end;
    return 1;
}

int adh_build_id_of(const void *base, unsigned char *out, size_t cap, size_t *len) {
    if (!base) return 0;
    struct image_desc d;
    image_describe(base, &d);
    if (!d.build_id_len) return 0;
    if (len) *len = d.build_id_len;
    if (out && cap) memcpy(out, d.build_id, d.build_id_len < cap ? d.build_id_len : cap);
    return 1;
}

int adh_build_id_from_phdr(const void *base, const ElfW(Phdr) *phdrs, int phnum,
                           unsigned char *out, size_t cap, size_t *len) {
    if (!base || !phdrs || phnum <= 0) return 0;
    struct image_desc d;
    memset(&d, 0, sizeof(d));
    d.base = base;
    describe_phdrs(&d, phdrs, phnum);
    if (!d.build_id_len) return 0;
    if (len) *len = d.build_id_len;
    if (out && cap) memcpy(out, d.build_id, d.build_id_len < cap ? d.build_id_len : cap);
    return 1;
}

int adh_self_image_bounds(unsigned long long *start, unsigned long long *end) {
    Dl_info self;
    if (!dladdr((void *)(uintptr_t)adh_self_module_name, &self) || !self.dli_fbase) return 0;
    return adh_image_bounds_of(self.dli_fbase, start, end);
}

int adh_self_build_id(unsigned char *out, size_t cap, size_t *len) {
    Dl_info self;
    if (!dladdr((void *)(uintptr_t)adh_self_module_name, &self) || !self.dli_fbase) return 0;
    return adh_build_id_of(self.dli_fbase, out, cap, len);
}

static const char *self_module_name(void) {
    return adh_self_module_name();
}

void adh_cmd_gothook_selftest(int fd, const char *id) {
    char idj[64]; json_escape(id, idj, sizeof(idj));
    const char *self_lib = self_module_name();
    void *libc = dlopen("libc.so", RTLD_NOW);
    void *orig = libc ? dlsym(libc, "close") : NULL;
    g_orig_close = orig;
    g_dbg_slot = 0; g_dbg_orig_perms[0] = 0;
    int replaced = orig ? adh_got_replace(self_lib, orig, (void *)my_close) : -1;
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
    if (replaced > 0 && orig) adh_got_replace(self_lib, (void *)my_close, orig);  // restore
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
// Exact-match resolver (original behavior) plus a prefix variant used for symbols whose
// mangled spelling varies across ROM/ABI versions.
void *adh_resolve_sym(const char *mod, const char *sym) { return resolve_sym_ex(mod, sym, 0); }
void *adh_resolve_sym_prefix(const char *mod, const char *pre) { return resolve_sym_ex(mod, pre, 1); }

int adh_addr_is_executable(void *addr) {
    if (!addr) return 0;
    char perms[8];
    perms_of_addr((unsigned long long)(uintptr_t)addr, perms, sizeof(perms));
    return perms[0] != '?' && perms[2] == 'x';
}
// Enumerate relocation/GOT entries for one loaded module. Plain Elf64_RELA/JMPREL entries are
// emitted with slot/symbol/current value; Android packed RELA is reported explicitly but not
// expanded yet (fail-loud rather than pretending the table is complete).
static const char *reloc_type_name(unsigned long long type) {
    switch (type) {
        case 1025: return "GLOB_DAT";
        case 1026: return "JUMP_SLOT";
        case 257: return "ABS64";
        default: return "OTHER";
    }
}

int adh_got_enum_json(const char *module, const char *filter, char **out_json,
                      char *error, size_t error_size) {
    if (out_json) *out_json = NULL;
    if (!module || !module[0]) {
        snprintf(error, error_size, "need module");
        return 0;
    }
    unsigned long long base = module_base_of(module);
    if (!base) {
        snprintf(error, error_size, "module not found: %s", module);
        return 0;
    }
    unsigned char *p = (unsigned char *)base;
    if (memcmp(p, "\x7f""ELF", 4) != 0) {
        snprintf(error, error_size, "module is not ELF: %s", module);
        return 0;
    }
    unsigned long long phoff = *(unsigned long long *)(p + 32);
    unsigned short phentsize = *(unsigned short *)(p + 54);
    unsigned short phnum = *(unsigned short *)(p + 56);
    unsigned long long dyn_vaddr = 0;
    for (int i = 0; i < phnum; i++) {
        unsigned char *ph = p + phoff + (unsigned long long)i * phentsize;
        if (*(unsigned int *)ph == 2) { dyn_vaddr = *(unsigned long long *)(ph + 16); break; }
    }
    if (!dyn_vaddr) {
        snprintf(error, error_size, "PT_DYNAMIC not found");
        return 0;
    }
    unsigned long long jmprel = 0, pltrelsz = 0, rela = 0, relasz = 0, relaent = 24;
    unsigned long long symtab = 0, strtab = 0, android_rela = 0, android_relasz = 0;
    unsigned long long *d = (unsigned long long *)(base + dyn_vaddr);
    for (; d[0] != 0; d += 2) {
        if (d[0] == 23) jmprel = d[1];             // DT_JMPREL
        else if (d[0] == 2) pltrelsz = d[1];        // DT_PLTRELSZ
        else if (d[0] == 7) rela = d[1];            // DT_RELA
        else if (d[0] == 8) relasz = d[1];          // DT_RELASZ
        else if (d[0] == 9) relaent = d[1];         // DT_RELAENT
        else if (d[0] == 6) symtab = d[1];          // DT_SYMTAB
        else if (d[0] == 5) strtab = d[1];          // DT_STRTAB
        else if (d[0] == 0x60000011ULL) android_rela = d[1];    // DT_ANDROID_RELA
        else if (d[0] == 0x60000012ULL) android_relasz = d[1];  // DT_ANDROID_RELASZ
    }
    if (!symtab || !strtab || (!jmprel && !rela)) {
        snprintf(error, error_size, "dynamic relocation tables unavailable");
        return 0;
    }
    if (relaent == 0) relaent = 24;
    if (symtab < base) symtab += base;
    if (strtab < base) strtab += base;
    const size_t cap = 512 * 1024;
    char *entries = (char *)malloc(cap);
    if (!entries) {
        snprintf(error, error_size, "out of memory");
        return 0;
    }
    size_t elen = 1;
    entries[0] = '[';
    entries[1] = 0;
    int count = 0;
    int truncated = 0;
    const unsigned long long regions[2][2] = { { jmprel, pltrelsz }, { rela, relasz } };
    for (int r = 0; r < 2 && !truncated; r++) {
        unsigned long long off = regions[r][0], sz = regions[r][1];
        if (!off || !sz) continue;
        if (off < base) off += base;
        for (unsigned long long e = off; e + relaent <= off + sz; e += relaent) {
            if (elen > cap - 768) { truncated = 1; break; }
            unsigned long long r_offset = *(unsigned long long *)e;
            unsigned long long r_info = *(unsigned long long *)(e + 8);
            unsigned int sym_idx = (unsigned int)(r_info >> 32);
            unsigned long long type = r_info & 0xffffffffULL;
            if (sym_idx == 0) continue;
            unsigned char *symrec = (unsigned char *)(symtab + (unsigned long long)sym_idx * 24);
            unsigned int st_name = *(unsigned int *)symrec;
            const char *name = (const char *)(strtab + st_name);
            if (!name || !name[0]) continue;
            if (filter && filter[0] && strcmp(name, filter) != 0) continue;
            unsigned long long slot_addr = r_offset < base ? base + r_offset : r_offset;
            void *value = *(void **)slot_addr;
            char name_escaped[512];
            json_escape(name, name_escaped, sizeof(name_escaped));
            elen += snprintf(entries + elen, cap - elen,
                             "%s{\"slot\":\"0x%llx\",\"symbol\":\"%s\",\"value\":\"0x%llx\",\"type\":\"%s\"}",
                             count ? "," : "", slot_addr, name_escaped,
                             (unsigned long long)(uintptr_t)value, reloc_type_name(type));
            count++;
            if (count >= 4096) { truncated = 1; break; }
        }
    }
    if (elen + 2 >= cap) truncated = 1;
    snprintf(entries + elen, cap - elen, "]");
    char module_escaped[256];
    char filter_escaped[512];
    json_escape(module, module_escaped, sizeof(module_escaped));
    json_escape(filter ? filter : "", filter_escaped, sizeof(filter_escaped));
    char *out = (char *)malloc(cap);
    if (!out) {
        free(entries);
        snprintf(error, error_size, "out of memory");
        return 0;
    }
    snprintf(out, cap,
             "{\"module\":\"%s\",\"count\":%d,\"truncated\":%s,\"packed\":%s,\"packedSize\":%llu,\"filter\":\"%s\",\"entries\":%s,\"packedUnsupported\":%s}",
             module_escaped, count, truncated ? "true" : "false",
             android_rela ? "true" : "false", (unsigned long long)android_relasz, filter_escaped, entries,
             android_rela ? "true" : "false");
    free(entries);
    char *copy = strdup(out);
    free(out);    if (!copy) {
        snprintf(error, error_size, "out of memory");
        return 0;
    }
    *out_json = copy;
    return 1;
}
#include "../src/hook/got.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

// Links the actual production got.c, not a copy of its restore algorithm.
int main(void) {
    const size_t size = (size_t)sysconf(_SC_PAGESIZE);
    void **slot = mmap(NULL, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(slot != MAP_FAILED);
    void *original = (void *)(uintptr_t)0x1000;
    void *ours = (void *)(uintptr_t)0x2000;
    void *other = (void *)(uintptr_t)0x3000;
    *slot = ours;
    assert(adh_restore_pointer_if_owned(slot, ours, original) == 1 && *slot == original);
    puts("PASS owned-writable");
    *slot = other;
    assert(adh_restore_pointer_if_owned(slot, ours, original) == -1 && *slot == other);
    puts("PASS foreign-writable-unchanged");
    *slot = ours;
    assert(mprotect(slot, size, PROT_READ) == 0);
    assert(adh_restore_pointer_if_owned(slot, ours, original) == 1 && *slot == original);
    char perms[8];
    adh_perms_of_addr(slot, perms, sizeof(perms));
    assert(perms[0] == 'r' && perms[1] == '-');
    puts("PASS owned-relro-protection-restored");
    assert(adh_restore_pointer_if_owned(slot, ours, original) == 1 && *slot == original);
    puts("PASS already-restored-idempotent");
    assert(mprotect(slot, size, PROT_READ | PROT_WRITE) == 0);
    *slot = other;
    assert(mprotect(slot, size, PROT_READ) == 0);
    assert(adh_restore_pointer_if_owned(slot, ours, original) == -1 && *slot == other);
    adh_perms_of_addr(slot, perms, sizeof(perms));
    assert(perms[0] == 'r' && perms[1] == '-');
    puts("PASS foreign-relro-value-and-protection-unchanged");
    assert(adh_restore_pointer_if_owned(NULL, ours, original) == 0);
    assert(adh_restore_pointer_if_owned((void **)((char *)slot + 1), ours, original) == 0);
    puts("PASS invalid-and-misaligned-rejected");
    assert(mprotect(slot, size, PROT_NONE) == 0);
    assert(adh_restore_pointer_if_owned(slot, ours, original) == 0);
    puts("PASS unreadable-rejected");
    assert(munmap(slot, size) == 0);
    assert(adh_restore_pointer_if_owned(slot, ours, original) == 0);
    puts("PASS unmapped-rejected");
    char path[]="/data/local/tmp/adh-got-sigbus-XXXXXX";
    int file=mkstemp(path);assert(file>=0);assert(ftruncate(file,(off_t)size)==0);
    void *mapped=mmap(NULL,size*2,PROT_READ,MAP_PRIVATE,file,0);assert(mapped!=MAP_FAILED);
    printf("SIGBUS_PROBE_FILE=%s\n",path);fflush(stdout);
    // The second page is listed as readable but any direct access raises SIGBUS.
    // A non-ELF data file never has a validated GOT; do not scan it for pointer values.
    assert(adh_got_replace(strrchr(path,'/')+1,ours,original)==0);
    assert(munmap(mapped,size*2)==0);assert(close(file)==0);assert(unlink(path)==0);
    puts("PASS non-ELF-mapping-with-SIGBUS-tail-is-not-scanned");
    puts("ADH_GOT_RESTORE_PASS 9");
    return 0;
}

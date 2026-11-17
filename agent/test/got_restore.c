#include "../src/hook/got.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

// Links the actual production got.c, not a copy of its restore algorithm.
static pid_t replacement_getpid(void) { return 424242; }

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
    pid_t actual_pid = getpid();
    assert(actual_pid > 0 && actual_pid != 424242);
    void *getpid_original = dlsym(RTLD_DEFAULT, "getpid");
    assert(getpid_original != NULL);
    void *pid_slot = NULL, *pid_value = NULL;
    assert(adh_got_unique_slot("verify", "getpid", &pid_slot, &pid_value) == 1);
    assert(pid_value == getpid_original);
    // Empty-filter capture must inspect actual loaded callers, not reject every module.
    assert(adh_got_replace_by_name("", "getpid", (void *)replacement_getpid) > 0);
    assert(getpid() == 424242);
    assert(adh_got_replace("", (void *)replacement_getpid, getpid_original) > 0);
    assert(*(void **)pid_slot == getpid_original);
    assert(getpid() == actual_pid);
    puts("PASS all-module-by-name-install-hit-and-value-restore");
    // The build requires a real DT_ANDROID_RELA table. stdout is its GLOB_DAT import;
    // do not perform stdout I/O while its import points at our synthetic variable.
    void *stdout_slot = NULL, *stdout_value = NULL;
    static FILE *synthetic_stdout;
    assert(adh_got_unique_slot("verify", "stdout", &stdout_slot, &stdout_value) == 1);
    assert(stdout_value == dlsym(RTLD_DEFAULT, "stdout"));
    assert(adh_got_replace("verify", stdout_value, &synthetic_stdout) == 1);
    assert(*(void **)stdout_slot == &synthetic_stdout);
    assert(adh_got_replace("verify", &synthetic_stdout, stdout_value) == 1);
    assert(*(void **)stdout_slot == stdout_value);
    puts("PASS APS2-packed-GLOB_DAT-value-install-and-restore");
    puts("ADH_GOT_RESTORE_PASS 11");
    return 0;
}

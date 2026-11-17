#include "../src/trace/qbdi_trace.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Standalone fixture links the production tracer, not the native Hook manager.
int adh_native_hook_at(uint64_t address,int *id,int *active) {
    (void)address;(void)id;(void)active;return 0;
}
__attribute__((naked,noinline)) static void stack_writer(void) {
    __asm__ volatile("sub sp, sp, #16\nstr w0, [sp, #12]\nldr w0, [sp, #12]\nadd sp, sp, #16\nret\n");
}
__attribute__((noinline)) static void stop_marker(void) { __asm__ volatile("" ::: "memory"); }

int main(void) {
    alarm(10);
    const size_t size=256*1024;
    unsigned char *source=mmap(NULL,size,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(source!=MAP_FAILED);memset(source,0x5a,size);
    const uint64_t sp=(uint64_t)(uintptr_t)(source+64*1024);
    uint64_t gpr[ADH_QTRACE_GPR_LEN]={0};
    gpr[0]=15;gpr[9]=sp+32;gpr[10]=(uint64_t)(uintptr_t)stop_marker;gpr[23]=sp;
    qbdi_summary_t summary;qbdi_watch_t watch;
    assert(adh_qbdi_run_from_watch((uint64_t)(uintptr_t)stack_writer,gpr,32,300,0,0,0,&summary,NULL)>0);
    assert(summary.ok&&summary.stack_shadow&&summary.stack_bytes>0);
    assert(*(uint32_t *)(uintptr_t)(sp-4)==0x5a5a5a5a);
    puts("PASS replay-does-not-write-the-supplied-stack");
    assert(adh_qbdi_run_from_watch((uint64_t)(uintptr_t)stack_writer,gpr,32,300,0,sp-4,sp,&summary,&watch)>0);
    assert(summary.ok&&watch.stack_shadow&&watch.count>0&&!watch.error[0]);
    assert(watch.hits[0].addr==sp-4&&watch.hits[0].value==15);
    assert(*(uint32_t *)(uintptr_t)(sp-4)==0x5a5a5a5a);
    puts("PASS stack-watch-reports-logical-source-address-without-writing-it");
    gpr[23]=sp+1;
    assert(adh_qbdi_run_from_watch((uint64_t)(uintptr_t)stack_writer,gpr,32,300,0,0,0,&summary,NULL)<0);
    assert(!summary.ok&&!strcmp(summary.stop_reason,"did-not-run"));
    puts("PASS unaligned-SP-refused-before-execution");
    gpr[23]=sp;gpr[9]=sp+160000;
    assert(adh_qbdi_run_from_watch((uint64_t)(uintptr_t)stack_writer,gpr,32,300,0,0,0,&summary,NULL)<0);
    assert(!summary.ok&&!strcmp(summary.stop_reason,"did-not-run")&&strstr(summary.error,"FP"));
    assert(munmap(source,size)==0);
    puts("PASS frame-outside-snapshot-refused-before-execution");
    puts("ADH_QBDI_STACK_PASS 4");return 0;
}

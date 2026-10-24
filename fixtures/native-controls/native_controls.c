#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
static _Atomic int adh_slow_status = 0;

// Eight independent FP arguments occupy d0..d7. Writing a hook seq over saved q7 corrupts the
// eighth term and makes this deterministic result differ from 204 for inputs 1..8.
__attribute__((visibility("default"), noinline))
double adh_fp8_target(double a, double b, double c, double d,
                      double e, double f, double g, double h) {
    return a + b*2 + c*3 + d*4 + e*5 + f*6 + g*7 + h*8;
}
__attribute__((visibility("default"), noinline))
double adh_fp8_after_target(double a, double b, double c, double d,
                            double e, double f, double g, double h) {
    return adh_fp8_target(a,b,c,d,e,f,g,h);
}

struct adh_pair { uint64_t lo, hi; };
__attribute__((visibility("default"), noinline))
struct adh_pair adh_pair_target(uint64_t a, uint64_t b) {
    struct adh_pair result = {a+1, b+2};
    return result;
}
__attribute__((visibility("default"), noinline))
uint64_t adh_pair_probe(void) {
    struct adh_pair result = adh_pair_target(7, 9);
    return result.lo ^ (result.hi << 1); // 8 ^ 22 == 30; observes BOTH x0 and x1 after memAfter
}

__attribute__((visibility("default"), noinline))
uint64_t adh_slow_target(uint64_t ms) {
    if (ms > 10000) ms = 10000;
    struct timespec delay = {(time_t)(ms/1000), (long)(ms%1000)*1000000};
    atomic_store(&adh_slow_status, 1);
    while (nanosleep(&delay, &delay) != 0) {}
    atomic_store(&adh_slow_status, 2);
    return 84;
}
__attribute__((visibility("default"), noinline))
uint64_t adh_slow_caller(uint64_t ms) { return adh_slow_target(ms); }
static void *adh_slow_worker(void *arg) {
    (void)adh_slow_caller((uint64_t)(uintptr_t)arg);
    return 0;
}
__attribute__((visibility("default"), noinline))
uint64_t adh_start_slow(uint64_t ms) {
    pthread_t thread;
    atomic_store(&adh_slow_status, 0);
    int error = pthread_create(&thread, 0, adh_slow_worker, (void *)(uintptr_t)ms);
    if (error) return (uint64_t)error;
    return (uint64_t)pthread_detach(thread);
}
__attribute__((visibility("default"), noinline))
uint64_t adh_slow_state(void) { return (uint64_t)atomic_load(&adh_slow_status); }

__attribute__((visibility("default"), noinline))
uint64_t adh_control_target(uint64_t value) { return value*2+1; }
__attribute__((visibility("default"), noinline))
uint64_t adh_control_probe(uint64_t rounds) {
    uint64_t result = 0;
    if (rounds > 64) rounds = 64;
    for (uint64_t i=0; i<rounds; i++) result += adh_control_target(20);
    return result;
}

typedef uint64_t (*adh_pointer_fn)(uint64_t);
__attribute__((visibility("default"),noinline))
uint64_t adh_pointer_target(uint64_t value) { return value+333; }
// A genuine indirect DATA slot, made read-only by the linker's GNU_RELRO mapping. volatile forces
// the probe to load the slot at runtime instead of letting the compiler fold it into a direct call.
__attribute__((visibility("default"),section(".data.rel.ro")))
adh_pointer_fn const volatile adh_pointer_table[1] = {adh_pointer_target};
__attribute__((visibility("default"),noinline))
uint64_t adh_pointer_probe(uint64_t value) { return adh_pointer_table[0](value); }

#define ADH_RETIRE_PROBE(N) \
__attribute__((visibility("default"),noinline)) uint64_t adh_retire_target_##N(uint64_t value){return value+(N);} \
__attribute__((visibility("default"),noinline)) uint64_t adh_retire_probe_##N(void){return adh_retire_target_##N(20);}
ADH_RETIRE_PROBE(0) ADH_RETIRE_PROBE(1) ADH_RETIRE_PROBE(2) ADH_RETIRE_PROBE(3)
ADH_RETIRE_PROBE(4) ADH_RETIRE_PROBE(5) ADH_RETIRE_PROBE(6) ADH_RETIRE_PROBE(7)
ADH_RETIRE_PROBE(8) ADH_RETIRE_PROBE(9) ADH_RETIRE_PROBE(10) ADH_RETIRE_PROBE(11)
ADH_RETIRE_PROBE(12) ADH_RETIRE_PROBE(13) ADH_RETIRE_PROBE(14) ADH_RETIRE_PROBE(15)

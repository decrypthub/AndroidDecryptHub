#define _GNU_SOURCE
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>

// A persistent, explicitly triggered writer. native_call runs on short-lived
// watchdog threads, so returning gettid() from that call is not a watch target.
static _Alignas(8) _Atomic uint64_t watched;
static _Atomic uint64_t issued, completed, writes;
static _Atomic int writer_tid, state, stopping, started;
static pthread_t worker;
static void pause_ms(void) { const struct timespec delay = {0, 1000000}; (void)nanosleep(&delay, 0); }

static void *watch_worker(void *unused) {
    (void)unused;
    atomic_store(&writer_tid, (int)syscall(__NR_gettid));
    atomic_store(&state, 1);
    while (!atomic_load(&stopping)) {
        uint64_t done = atomic_load(&completed);
        if (atomic_load(&issued) <= done) { pause_ms(); continue; }
        atomic_store(&state, 2);
        // Exactly two aligned 8-byte stores to the watched location. Other
        // counters live elsewhere and do not create watched-address events.
        atomic_store_explicit(&watched, UINT64_C(0x1122334455667788), memory_order_relaxed);
        atomic_fetch_add(&writes, 1);
        atomic_store_explicit(&watched, UINT64_C(0x8877665544332211), memory_order_relaxed);
        atomic_fetch_add(&writes, 1);
        atomic_store(&completed, done + 1);
        atomic_store(&state, 1);
    }
    atomic_store(&state, 4);
    return 0;
}

__attribute__((visibility("default"), noinline))
uint64_t adh_watch_start(void) {
    int expected = 0;
    if (!atomic_compare_exchange_strong(&started, &expected, 1)) return (uint64_t)atomic_load(&writer_tid);
    atomic_store(&writer_tid, 0); atomic_store(&state, 0); atomic_store(&stopping, 0);
    atomic_store(&issued, 0); atomic_store(&completed, 0); atomic_store(&writes, 0);
    atomic_store(&watched, 0);
    if (pthread_create(&worker, 0, watch_worker, 0)) { atomic_store(&started, 0); return 0; }
    for (int i = 0; i < 1000 && !atomic_load(&writer_tid); i++) pause_ms();
    return (uint64_t)atomic_load(&writer_tid);
}
__attribute__((visibility("default"), noinline))
uint64_t adh_watch_address(void) { return (uint64_t)(uintptr_t)&watched; }
__attribute__((visibility("default"), noinline))
uint64_t adh_watch_trigger(void) {
    if (!atomic_load(&started) || atomic_load(&stopping)) return 0;
    return atomic_fetch_add(&issued, 1) + 1;
}
__attribute__((visibility("default"), noinline))
uint64_t adh_watch_count(void) { return atomic_load(&writes); }
__attribute__((visibility("default"), noinline))
uint64_t adh_watch_state(void) { return (uint64_t)atomic_load(&state); }
__attribute__((visibility("default"), noinline))
uint64_t adh_watch_value(void) { return atomic_load(&watched); }
__attribute__((visibility("default"), noinline))
uint64_t adh_watch_stop(void) {
    if (!atomic_load(&started)) return 0;
    atomic_store(&stopping, 1);
    int result = pthread_join(worker, 0);
    if (!result) atomic_store(&started, 0);
    return (uint64_t)result;
}

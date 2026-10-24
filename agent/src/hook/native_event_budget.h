#ifndef ADH_NATIVE_EVENT_BUDGET_H
#define ADH_NATIVE_EVENT_BUDGET_H

#include <atomic>
#include <cstdint>

// Allocation-free observation accounting shared by every native-hook backend. These counters
// describe admission to the capture ring, not delivery to the host (the ring has its own losses).
// A budget never deactivates the hook: argument writes and replacement semantics still run.
struct AdhNativeEventBudget {
    std::atomic<unsigned long long> selected{0}, filtered{0}, sampled_out{0};
    std::atomic<unsigned long long> limited{0}, emitted{0}, reservations{0};

    void reset() {
        selected.store(0, std::memory_order_relaxed);
        filtered.store(0, std::memory_order_relaxed);
        sampled_out.store(0, std::memory_order_relaxed);
        limited.store(0, std::memory_order_relaxed);
        emitted.store(0, std::memory_order_relaxed);
        reservations.store(0, std::memory_order_relaxed);
    }

    // Keep the first matching hit, then every Nth matching hit. Cross-thread ordering is the
    // atomic sequence, not wall-clock order; a filtered call does not advance this sequence.
    bool sample(unsigned sample_every) {
        const auto ordinal = selected.fetch_add(1, std::memory_order_relaxed);
        if (sample_every > 1 && ordinal % sample_every != 0) {
            sampled_out.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        return true;
    }

    // After sampling and the time throttle. fetch_add gives distinct tickets even when many
    // target threads arrive together: at most max_events callers may build/copy an event.
    bool reserve(unsigned max_events) {
        const auto ticket = reservations.fetch_add(1, std::memory_order_relaxed);
        if (max_events && ticket >= max_events) {
            limited.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        return true;
    }
};

#endif

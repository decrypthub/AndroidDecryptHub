#include "../src/hook/native_event_budget.h"
#include <cassert>
#include <thread>
#include <vector>
#include <cstdio>

int main() {
    AdhNativeEventBudget b;
    for (unsigned i = 0; i < 12; i++) {
        if (b.sample(3) && b.reserve(2)) b.emitted.fetch_add(1);
    }
    assert(b.selected == 12 && b.sampled_out == 8 && b.limited == 2 && b.emitted == 2);
    // No limit, no sampling: every selected call is recorded.
    b.reset();
    for (unsigned i = 0; i < 123; i++) {
        assert(b.sample(1) && b.reserve(0));
        b.emitted.fetch_add(1);
    }
    assert(b.selected == 123 && b.emitted == 123 && b.limited == 0);
    // Simultaneous target threads cannot overshoot a strict quota.
    b.reset();
    std::vector<std::thread> workers;
    for (int t = 0; t < 8; t++) workers.emplace_back([&]() {
        for (unsigned i = 0; i < 10000; i++) {
            if (b.sample(7) && b.reserve(31)) b.emitted.fetch_add(1);
        }
    });
    for (auto &w : workers) w.join();
    assert(b.selected == 80000 && b.emitted == 31);
    assert(b.selected == b.sampled_out + b.limited + b.emitted);
    // A new install must not inherit the old quota or sampling phase.
    b.reset();
    assert(b.sample(7) && b.reserve(1));
    assert(b.filtered == 0 && b.sampled_out == 0 && b.limited == 0);
    std::puts("ADH_NATIVE_EVENT_BUDGET_PASS");
}

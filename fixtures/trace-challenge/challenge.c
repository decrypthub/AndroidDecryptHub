#include <stdint.h>
// Seed and iteration count are chosen at verification time. No captured target material.
// Flattened dispatch exercises branches, loops, arithmetic and output dependence.
__attribute__((visibility("default"),noinline))
uint64_t adh_trace_challenge(uint64_t seed, uint64_t rounds) {
    uint64_t value = seed, index = 0, state = 7;
    if (rounds > 4096) rounds = 4096;
    while (state != 11) {
        switch (state) {
            case 7: state = index == rounds ? 11 : 3; break;
            case 3: value += seed ^ index; state = 9; break;
            case 9: value = (value << 7) | (value >> 57); state = 1; break;
            case 1: value ^= 0x9e3779b97f4a7c15ULL; state = 5; break;
            case 5: index++; state = 7; break;
            default: state = 11; break;
        }
    }
    return value;
}

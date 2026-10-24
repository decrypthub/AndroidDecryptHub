#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/bootstrap/process_identity.h"

int main(void) {
    const char *normal = "101 (probe) S 1 101 101 0 -1 4194560 42 0 0 0 2 1 0 0 20 0 3 0 123456 1048576 32\n";
    const char *strange = "101 (probe (worker)\n))) D 1 101 101 0 -1 4194560 42 0 0 0 2 1 0 0 20 0 3 0 18446744073709551615 1048576 32\n";
    char out[24];
    assert(adh_parse_starttime_ticks(normal, out, sizeof(out)) && !strcmp(out, "123456"));
    assert(adh_parse_starttime_ticks(strange, out, sizeof(out)) && !strcmp(out, "18446744073709551615"));
    assert(!adh_parse_starttime_ticks("101 (broken) S 1 2", out, sizeof(out)) && !out[0]);
    assert(!adh_parse_starttime_ticks(normal, out, 4) && !out[0]);
    assert(!adh_parse_starttime_ticks(NULL, out, sizeof(out)) && !out[0]);
    // Optional Linux self-read is an actual procfs roundtrip, not needed on a Windows host.
#ifdef __linux__
    assert(adh_self_starttime_ticks(out, sizeof(out)) && out[0]);
#endif
    puts("process identity: PASS");
    return 0;
}

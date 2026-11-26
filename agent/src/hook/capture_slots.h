#ifndef ADH_CAPTURE_SLOTS_H
#define ADH_CAPTURE_SLOTS_H
#include <stddef.h>
#include <string.h>

// Command-thread-owned metadata, never touched by a capture callback. Every publication
// saves the actual prior pointer (including an unresolved PLT stub or pre-existing hook).
// Readers/writers are adapters so the exact ledger can be exercised without an Android linker.
#define ADH_CAPTURE_SLOT_MAX 1024
#define ADH_CAPTURE_OWNER_MAX 32
struct AdhCaptureSlot { void **slot; void *prior, *wrapper; int protection; };
struct AdhCaptureOwner {
    void *wrapper;
    unsigned restored, restoreConflicts, restoreFailures, capacityFailures;
};
struct AdhCaptureSlots {
    struct AdhCaptureSlot slots[ADH_CAPTURE_SLOT_MAX];
    struct AdhCaptureOwner owners[ADH_CAPTURE_OWNER_MAX];
};
struct AdhCaptureSlotState {
    unsigned tracked, owned, changed, unreadable;
    unsigned restored, restoreConflicts, restoreFailures, capacityFailures;
};
typedef int (*AdhCaptureSlotRead)(void **slot, void **value);
typedef int (*AdhCaptureSlotSwap)(void **slot, void *expected, void *value);

static inline struct AdhCaptureOwner *adh_capture_slot_owner(struct AdhCaptureSlots *l, void *wrapper) {
    struct AdhCaptureOwner *free_owner = NULL;
    for (int i = 0; i < ADH_CAPTURE_OWNER_MAX; i++) {
        if (l->owners[i].wrapper == wrapper) return &l->owners[i];
        if (!l->owners[i].wrapper && !free_owner) free_owner = &l->owners[i];
    }
    if (free_owner) free_owner->wrapper = wrapper;
    return free_owner;
}

static inline int adh_capture_slot_publish(struct AdhCaptureSlots *l, void **slot,
        void *observed, void *wrapper, int protection, AdhCaptureSlotRead read, AdhCaptureSlotSwap swap) {
    if (!slot || !wrapper) return -1;
    struct AdhCaptureOwner *owner = adh_capture_slot_owner(l, wrapper);
    if (!owner) return -2;
    struct AdhCaptureSlot *free_slot = NULL;
    for (int i = 0; i < ADH_CAPTURE_SLOT_MAX; i++) {
        struct AdhCaptureSlot *s = &l->slots[i];
        if (s->slot == slot) {
            // No nested capture owners and no replacement of a saved pristine pointer.
            void *current = NULL;
            return s->wrapper == wrapper && read(slot, &current) && current == wrapper ? 1 : -1;
        }
        if (!s->slot && !free_slot) free_slot = s;
    }
    if (!free_slot) { owner->capacityFailures++; return -2; }
    // A wrapper with no matching ledger entry is not a pristine original.
    if (observed == wrapper) return -1;
    free_slot->slot = slot; free_slot->prior = observed; free_slot->wrapper = wrapper;
    free_slot->protection = protection;
    int result = swap(slot, observed, wrapper);
    if (result == 1) return 1;
    // A failed protection restore may still have published the pointer. Keep its undo
    // metadata until a safe read proves we do not own it; never strand an untracked hook.
    void *current = NULL;
    if (result < 0 && read(slot, &current) && current != wrapper) memset(free_slot, 0, sizeof(*free_slot));
    owner->restoreFailures++;
    return result < 0 ? -1 : 0;
}

static inline int adh_capture_slot_restore(struct AdhCaptureSlots *l, void *wrapper,
        AdhCaptureSlotRead read, AdhCaptureSlotSwap swap) {
    struct AdhCaptureOwner *owner = adh_capture_slot_owner(l, wrapper);
    if (!owner) return 0;
    int restored = 0, failed = 0;
    for (int i = 0; i < ADH_CAPTURE_SLOT_MAX; i++) {
        struct AdhCaptureSlot *s = &l->slots[i];
        if (!s->slot || s->wrapper != wrapper) continue;
        void *current = NULL;
        if (!read(s->slot, &current)) { owner->restoreFailures++; failed++; continue; }
        if (current != wrapper && current != s->prior) {
            owner->restoreConflicts++; memset(s, 0, sizeof(*s)); failed++; continue;
        }
        // The adapter also verifies/restores saved page protection, including retries
        // where the pointer already returned to its original value.
        int result = swap(s->slot, wrapper, s->prior);
        if (result == 1) {
            owner->restored++; restored++; memset(s, 0, sizeof(*s));
        } else if (result < 0) {
            owner->restoreConflicts++; memset(s, 0, sizeof(*s)); failed++;
        } else {
            // Do not forget the original on a protection/read failure; stop is incomplete.
            owner->restoreFailures++; failed++;
        }
    }
    return failed ? -failed : restored;
}

static inline void adh_capture_slot_state(struct AdhCaptureSlots *l, void *wrapper,
        AdhCaptureSlotRead read, struct AdhCaptureSlotState *out) {
    memset(out, 0, sizeof(*out));
    struct AdhCaptureOwner *owner = adh_capture_slot_owner(l, wrapper);
    if (owner) {
        out->restored = owner->restored; out->restoreConflicts = owner->restoreConflicts;
        out->restoreFailures = owner->restoreFailures; out->capacityFailures = owner->capacityFailures;
    }
    for (int i = 0; i < ADH_CAPTURE_SLOT_MAX; i++) {
        const struct AdhCaptureSlot *s = &l->slots[i];
        if (!s->slot || s->wrapper != wrapper) continue;
        void *current = NULL; out->tracked++;
        if (!read(s->slot, &current)) out->unreadable++;
        else if (current == wrapper) out->owned++;
        else if (current != s->prior) out->changed++;
    }
}
static inline unsigned adh_capture_slots_pending(const struct AdhCaptureSlots *l) {
    unsigned n = 0;
    for (int i = 0; i < ADH_CAPTURE_SLOT_MAX; i++) if (l->slots[i].slot) n++;
    return n;
}
#endif

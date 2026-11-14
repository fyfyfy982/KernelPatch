/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_HOOK_LIFECYCLE_H_
#define _KP_HOOK_LIFECYCLE_H_

#include <stdint.h>
#include <stdbool.h>

#define CHAIN_ITEM_STATE_EMPTY 0
#define CHAIN_ITEM_STATE_READY 1
#define CHAIN_ITEM_STATE_BUSY 2
#define CHAIN_ITEM_STATE_DRAINING 3
#define CHAIN_ITEM_STATE_REMOVING 4

enum hook_remove_state
{
    HOOK_REMOVE_NOT_FOUND = 0,
    HOOK_REMOVE_DEFERRED,
    HOOK_REMOVE_READY,
    HOOK_REMOVE_FINISHED,
};

static inline __attribute__((always_inline)) int hook_item_claim_state(
    int8_t *state, int8_t expected, int8_t desired)
{
#if defined(__aarch64__)
    uint32_t observed;
    uint32_t status;
    asm volatile(
        "1: ldaxrb %w[observed], [%[state]]\n"
        "cmp %w[observed], %w[expected]\n"
        "b.ne 2f\n"
        "stlxrb %w[status], %w[desired], [%[state]]\n"
        "cbnz %w[status], 1b\n"
        "2:\n"
        : [observed] "=&r"(observed), [status] "=&r"(status)
        : [state] "r"(state), [expected] "r"((uint32_t)(uint8_t)expected),
          [desired] "r"((uint32_t)(uint8_t)desired)
        : "cc", "memory");
    return observed == (uint8_t)expected;
#else
    return __atomic_compare_exchange_n(
        state, &expected, desired, false,
        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
#endif
}

static inline __attribute__((always_inline)) int32_t
hook_item_debt_dec(volatile int32_t *debt)
{
#if defined(__aarch64__)
    int32_t value;
    uint32_t status;
    asm volatile(
        "1: ldaxr %w[value], [%[debt]]\n"
        "sub %w[value], %w[value], #1\n"
        "stlxr %w[status], %w[value], [%[debt]]\n"
        "cbnz %w[status], 1b\n"
        : [value] "=&r"(value), [status] "=&r"(status)
        : [debt] "r"(debt)
        : "memory");
    return value;
#else
    return __atomic_sub_fetch(debt, 1, __ATOMIC_ACQ_REL);
#endif
}

static inline __attribute__((always_inline)) int32_t
hook_item_reader_dec(volatile int32_t *reader)
{
#if defined(__aarch64__)
    int32_t value;
    uint32_t status;
    asm volatile(
        "1: ldaxr %w[value], [%[reader]]\n"
        "sub %w[value], %w[value], #1\n"
        "stlxr %w[status], %w[value], [%[reader]]\n"
        "cbnz %w[status], 1b\n"
        : [value] "=&r"(value), [status] "=&r"(status)
        : [reader] "r"(reader)
        : "memory");
    return value;
#else
    return __atomic_sub_fetch(reader, 1, __ATOMIC_ACQ_REL);
#endif
}

static inline __attribute__((always_inline)) void hook_item_publish_debt(
    uint8_t *debt_counted, volatile int32_t *debt)
{
    __atomic_add_fetch(debt, 1, __ATOMIC_ACQ_REL);
    __atomic_store_n(debt_counted, 1, __ATOMIC_RELEASE);
}

static inline __attribute__((always_inline)) int
hook_item_try_claim_removing_drain(
    int8_t *state, volatile int32_t *readers)
{
    if (__atomic_load_n(readers, __ATOMIC_ACQUIRE) != 0) return 0;
    return hook_item_claim_state(state, CHAIN_ITEM_STATE_REMOVING,
                                 CHAIN_ITEM_STATE_DRAINING);
}

static inline __attribute__((always_inline)) void hook_item_publish_waiting(
    int8_t *state)
{
    __atomic_store_n(state, CHAIN_ITEM_STATE_BUSY, __ATOMIC_RELEASE);
}

static inline __attribute__((always_inline)) enum hook_remove_state
hook_item_begin_remove(
    int8_t *state, uint8_t *debt_counted, volatile int32_t *readers,
    volatile int32_t *debt)
{
    int item_state = __atomic_load_n(state, __ATOMIC_ACQUIRE);
    if (item_state == CHAIN_ITEM_STATE_READY) {
        if (!hook_item_claim_state(state, CHAIN_ITEM_STATE_READY,
                                   CHAIN_ITEM_STATE_REMOVING))
            item_state = __atomic_load_n(state, __ATOMIC_ACQUIRE);
        else {
            hook_item_publish_debt(debt_counted, debt);
            if (hook_item_try_claim_removing_drain(state, readers))
                return HOOK_REMOVE_READY;
            hook_item_publish_waiting(state);
            if (__atomic_load_n(readers, __ATOMIC_ACQUIRE) == 0) {
                if (hook_item_claim_state(state, CHAIN_ITEM_STATE_BUSY,
                                          CHAIN_ITEM_STATE_DRAINING))
                    return HOOK_REMOVE_READY;
                if (__atomic_load_n(state, __ATOMIC_ACQUIRE) ==
                    CHAIN_ITEM_STATE_EMPTY)
                    return HOOK_REMOVE_FINISHED;
            }
            return HOOK_REMOVE_DEFERRED;
        }
    }
    if (item_state == CHAIN_ITEM_STATE_BUSY) {
        if (__atomic_load_n(readers, __ATOMIC_ACQUIRE) == 0) {
            if (hook_item_claim_state(state, CHAIN_ITEM_STATE_BUSY,
                                      CHAIN_ITEM_STATE_DRAINING))
                return HOOK_REMOVE_READY;
            if (__atomic_load_n(state, __ATOMIC_ACQUIRE) ==
                CHAIN_ITEM_STATE_EMPTY)
                return HOOK_REMOVE_FINISHED;
        }
        return HOOK_REMOVE_DEFERRED;
    }
    if (item_state == CHAIN_ITEM_STATE_REMOVING ||
        item_state == CHAIN_ITEM_STATE_DRAINING)
        return HOOK_REMOVE_DEFERRED;
    return HOOK_REMOVE_NOT_FOUND;
}

static inline __attribute__((always_inline)) int hook_item_try_claim_drain(
    int8_t *state, volatile int32_t *readers)
{
    if (__atomic_load_n(readers, __ATOMIC_ACQUIRE) != 0) return 0;
    return hook_item_claim_state(state, CHAIN_ITEM_STATE_BUSY,
                                 CHAIN_ITEM_STATE_DRAINING);
}

static inline __attribute__((always_inline)) void hook_item_finish_remove(
    int8_t *state, uint8_t *debt_counted, volatile int32_t *debt)
{
    if (__atomic_load_n(debt_counted, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(debt_counted, 0, __ATOMIC_RELEASE);
        hook_item_debt_dec(debt);
    }
    __atomic_store_n(state, CHAIN_ITEM_STATE_EMPTY, __ATOMIC_RELEASE);
}

static inline __attribute__((always_inline)) int hook_item_reader_release(
    int8_t *state, volatile int32_t *readers, uint8_t *debt_counted,
    volatile int32_t *debt, void **udata, void **before, void **after)
{
    if (hook_item_reader_dec(readers) != 0) return 0;
    if (!hook_item_try_claim_drain(state, readers)) return 0;
    *udata = 0;
    *before = 0;
    *after = 0;
    hook_item_finish_remove(state, debt_counted, debt);
    return 1;
}

#endif

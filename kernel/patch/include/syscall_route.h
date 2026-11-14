/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_SYSCALL_ROUTE_H_
#define _KP_SYSCALL_ROUTE_H_

#include <stdint.h>
#include <stdbool.h>

enum syscall_hook_backend
{
    SYSCALL_HOOK_NONE = 0,
    SYSCALL_HOOK_FUNCTION_POINTER,
    SYSCALL_HOOK_INLINE,
};

enum syscall_hook_route_state
{
    SYSCALL_ROUTE_UNBOUND = 0,
    SYSCALL_ROUTE_BOUND,
    SYSCALL_ROUTE_INSTALLING,
    SYSCALL_ROUTE_REMOVING,
};

struct syscall_hook_route
{
    volatile int32_t state;
    enum syscall_hook_backend backend;
    uintptr_t target;
};

struct syscall_hook_route_claim
{
    enum syscall_hook_backend backend;
    uintptr_t target;
    int was_bound;
};

static inline int syscall_hook_route_begin_install(
    struct syscall_hook_route *route, uintptr_t fp_target,
    uintptr_t inline_target, struct syscall_hook_route_claim *claim)
{
    int32_t expected;
    enum syscall_hook_backend backend;
    uintptr_t target;

    if (!route || !claim) return -1;
    expected = __atomic_load_n(&route->state, __ATOMIC_ACQUIRE);
    if (expected == SYSCALL_ROUTE_BOUND) {
        if (!__atomic_compare_exchange_n(
                &route->state, &expected, SYSCALL_ROUTE_INSTALLING, false,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return -2;
        if (route->backend == SYSCALL_HOOK_NONE || !route->target) {
            __atomic_store_n(&route->state, SYSCALL_ROUTE_BOUND,
                             __ATOMIC_RELEASE);
            return -1;
        }
        claim->backend = route->backend;
        claim->target = route->target;
        claim->was_bound = 1;
        return 0;
    }
    if (expected != SYSCALL_ROUTE_UNBOUND) return -2;
    if (fp_target) {
        backend = SYSCALL_HOOK_FUNCTION_POINTER;
        target = fp_target;
    } else if (inline_target) {
        backend = SYSCALL_HOOK_INLINE;
        target = inline_target;
    } else {
        return -1;
    }
    if (!__atomic_compare_exchange_n(
            &route->state, &expected, SYSCALL_ROUTE_INSTALLING, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -2;
    route->backend = backend;
    route->target = target;
    claim->backend = backend;
    claim->target = target;
    claim->was_bound = 0;
    return 0;
}

static inline void syscall_hook_route_finish_install(
    struct syscall_hook_route *route,
    const struct syscall_hook_route_claim *claim, int success)
{
    if (!success && !claim->was_bound) {
        route->target = 0;
        route->backend = SYSCALL_HOOK_NONE;
        __atomic_store_n(&route->state, SYSCALL_ROUTE_UNBOUND,
                         __ATOMIC_RELEASE);
        return;
    }
    __atomic_store_n(&route->state, SYSCALL_ROUTE_BOUND,
                     __ATOMIC_RELEASE);
}

static inline int syscall_hook_route_begin_remove(
    struct syscall_hook_route *route, struct syscall_hook_route_claim *claim)
{
    int32_t expected = SYSCALL_ROUTE_BOUND;
    if (!route || !claim) return -1;
    if (!__atomic_compare_exchange_n(
            &route->state, &expected, SYSCALL_ROUTE_REMOVING, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return expected == SYSCALL_ROUTE_UNBOUND ? -1 : -2;
    if (route->backend == SYSCALL_HOOK_NONE || !route->target) {
        __atomic_store_n(&route->state, SYSCALL_ROUTE_BOUND,
                         __ATOMIC_RELEASE);
        return -1;
    }
    claim->backend = route->backend;
    claim->target = route->target;
    claim->was_bound = 1;
    return 0;
}

static inline void syscall_hook_route_finish_remove(
    struct syscall_hook_route *route)
{
    __atomic_store_n(&route->state, SYSCALL_ROUTE_BOUND,
                     __ATOMIC_RELEASE);
}

static inline void syscall_hook_route_reset(struct syscall_hook_route *route)
{
    route->target = 0;
    route->backend = SYSCALL_HOOK_NONE;
    __atomic_store_n(&route->state, SYSCALL_ROUTE_UNBOUND,
                     __ATOMIC_RELEASE);
}

#endif

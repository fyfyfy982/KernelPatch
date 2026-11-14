/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _KP_MODULE_LIFECYCLE_H_
#define _KP_MODULE_LIFECYCLE_H_

#include <stdbool.h>
#include <stdint.h>

enum module_lifecycle_state
{
    MODULE_STATE_LOADING = 0,
    MODULE_STATE_LIVE,
    MODULE_STATE_EXITING,
    MODULE_STATE_EXIT_FAILED,
    MODULE_STATE_RETIRING,
    MODULE_STATE_EXIT_DONE,
};

struct module_lifecycle
{
    enum module_lifecycle_state state;
    unsigned int active_calls;
    int control_busy;
    uintptr_t control_owner;
    long init_error;
    long exit_error;
};

static inline void module_lifecycle_init(struct module_lifecycle *lifecycle)
{
    lifecycle->state = MODULE_STATE_LOADING;
    lifecycle->active_calls = 0;
    lifecycle->control_busy = 0;
    lifecycle->control_owner = 0;
    lifecycle->init_error = 0;
    lifecycle->exit_error = 0;
}

static inline bool module_lifecycle_try_get_control(
    struct module_lifecycle *lifecycle, uintptr_t owner)
{
    if (lifecycle->state != MODULE_STATE_LIVE || lifecycle->control_busy)
        return false;
    lifecycle->control_busy = 1;
    lifecycle->control_owner = owner;
    lifecycle->active_calls++;
    return true;
}

static inline bool module_lifecycle_put_control(
    struct module_lifecycle *lifecycle)
{
    lifecycle->control_busy = 0;
    lifecycle->control_owner = 0;
    if (!lifecycle->active_calls) return false;
    lifecycle->active_calls--;
    return true;
}

static inline bool module_lifecycle_is_control_owner(
    const struct module_lifecycle *lifecycle, uintptr_t owner)
{
    return lifecycle->control_busy && lifecycle->control_owner == owner;
}

static inline bool module_lifecycle_try_get_info(
    struct module_lifecycle *lifecycle)
{
    if (lifecycle->state != MODULE_STATE_LIVE &&
        lifecycle->state != MODULE_STATE_EXIT_FAILED)
        return false;
    lifecycle->active_calls++;
    return true;
}

static inline bool module_lifecycle_put_info(
    struct module_lifecycle *lifecycle)
{
    if (!lifecycle->active_calls) return false;
    lifecycle->active_calls--;
    return true;
}

static inline bool module_lifecycle_begin_unload(
    struct module_lifecycle *lifecycle,
    enum module_lifecycle_state *previous_state,
    bool *exit_already_done)
{
    if (lifecycle->state != MODULE_STATE_LIVE &&
        lifecycle->state != MODULE_STATE_EXIT_FAILED &&
        lifecycle->state != MODULE_STATE_EXIT_DONE)
        return false;
    *previous_state = lifecycle->state;
    *exit_already_done = lifecycle->state == MODULE_STATE_EXIT_DONE;
    lifecycle->state = MODULE_STATE_EXITING;
    return true;
}

static inline void module_lifecycle_restore(
    struct module_lifecycle *lifecycle,
    enum module_lifecycle_state previous_state,
    long error)
{
    lifecycle->state = previous_state;
    lifecycle->exit_error = error;
}

static inline void module_lifecycle_mark_live(
    struct module_lifecycle *lifecycle)
{
    lifecycle->state = MODULE_STATE_LIVE;
    lifecycle->exit_error = 0;
}

static inline void module_lifecycle_mark_exit_failed(
    struct module_lifecycle *lifecycle, long error)
{
    lifecycle->state = MODULE_STATE_EXIT_FAILED;
    lifecycle->exit_error = error;
}

static inline void module_lifecycle_mark_exit_done(
    struct module_lifecycle *lifecycle)
{
    lifecycle->state = MODULE_STATE_EXIT_DONE;
    lifecycle->exit_error = 0;
}

static inline void module_lifecycle_mark_retiring(
    struct module_lifecycle *lifecycle)
{
    lifecycle->state = MODULE_STATE_RETIRING;
    lifecycle->exit_error = 0;
}

static inline bool module_lifecycle_is_idle(
    const struct module_lifecycle *lifecycle)
{
    return lifecycle->active_calls == 0;
}

#endif

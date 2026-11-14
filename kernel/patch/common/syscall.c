/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "syscall.h"

#include <cache.h>
#include <ktypes.h>
#include <hook.h>
#include <common.h>
#include <linux/string.h>
#include <symbol.h>
#include <uapi/asm-generic/errno.h>
#include <asm-generic/compat.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>
#include <predata.h>
#include <kputils.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <syscall_route.h>

#define SYSCALL_ROUTE_COUNT 460

static struct syscall_hook_route syscall_routes[SYSCALL_ROUTE_COUNT];
static struct syscall_hook_route compat_syscall_routes[SYSCALL_ROUTE_COUNT];

static struct syscall_hook_route *syscall_route_slot(int nr, int is_compat)
{
    if (nr < 0 || nr >= SYSCALL_ROUTE_COUNT) return 0;
    return is_compat ? &compat_syscall_routes[nr] : &syscall_routes[nr];
}

static hook_err_t syscall_wrap_recorded(int nr, int narg, int is_compat,
                                        void *before, void *after,
                                        void *udata)
{
    struct syscall_hook_route *route = syscall_route_slot(nr, is_compat);
    struct syscall_hook_route_claim claim;
    uintptr_t fp_target = 0;
    uintptr_t inline_target = 0;
    int claim_rc;
    hook_err_t rc;

    if (!route) return -HOOK_BAD_ADDRESS;
    if (__atomic_load_n(&route->state, __ATOMIC_ACQUIRE) ==
        SYSCALL_ROUTE_UNBOUND) {
        uintptr_t *table = is_compat ? compat_sys_call_table : sys_call_table;
        if (table)
            fp_target = (uintptr_t)(table + nr);
        else
            inline_target = syscalln_name_addr(nr, is_compat);
    }
    claim_rc = syscall_hook_route_begin_install(
        route, fp_target, inline_target, &claim);
    if (claim_rc) return claim_rc == -2 ? -HOOK_READER_BUSY
                                       : -HOOK_BAD_ADDRESS;
    if (has_syscall_wrapper) narg = 1;
    if (claim.backend == SYSCALL_HOOK_FUNCTION_POINTER)
        rc = fp_hook_wrap(claim.target, narg, before, after, udata);
    else
        rc = hook_wrap((void *)claim.target, narg, before, after, udata);
    syscall_hook_route_finish_install(route, &claim, rc == HOOK_NO_ERR);
    return rc;
}

static hook_err_t syscall_unwrap_recorded(int nr, int is_compat,
                                          void *before, void *after)
{
    struct syscall_hook_route *route = syscall_route_slot(nr, is_compat);
    struct syscall_hook_route_claim claim;
    int claim_rc;
    hook_err_t rc;

    if (!route) return -HOOK_BAD_ADDRESS;
    claim_rc = syscall_hook_route_begin_remove(route, &claim);
    if (claim_rc) return claim_rc == -2 ? -HOOK_READER_BUSY
                                       : -HOOK_NOT_FOUND;
    if (claim.backend == SYSCALL_HOOK_FUNCTION_POINTER)
        rc = fp_hook_unwrap_checked(claim.target, before, after);
    else
        rc = hook_unwrap_remove_checked(
            (void *)claim.target, before, after, 1);
    syscall_hook_route_finish_remove(route);
    return rc;
}

uintptr_t *sys_call_table = 0;
KP_EXPORT_SYMBOL(sys_call_table);

uintptr_t *compat_sys_call_table = 0;
KP_EXPORT_SYMBOL(compat_sys_call_table);

int has_syscall_wrapper = 0;
KP_EXPORT_SYMBOL(has_syscall_wrapper);

int has_config_compat = 0;
KP_EXPORT_SYMBOL(has_config_compat);

struct user_arg_ptr
{
    union
    {
        const char __user *const __user *native;
    } ptr;
};

struct user_arg_ptr_compat
{
    bool is_compat;
    union
    {
        const char __user *const __user *native;
        const compat_uptr_t __user *compat;
    } ptr;
};

// actually, a0 is true if it is compat
const char __user *get_user_arg_ptr(void *a0, void *a1, int nr)
{
    char __user *const __user *native = (char __user *const __user *)a0;
    int size = 8;
    if (has_config_compat) {
        native = (char __user *const __user *)a1;
        if (a0) size = 4; // compat
    }
    native = (char __user *const __user *)((unsigned long)native + nr * size);
    char __user **upptr = memdup_user(native, size);
    if (IS_ERR(upptr)) return ERR_PTR((long)upptr);

    char __user *uptr;
    if (size == 8) {
        uptr = *upptr;
    } else {
        uptr = (char __user *)(unsigned long)*(int32_t *)upptr;
    }
    kfree(upptr);
    return uptr;
}

int set_user_arg_ptr(void *a0, void *a1, int nr, uintptr_t val)
{
    uintptr_t valp = (uintptr_t)&val;
    char __user *const __user *native = (char __user *const __user *)a0;
    int size = 8;
    if (has_config_compat) {
        native = (char __user *const __user *)a1;
        if (a0) {
            size = 4; // compat
            valp += 4;
        }
    }
    native = (char __user *const __user *)((unsigned long)native + nr * size);
    int cplen = compat_copy_to_user((void *)native, (void *)valp, size);
    return cplen == size ? 0 : cplen;
}

typedef long (*warp_raw_syscall_f)(const struct pt_regs *regs);
typedef long (*raw_syscall0_f)();
typedef long (*raw_syscall1_f)(long arg0);
typedef long (*raw_syscall2_f)(long arg0, long arg1);
typedef long (*raw_syscall3_f)(long arg0, long arg1, long arg2);
typedef long (*raw_syscall4_f)(long arg0, long arg1, long arg2, long arg3);
typedef long (*raw_syscall5_f)(long arg0, long arg1, long arg2, long arg3, long arg4);
typedef long (*raw_syscall6_f)(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5);

uintptr_t syscalln_name_addr(int nr, int is_compat)
{
    const char *name = 0;
    if (!is_compat) {
        if (syscall_name_table[nr].addr) {
            return syscall_name_table[nr].addr;
        }
        name = syscall_name_table[nr].name;
    } else {
        if (compat_syscall_name_table[nr].addr) {
            return compat_syscall_name_table[nr].addr;
        }
        name = compat_syscall_name_table[nr].name;
    }

    if (!name) return 0;

    const char *prefix[2];
    prefix[0] = "__arm64_";
    prefix[1] = "";
    const char *suffix[3];
    suffix[0] = ".cfi_jt";
    suffix[1] = ".cfi";
    suffix[2] = "";

    uintptr_t addr = 0;

    char buffer[256];
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 3; j++) {
            snprintf(buffer, sizeof(buffer), "%s%s%s", prefix[i], name, suffix[j]);
            addr = kallsyms_lookup_name(buffer);
            if (addr) break;
        }
        if (addr) break;
    }
    if (!is_compat) {
        syscall_name_table[nr].addr = addr;
    } else {
        compat_syscall_name_table[nr].addr = addr;
    }
    return addr;
}
KP_EXPORT_SYMBOL(syscalln_name_addr);

uintptr_t syscalln_addr(int nr, int is_compat)
{
    if (!is_compat && sys_call_table) return sys_call_table[nr];
    if (is_compat && compat_sys_call_table) return compat_sys_call_table[nr];
    return syscalln_name_addr(nr, is_compat);
}
KP_EXPORT_SYMBOL(syscalln_addr);

long raw_syscall0(long nr)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall0_f)addr)();
}
KP_EXPORT_SYMBOL(raw_syscall0);

long raw_syscall1(long nr, long arg0)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall1_f)addr)(arg0);
}
KP_EXPORT_SYMBOL(raw_syscall1);

long raw_syscall2(long nr, long arg0, long arg1)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall2_f)addr)(arg0, arg1);
}
KP_EXPORT_SYMBOL(raw_syscall2);

long raw_syscall3(long nr, long arg0, long arg1, long arg2)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall3_f)addr)(arg0, arg1, arg2);
}
KP_EXPORT_SYMBOL(raw_syscall3);

long raw_syscall4(long nr, long arg0, long arg1, long arg2, long arg3)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall4_f)addr)(arg0, arg1, arg2, arg3);
}
KP_EXPORT_SYMBOL(raw_syscall4);

long raw_syscall5(long nr, long arg0, long arg1, long arg2, long arg3, long arg4)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall5_f)addr)(arg0, arg1, arg2, arg3, arg4);
}
KP_EXPORT_SYMBOL(raw_syscall5);

long raw_syscall6(long nr, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    uintptr_t addr = syscalln_addr(nr, 0);
    if (has_syscall_wrapper) {
        struct pt_regs regs;
        regs.syscallno = nr;
        regs.regs[8] = nr;
        regs.regs[0] = arg0;
        regs.regs[1] = arg1;
        regs.regs[2] = arg2;
        regs.regs[3] = arg3;
        regs.regs[4] = arg4;
        regs.regs[5] = arg5;
        return ((warp_raw_syscall_f)addr)(&regs);
    }
    return ((raw_syscall6_f)addr)(arg0, arg1, arg2, arg3, arg4, arg5);
}
KP_EXPORT_SYMBOL(raw_syscall6);

hook_err_t fp_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    if (!is_compat) {
        if (!sys_call_table) return HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(sys_call_table + nr);
        if (has_syscall_wrapper) narg = 1;
        return fp_hook_wrap(fp_addr, narg, before, after, udata);
    } else {
        if (!compat_sys_call_table) return HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(compat_sys_call_table + nr);
        if (has_syscall_wrapper) narg = 1;
        return fp_hook_wrap(fp_addr, narg, before, after, udata);
    }
}
KP_EXPORT_SYMBOL(fp_wrap_syscalln);

hook_err_t fp_unwrap_syscalln_checked(int nr, int is_compat, void *before,
                                      void *after)
{
    if (!is_compat) {
        if (!sys_call_table) return -HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(sys_call_table + nr);
        return fp_hook_unwrap_checked(fp_addr, before, after);
    } else {
        if (!compat_sys_call_table) return -HOOK_BAD_ADDRESS;
        uintptr_t fp_addr = (uintptr_t)(compat_sys_call_table + nr);
        return fp_hook_unwrap_checked(fp_addr, before, after);
    }
}
KP_EXPORT_SYMBOL(fp_unwrap_syscalln_checked);

void fp_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    hook_err_t rc = fp_unwrap_syscalln_checked(nr, is_compat, before, after);
    if (rc) logke("fp syscall unwrap deferred/failed rc=%d\n", rc);
}
KP_EXPORT_SYMBOL(fp_unwrap_syscalln);

/*
sys_xxx.cfi_jt

hint #0x22  # bti c
b #0xfffffffffeb452f4
*/
hook_err_t inline_wrap_syscalln(int nr, int narg, int is_compat, void *before, void *after, void *udata)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    if (!addr) return -HOOK_BAD_ADDRESS;
    if (has_syscall_wrapper) narg = 1;
    return hook_wrap((void *)addr, narg, before, after, udata);
}
KP_EXPORT_SYMBOL(inline_wrap_syscalln);

hook_err_t inline_unwrap_syscalln_checked(int nr, int is_compat, void *before,
                                          void *after)
{
    uintptr_t addr = syscalln_name_addr(nr, is_compat);
    if (!addr) return -HOOK_BAD_ADDRESS;
    return hook_unwrap_remove_checked((void *)addr, before, after, 1);
}
KP_EXPORT_SYMBOL(inline_unwrap_syscalln_checked);

void inline_unwrap_syscalln(int nr, int is_compat, void *before, void *after)
{
    hook_err_t rc = inline_unwrap_syscalln_checked(
        nr, is_compat, before, after);
    if (rc) logke("inline syscall unwrap deferred/failed rc=%d\n", rc);
}
KP_EXPORT_SYMBOL(inline_unwrap_syscalln);

hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    return syscall_wrap_recorded(nr, narg, 0, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_syscalln);

hook_err_t unhook_syscalln_checked(int nr, void *before, void *after)
{
    return syscall_unwrap_recorded(nr, 0, before, after);
}
KP_EXPORT_SYMBOL(unhook_syscalln_checked);

void unhook_syscalln(int nr, void *before, void *after)
{
    hook_err_t rc = unhook_syscalln_checked(nr, before, after);
    if (rc) logke("syscall unhook deferred/failed rc=%d\n", rc);
}
KP_EXPORT_SYMBOL(unhook_syscalln);

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    return syscall_wrap_recorded(nr, narg, 1, before, after, udata);
}
KP_EXPORT_SYMBOL(hook_compat_syscalln);

hook_err_t unhook_compat_syscalln_checked(int nr, void *before, void *after)
{
    return syscall_unwrap_recorded(nr, 1, before, after);
}
KP_EXPORT_SYMBOL(unhook_compat_syscalln_checked);

void unhook_compat_syscalln(int nr, void *before, void *after)
{
    hook_err_t rc = unhook_compat_syscalln_checked(nr, before, after);
    if (rc) logke("compat syscall unhook deferred/failed rc=%d\n", rc);
}
KP_EXPORT_SYMBOL(unhook_compat_syscalln);

void syscall_init()
{
    for (int i = 0; i < SYSCALL_ROUTE_COUNT; i++) {
        syscall_hook_route_reset(&syscall_routes[i]);
        syscall_hook_route_reset(&compat_syscall_routes[i]);
    }

    for (int i = 0; i < sizeof(syscall_name_table) / sizeof(syscall_name_table[0]); i++) {
        uintptr_t *addr = (uintptr_t *)&syscall_name_table[i].name;
        *addr = link2runtime(*addr);
    }

    for (int i = 0; i < sizeof(compat_syscall_name_table) / sizeof(compat_syscall_name_table[0]); i++) {
        uintptr_t *addr = (uintptr_t *)&compat_syscall_name_table[i].name;
        *addr = link2runtime(*addr);
    }

    sys_call_table = (typeof(sys_call_table))kallsyms_lookup_name("sys_call_table");
    log_boot("sys_call_table addr: %llx\n", sys_call_table);

    compat_sys_call_table = (typeof(compat_sys_call_table))kallsyms_lookup_name("compat_sys_call_table");
    log_boot("compat_sys_call_table addr: %llx\n", compat_sys_call_table);

    has_config_compat = 0;
    has_syscall_wrapper = 0;

    if (kallsyms_lookup_name("__arm64_compat_sys_openat")) {
        has_config_compat = 1;
        has_syscall_wrapper = 1;
    } else {
        if (kallsyms_lookup_name("compat_sys_call_table") || kallsyms_lookup_name("compat_sys_openat")) {
            has_config_compat = 1;
        }
        if (kallsyms_lookup_name("__arm64_sys_openat")) {
            has_syscall_wrapper = 1;
        }
    }

    log_boot("syscall config_compat: %d\n", has_config_compat);
    log_boot("syscall has_wrapper: %d\n", has_syscall_wrapper);
}

/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <hook.h>
#include <symbol.h>
#include <pgtable.h>
#include <cache.h>
#include "hmem.h"

static volatile int32_t fp_hook_guard;

static void fp_hook_lock(void)
{
    while (__atomic_exchange_n(&fp_hook_guard, 1, __ATOMIC_ACQUIRE))
        asm volatile("yield" ::: "memory");
}

static void fp_hook_unlock(void)
{
    __atomic_store_n(&fp_hook_guard, 0, __ATOMIC_RELEASE);
}

static inline __attribute__((always_inline)) int32_t
fp_transit_reader_inc(volatile int32_t *reader)
{
    int32_t value;
    uint32_t status;
    asm volatile(
        "1: ldaxr %w[value], [%[reader]]\n"
        "add %w[value], %w[value], #1\n"
        "stlxr %w[status], %w[value], [%[reader]]\n"
        "cbnz %w[status], 1b\n"
        : [value] "=&r"(value), [status] "=&r"(status)
        : [reader] "r"(reader)
        : "memory");
    return value;
}

static inline __attribute__((always_inline)) int
fp_chain_snapshot_items(fp_hook_chain_t *chain,
                        uint8_t retained[FP_HOOK_CHAIN_NUM])
{
    int max = __atomic_load_n(&chain->chain_items_max, __ATOMIC_ACQUIRE);
    if (max < 0) max = 0;
    if (max > FP_HOOK_CHAIN_NUM) max = FP_HOOK_CHAIN_NUM;
    for (int i = 0; i < FP_HOOK_CHAIN_NUM; i++) retained[i] = 0;
    for (int i = 0; i < max; i++) {
        if (__atomic_load_n(&chain->states[i], __ATOMIC_ACQUIRE) !=
            CHAIN_ITEM_STATE_READY)
            continue;
        fp_transit_reader_inc(&chain->readers[i]);
        if (__atomic_load_n(&chain->states[i], __ATOMIC_ACQUIRE) ==
            CHAIN_ITEM_STATE_READY) {
            retained[i] = 1;
        } else {
            hook_item_reader_release(
                &chain->states[i], &chain->readers[i],
                &chain->debt_counted[i], chain->debt_ptr,
                &chain->udata[i], &chain->befores[i], &chain->afters[i]);
        }
    }
    return max;
}

static inline __attribute__((always_inline)) void
fp_chain_release_items(fp_hook_chain_t *chain,
                       const uint8_t retained[FP_HOOK_CHAIN_NUM], int max)
{
    for (int i = 0; i < max; i++) {
        if (!retained[i]) continue;
        hook_item_reader_release(
            &chain->states[i], &chain->readers[i],
            &chain->debt_counted[i], chain->debt_ptr,
            &chain->udata[i], &chain->befores[i], &chain->afters[i]);
    }
}

// transit0
typedef uint64_t (*transit0_func_t)();

uint64_t __attribute__((section(".fp.transit0.text"))) __attribute__((__noinline__)) _fp_transit0()
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    uint32_t *vptr = (uint32_t *)this_va;
    while (*--vptr != ARM64_NOP) {
    };
    vptr--;
    fp_hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, fp_hook_chain_t, transit);
    uint8_t retained[FP_HOOK_CHAIN_NUM];
    int retained_max = fp_chain_snapshot_items(hook_chain, retained);
    hook_fargs0_t fargs;
    fargs.skip_origin = 0;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < retained_max; i++) {
        if (!retained[i]) continue;
        hook_chain0_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit0_func_t origin_func = (transit0_func_t)hook_chain->hook.origin_fp;
        fargs.ret = origin_func();
    }
    for (int32_t i = retained_max - 1; i >= 0; i--) {
        if (!retained[i]) continue;
        hook_chain0_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    fp_chain_release_items(hook_chain, retained, retained_max);
    return fargs.ret;
}
extern void _fp_transit0_end();

// transit4
typedef uint64_t (*transit4_func_t)(uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".fp.transit4.text"))) __attribute__((__noinline__))
_fp_transit4(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    uint32_t *vptr = (uint32_t *)this_va;
    while (*--vptr != ARM64_NOP) {
    };
    vptr--;
    fp_hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, fp_hook_chain_t, transit);
    uint8_t retained[FP_HOOK_CHAIN_NUM];
    int retained_max = fp_chain_snapshot_items(hook_chain, retained);
    hook_fargs4_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < retained_max; i++) {
        if (!retained[i]) continue;
        hook_chain4_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit4_func_t origin_func = (transit4_func_t)hook_chain->hook.origin_fp;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3);
    }
    for (int32_t i = retained_max - 1; i >= 0; i--) {
        if (!retained[i]) continue;
        hook_chain4_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    fp_chain_release_items(hook_chain, retained, retained_max);
    return fargs.ret;
}

extern void _fp_transit4_end();

// transit8:
typedef uint64_t (*transit8_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".fp.transit8.text"))) __attribute__((__noinline__))
_fp_transit8(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
             uint64_t arg7)
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    uint32_t *vptr = (uint32_t *)this_va;
    while (*--vptr != ARM64_NOP) {
    };
    vptr--;
    fp_hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, fp_hook_chain_t, transit);
    uint8_t retained[FP_HOOK_CHAIN_NUM];
    int retained_max = fp_chain_snapshot_items(hook_chain, retained);
    hook_fargs8_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < retained_max; i++) {
        if (!retained[i]) continue;
        hook_chain8_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit8_func_t origin_func = (transit8_func_t)hook_chain->hook.origin_fp;
        fargs.ret =
            origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6, fargs.arg7);
    }
    for (int32_t i = retained_max - 1; i >= 0; i--) {
        if (!retained[i]) continue;
        hook_chain8_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    fp_chain_release_items(hook_chain, retained, retained_max);
    return fargs.ret;
}

extern void _fp_transit8_end();

// transit12:
typedef uint64_t (*transit12_func_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                                     uint64_t, uint64_t, uint64_t, uint64_t);

uint64_t __attribute__((section(".fp.transit12.text"))) __attribute__((__noinline__))
_fp_transit12(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
              uint64_t arg7, uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11)
{
    uint64_t this_va;
    asm volatile("adr %0, ." : "=r"(this_va));
    uint32_t *vptr = (uint32_t *)this_va;
    while (*--vptr != ARM64_NOP) {
    };
    vptr--;
    fp_hook_chain_t *hook_chain = local_container_of((uint64_t)vptr, fp_hook_chain_t, transit);
    uint8_t retained[FP_HOOK_CHAIN_NUM];
    int retained_max = fp_chain_snapshot_items(hook_chain, retained);
    hook_fargs12_t fargs;
    fargs.skip_origin = 0;
    fargs.arg0 = arg0;
    fargs.arg1 = arg1;
    fargs.arg2 = arg2;
    fargs.arg3 = arg3;
    fargs.arg4 = arg4;
    fargs.arg5 = arg5;
    fargs.arg6 = arg6;
    fargs.arg7 = arg7;
    fargs.arg8 = arg8;
    fargs.arg9 = arg9;
    fargs.arg10 = arg10;
    fargs.arg11 = arg11;
    fargs.chain = hook_chain;
    for (int32_t i = 0; i < retained_max; i++) {
        if (!retained[i]) continue;
        hook_chain12_callback func = hook_chain->befores[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    if (!fargs.skip_origin) {
        transit12_func_t origin_func = (transit12_func_t)hook_chain->hook.origin_fp;
        fargs.ret = origin_func(fargs.arg0, fargs.arg1, fargs.arg2, fargs.arg3, fargs.arg4, fargs.arg5, fargs.arg6,
                                fargs.arg7, fargs.arg8, fargs.arg9, fargs.arg10, fargs.arg11);
    }
    for (int32_t i = retained_max - 1; i >= 0; i--) {
        if (!retained[i]) continue;
        hook_chain12_callback func = hook_chain->afters[i];
        if (func) func(&fargs, hook_chain->udata[i]);
    }
    fp_chain_release_items(hook_chain, retained, retained_max);
    return fargs.ret;
}

extern void _fp_transit12_end();

static hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno)
{
    uint64_t transit_start, transit_end;
    switch (argno) {
    case 0:
        transit_start = (uint64_t)_fp_transit0;
        transit_end = (uint64_t)_fp_transit0_end;
        break;
    case 1:
    case 2:
    case 3:
    case 4:
        transit_start = (uint64_t)_fp_transit4;
        transit_end = (uint64_t)_fp_transit4_end;
        break;
    case 5:
    case 6:
    case 7:
    case 8:
        transit_start = (uint64_t)_fp_transit8;
        transit_end = (uint64_t)_fp_transit8_end;
        break;
    default:
        transit_start = (uint64_t)_fp_transit12;
        transit_end = (uint64_t)_fp_transit12_end;
        break;
    }

    int32_t transit_num = (transit_end - transit_start) / 4;

    // todo: assert
    if (transit_num > TRANSIT_INST_NUM - 2) return -HOOK_TRANSIT_NO_MEM;

    transit[0] = ARM64_BTI_JC;
    transit[1] = ARM64_NOP;
    for (int i = 0; i < transit_num; i++) {
        transit[i + 2] = ((uint32_t *)transit_start)[i];
    }
    return HOOK_NO_ERR;
}

void fp_hook(uintptr_t fp_addr, void *replace, void **backup)
{
    if (!hook_management_context_ok()) {
        logke("Function-pointer hook rejected outside process context\n");
        return;
    }
    uint64_t *entry = pgtable_entry_kernel(fp_addr);
    uint64_t ori_prot = *entry;
    modify_entry_kernel(fp_addr, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
    flush_tlb_kernel_page(fp_addr);
    *(uintptr_t *)backup = *(uintptr_t *)fp_addr;
    *(uintptr_t *)fp_addr = (uintptr_t)replace;
    dsb(ish);
    modify_entry_kernel(fp_addr, entry, ori_prot);
}
KP_EXPORT_SYMBOL(fp_hook);

hook_err_t fp_unhook_checked(uintptr_t fp_addr, void *backup)
{
    hook_err_t rc;
    if (!hook_management_context_ok()) return -HOOK_BAD_CONTEXT;
    uint64_t *entry = pgtable_entry_kernel(fp_addr);
    uint64_t ori_prot = *entry;
    modify_entry_kernel(fp_addr, entry, (ori_prot | PTE_DBM) & ~PTE_RDONLY);
    *(uintptr_t *)fp_addr = (uintptr_t)backup;
    dsb(ish);
    isb();
    flush_icache_all();
    modify_entry_kernel(fp_addr, entry, ori_prot);
    rc = hook_reactivation_grace();
    return rc;
}
KP_EXPORT_SYMBOL(fp_unhook_checked);

void fp_unhook(uintptr_t fp_addr, void *backup)
{
    hook_err_t rc = fp_unhook_checked(fp_addr, backup);
    if (rc) logke("Function-pointer unhook failed rc=%d\n", rc);
}
KP_EXPORT_SYMBOL(fp_unhook);

static hook_err_t fp_chain_add_locked(fp_hook_chain_t *chain, void *before,
                                      void *after, void *udata)
{
    for (int i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if ((before && chain->befores[i] == before) || (after && chain->afters[i] == after)) return -HOOK_DUPLICATED;
        if (__atomic_load_n(&chain->states[i], __ATOMIC_ACQUIRE) ==
            CHAIN_ITEM_STATE_EMPTY) {
            __atomic_store_n(&chain->states[i], CHAIN_ITEM_STATE_BUSY,
                             __ATOMIC_RELEASE);
            chain->udata[i] = udata;
            chain->befores[i] = before;
            chain->afters[i] = after;
            if (i + 1 > chain->chain_items_max) {
                __atomic_store_n(&chain->chain_items_max, i + 1,
                                 __ATOMIC_RELEASE);
            }
            __atomic_store_n(&chain->states[i], CHAIN_ITEM_STATE_READY,
                             __ATOMIC_RELEASE);
            logkv("Wrap func pointer add: %llx, %llx, %llx successed\n", chain->hook.fp_addr, before, after);
            return HOOK_NO_ERR;
        }
    }
    logkv("Wrap func pointer add: %llx, %llx, %llx failed\n", chain->hook.fp_addr, before, after);
    return -HOOK_CHAIN_FULL;
}

static int fp_chain_find_item(fp_hook_chain_t *chain, void *before,
                              void *after)
{
    for (int i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        int state = __atomic_load_n(&chain->states[i], __ATOMIC_ACQUIRE);
        if ((state == CHAIN_ITEM_STATE_READY ||
             state == CHAIN_ITEM_STATE_BUSY ||
             state == CHAIN_ITEM_STATE_REMOVING ||
             state == CHAIN_ITEM_STATE_DRAINING) &&
            ((before && chain->befores[i] == before) ||
             (after && chain->afters[i] == after)))
            return i;
    }
    return -1;
}

hook_err_t fp_hook_wrap(uintptr_t fp_addr, int32_t argno, void *before,
                        void *after, void *udata)
{
    hook_err_t err = HOOK_NO_ERR;
    int needs_install = 0;
    if (!hook_management_context_ok()) return -HOOK_BAD_CONTEXT;
    if (is_bad_address((void *)fp_addr)) return -HOOK_BAD_ADDRESS;

retry:
    fp_hook_lock();
    fp_hook_chain_t *chain = hook_get_mem_from_origin(fp_addr);
    if (chain) {
        int install_state;
        if (hook_get_mem_type(chain) != FUNCTION_POINTER_CHAIN) {
            fp_hook_unlock();
            return -HOOK_WRONG_TYPE;
        }
        install_state = __atomic_load_n(&chain->installed,
                                        __ATOMIC_ACQUIRE);
        if (install_state == CHAIN_INSTALL_UPDATING) {
            fp_hook_unlock();
            return -HOOK_READER_BUSY;
        }
        if (install_state == CHAIN_INSTALL_RETIRED &&
            !__atomic_load_n(&chain->grace_complete, __ATOMIC_ACQUIRE)) {
            fp_hook_unlock();
            err = hook_reactivation_grace();
            if (err) return err;
            fp_hook_lock();
            chain = hook_get_mem_from_origin(fp_addr);
            if (!chain) {
                fp_hook_unlock();
                return -HOOK_NOT_FOUND;
            }
            if (__atomic_load_n(&chain->installed, __ATOMIC_ACQUIRE) ==
                CHAIN_INSTALL_RETIRED)
                __atomic_store_n(&chain->grace_complete, 1,
                                 __ATOMIC_RELEASE);
            fp_hook_unlock();
            goto retry;
        }
        err = fp_chain_add_locked(chain, before, after, udata);
        if (!err && install_state == CHAIN_INSTALL_RETIRED) {
            __atomic_store_n(&chain->installed, CHAIN_INSTALL_UPDATING,
                             __ATOMIC_RELEASE);
            needs_install = 1;
        }
        fp_hook_unlock();
        if (!err && needs_install) {
            flush_icache_all();
            fp_hook(chain->hook.fp_addr, (void *)chain->hook.replace_addr,
                    (void **)&chain->hook.origin_fp);
            fp_hook_lock();
            __atomic_store_n(&chain->installed, CHAIN_INSTALL_ACTIVE,
                             __ATOMIC_RELEASE);
            fp_hook_unlock();
        }
        return err;
    }

    chain = (fp_hook_chain_t *)hook_mem_zalloc(
        fp_addr, FUNCTION_POINTER_CHAIN);
    if (!chain) {
        fp_hook_unlock();
        return -HOOK_NO_MEM;
    }
    chain->hook.fp_addr = fp_addr;
    chain->hook.replace_addr = (uint64_t)chain->transit;
    chain->debt_ptr = &hook_deferred_debt;
    err = hook_chain_prepare(chain->transit, argno);
    if (err) goto failed;
    err = fp_chain_add_locked(chain, before, after, udata);
    if (err) goto failed;
    __atomic_store_n(&chain->installed, CHAIN_INSTALL_UPDATING,
                     __ATOMIC_RELEASE);
    fp_hook_unlock();
    flush_icache_all();
    fp_hook(chain->hook.fp_addr, (void *)chain->hook.replace_addr,
            (void **)&chain->hook.origin_fp);
    fp_hook_lock();
    __atomic_store_n(&chain->installed, CHAIN_INSTALL_ACTIVE,
                     __ATOMIC_RELEASE);
    fp_hook_unlock();
    return HOOK_NO_ERR;

failed:
    hook_mem_free(chain);
    fp_hook_unlock();
    return err;
}
KP_EXPORT_SYMBOL(fp_hook_wrap);

hook_err_t fp_hook_unwrap_checked(uintptr_t fp_addr, void *before,
                                  void *after)
{
    enum hook_remove_state remove_state;
    int empty = 1;
    int needs_uninstall = 0;
    int item;
    int install_state;
    if (!hook_management_context_ok()) return -HOOK_BAD_CONTEXT;
    if (is_bad_address((void *)fp_addr)) return -HOOK_BAD_ADDRESS;

    fp_hook_lock();
    fp_hook_chain_t *chain = (fp_hook_chain_t *)hook_get_mem_from_origin(fp_addr);
    if (!chain || hook_get_mem_type(chain) != FUNCTION_POINTER_CHAIN) {
        fp_hook_unlock();
        return chain ? -HOOK_WRONG_TYPE : -HOOK_NOT_FOUND;
    }
    install_state = __atomic_load_n(&chain->installed, __ATOMIC_ACQUIRE);
    if (install_state == CHAIN_INSTALL_UPDATING) {
        fp_hook_unlock();
        return -HOOK_READER_BUSY;
    }
    if (install_state == CHAIN_INSTALL_RETIRED) {
        if (!__atomic_load_n(&chain->grace_complete, __ATOMIC_ACQUIRE)) {
            fp_hook_unlock();
            hook_err_t grace_rc = hook_reactivation_grace();
            if (grace_rc) return grace_rc;
            fp_hook_lock();
            __atomic_store_n(&chain->grace_complete, 1,
                             __ATOMIC_RELEASE);
            fp_hook_unlock();
            return HOOK_NO_ERR;
        }
        fp_hook_unlock();
        return HOOK_NO_ERR;
    }
    item = fp_chain_find_item(chain, before, after);
    if (item < 0) {
        for (int i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
            if (__atomic_load_n(&chain->states[i], __ATOMIC_ACQUIRE) !=
                CHAIN_ITEM_STATE_EMPTY) {
                fp_hook_unlock();
                return -HOOK_NOT_FOUND;
            }
        }
    } else {
        remove_state = hook_item_begin_remove(
            &chain->states[item], &chain->debt_counted[item],
            &chain->readers[item], chain->debt_ptr);
        if (remove_state == HOOK_REMOVE_FINISHED) {
            fp_hook_unlock();
            return HOOK_NO_ERR;
        }
        if (remove_state == HOOK_REMOVE_DEFERRED) {
            fp_hook_unlock();
            return -HOOK_DEFERRED;
        }
        if (remove_state != HOOK_REMOVE_READY) {
            fp_hook_unlock();
            return __atomic_load_n(&chain->states[item], __ATOMIC_ACQUIRE) ==
                CHAIN_ITEM_STATE_DRAINING ? -HOOK_DEFERRED : -HOOK_NOT_FOUND;
        }
        chain->udata[item] = 0;
        chain->befores[item] = 0;
        chain->afters[item] = 0;
        hook_item_finish_remove(&chain->states[item],
                                &chain->debt_counted[item],
                                chain->debt_ptr);
    }

    for (int i = 0; i < FP_HOOK_CHAIN_NUM; i++) {
        if (__atomic_load_n(&chain->states[i], __ATOMIC_ACQUIRE) !=
            CHAIN_ITEM_STATE_EMPTY) {
            empty = 0;
            break;
        }
    }
    if (empty) {
        __atomic_store_n(&chain->installed, CHAIN_INSTALL_UPDATING,
                         __ATOMIC_RELEASE);
        needs_uninstall = 1;
    }
    fp_hook_unlock();

    if (needs_uninstall) {
        hook_err_t unhook_rc = fp_unhook_checked(
            chain->hook.fp_addr, (void *)chain->hook.origin_fp);
        fp_hook_lock();
        __atomic_store_n(&chain->installed, CHAIN_INSTALL_RETIRED,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&chain->grace_complete, unhook_rc ? 0 : 1,
                         __ATOMIC_RELEASE);
        fp_hook_unlock();
        if (unhook_rc) return unhook_rc;
    }
    logkv("Wrap func pointer remove: %llx, %llx, %llx\n",
          chain->hook.fp_addr, before, after);
    return HOOK_NO_ERR;
}
KP_EXPORT_SYMBOL(fp_hook_unwrap_checked);

void fp_hook_unwrap(uintptr_t fp_addr, void *before, void *after)
{
    hook_err_t rc = fp_hook_unwrap_checked(fp_addr, before, after);
    if (rc)
        logke("Function-pointer unwrap deferred/failed rc=%d debt=%d\n",
              rc, hook_cleanup_pending());
}
KP_EXPORT_SYMBOL(fp_hook_unwrap);

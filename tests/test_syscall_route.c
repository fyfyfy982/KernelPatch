/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdio.h>
#include <stdlib.h>

#include "../kernel/patch/include/syscall_route.h"

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            fprintf(stderr, "FAIL line=%d expression=%s\n", __LINE__,        \
                    #condition);                                                \
            return EXIT_FAILURE;                                                \
        }                                                                       \
    } while (0)

int main(void)
{
    struct syscall_hook_route native = {0};
    struct syscall_hook_route compat = {0};
    struct syscall_hook_route_claim claim;

    CHECK(syscall_hook_route_begin_install(
              &native, 0x1000, 0x2000, &claim) == 0);
    CHECK(claim.backend == SYSCALL_HOOK_FUNCTION_POINTER &&
          claim.target == 0x1000 && !claim.was_bound);
    syscall_hook_route_finish_install(&native, &claim, 1);

    CHECK(syscall_hook_route_begin_install(
              &native, 0, 0x3000, &claim) == 0);
    CHECK(claim.backend == SYSCALL_HOOK_FUNCTION_POINTER &&
          claim.target == 0x1000 && claim.was_bound);
    syscall_hook_route_finish_install(&native, &claim, 1);

    CHECK(syscall_hook_route_begin_install(
              &compat, 0, 0x4000, &claim) == 0);
    CHECK(claim.backend == SYSCALL_HOOK_INLINE &&
          claim.target == 0x4000 && !claim.was_bound);
    syscall_hook_route_finish_install(&compat, &claim, 1);
    CHECK(syscall_hook_route_begin_remove(&compat, &claim) == 0);
    CHECK(claim.backend == SYSCALL_HOOK_INLINE && claim.target == 0x4000);
    syscall_hook_route_finish_remove(&compat);
    CHECK(syscall_hook_route_begin_install(
              &compat, 0x5000, 0, &claim) == 0);
    CHECK(claim.backend == SYSCALL_HOOK_INLINE &&
          claim.target == 0x4000 && claim.was_bound);
    syscall_hook_route_finish_install(&compat, &claim, 0);

    syscall_hook_route_reset(&native);
    CHECK(syscall_hook_route_begin_remove(&native, &claim) != 0);
    CHECK(syscall_hook_route_begin_install(
              &native, 0, 0x6000, &claim) == 0);
    syscall_hook_route_finish_install(&native, &claim, 0);
    CHECK(native.state == SYSCALL_ROUTE_UNBOUND);
    CHECK(native.backend == SYSCALL_HOOK_NONE && native.target == 0);
    puts("syscall_route_test PASS");
    return EXIT_SUCCESS;
}

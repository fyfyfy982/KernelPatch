/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdio.h>
#include <stdlib.h>

#include "../kernel/patch/include/module_lifecycle.h"

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            fprintf(stderr, "FAIL line=%d expression=%s\n", __LINE__,        \
                    #condition);                                                \
            return 1;                                                           \
        }                                                                       \
    } while (0)

static int test_info_control_concurrency(void)
{
    struct module_lifecycle lifecycle;
    enum module_lifecycle_state previous;
    bool exit_done;

    module_lifecycle_init(&lifecycle);
    module_lifecycle_mark_live(&lifecycle);
    CHECK(module_lifecycle_try_get_info(&lifecycle));
    CHECK(module_lifecycle_try_get_control(&lifecycle, 0x1234));
    CHECK(module_lifecycle_is_control_owner(&lifecycle, 0x1234));
    CHECK(!module_lifecycle_try_get_control(&lifecycle, 0x5678));
    CHECK(lifecycle.active_calls == 2);

    CHECK(module_lifecycle_begin_unload(&lifecycle, &previous, &exit_done));
    CHECK(previous == MODULE_STATE_LIVE);
    CHECK(!exit_done);
    CHECK(!module_lifecycle_try_get_info(&lifecycle));
    CHECK(!module_lifecycle_try_get_control(&lifecycle, 0x9999));
    CHECK(!module_lifecycle_is_idle(&lifecycle));

    module_lifecycle_restore(&lifecycle, previous, -16);
    CHECK(module_lifecycle_put_control(&lifecycle));
    CHECK(module_lifecycle_put_info(&lifecycle));
    CHECK(module_lifecycle_is_idle(&lifecycle));
    return 0;
}

static int test_init_rollback_failure_and_retry(void)
{
    struct module_lifecycle lifecycle;
    enum module_lifecycle_state previous;
    bool exit_done;

    module_lifecycle_init(&lifecycle);
    lifecycle.init_error = -5;
    module_lifecycle_mark_exit_failed(&lifecycle, -16);
    CHECK(lifecycle.state == MODULE_STATE_EXIT_FAILED);
    CHECK(lifecycle.init_error == -5);
    CHECK(lifecycle.exit_error == -16);
    CHECK(module_lifecycle_try_get_info(&lifecycle));
    CHECK(module_lifecycle_put_info(&lifecycle));

    CHECK(module_lifecycle_begin_unload(&lifecycle, &previous, &exit_done));
    CHECK(previous == MODULE_STATE_EXIT_FAILED);
    CHECK(!exit_done);
    module_lifecycle_mark_exit_done(&lifecycle);
    CHECK(module_lifecycle_is_idle(&lifecycle));

    CHECK(module_lifecycle_begin_unload(&lifecycle, &previous, &exit_done));
    CHECK(previous == MODULE_STATE_EXIT_DONE);
    CHECK(exit_done);
    CHECK(module_lifecycle_is_idle(&lifecycle));
    return 0;
}

static int test_exit_done_waits_for_prior_info_ref(void)
{
    struct module_lifecycle lifecycle;
    enum module_lifecycle_state previous;
    bool exit_done;

    module_lifecycle_init(&lifecycle);
    module_lifecycle_mark_live(&lifecycle);
    CHECK(module_lifecycle_try_get_info(&lifecycle));
    CHECK(module_lifecycle_begin_unload(&lifecycle, &previous, &exit_done));
    CHECK(!exit_done);
    module_lifecycle_mark_exit_done(&lifecycle);
    CHECK(!module_lifecycle_try_get_info(&lifecycle));
    CHECK(!module_lifecycle_is_idle(&lifecycle));
    CHECK(module_lifecycle_put_info(&lifecycle));
    CHECK(module_lifecycle_is_idle(&lifecycle));

    CHECK(module_lifecycle_begin_unload(&lifecycle, &previous, &exit_done));
    CHECK(exit_done);
    CHECK(module_lifecycle_is_idle(&lifecycle));
    return 0;
}

static int test_retiring_cannot_be_reclaimed(void)
{
    struct module_lifecycle lifecycle;
    enum module_lifecycle_state previous;
    bool exit_done;

    module_lifecycle_init(&lifecycle);
    module_lifecycle_mark_live(&lifecycle);
    CHECK(module_lifecycle_begin_unload(&lifecycle, &previous, &exit_done));
    CHECK(!exit_done);
    module_lifecycle_mark_retiring(&lifecycle);
    CHECK(lifecycle.state == MODULE_STATE_RETIRING);
    CHECK(!module_lifecycle_begin_unload(
        &lifecycle, &previous, &exit_done));

    module_lifecycle_mark_exit_done(&lifecycle);
    lifecycle.exit_error = -38;
    CHECK(module_lifecycle_begin_unload(&lifecycle, &previous, &exit_done));
    CHECK(previous == MODULE_STATE_EXIT_DONE);
    CHECK(exit_done);
    module_lifecycle_mark_retiring(&lifecycle);
    CHECK(!module_lifecycle_begin_unload(
        &lifecycle, &previous, &exit_done));
    return 0;
}

int main(void)
{
    if (test_info_control_concurrency()) return EXIT_FAILURE;
    if (test_init_rollback_failure_and_retry()) return EXIT_FAILURE;
    if (test_exit_done_waits_for_prior_info_ref()) return EXIT_FAILURE;
    if (test_retiring_cannot_be_reclaimed()) return EXIT_FAILURE;
    puts("module_lifecycle_test PASS");
    return EXIT_SUCCESS;
}

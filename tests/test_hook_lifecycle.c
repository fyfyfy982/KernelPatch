/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdio.h>
#include <stdlib.h>

#include "../kernel/include/hook_lifecycle.h"

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            fprintf(stderr, "FAIL line=%d expression=%s\n", __LINE__,        \
                    #condition);                                                \
            return EXIT_FAILURE;                                                \
        }                                                                       \
    } while (0)

static int test_many_hook_exit_drain(void)
{
    enum { HOOK_COUNT = 33 };
    int8_t states[HOOK_COUNT];
    uint8_t counted[HOOK_COUNT] = {0};
    volatile int32_t readers[HOOK_COUNT];
    volatile int32_t debt = 0;

    for (int i = 0; i < HOOK_COUNT; i++) {
        states[i] = CHAIN_ITEM_STATE_READY;
        readers[i] = 1;
        CHECK(hook_item_begin_remove(
                  &states[i], &counted[i], &readers[i], &debt) ==
              HOOK_REMOVE_DEFERRED);
    }
    CHECK(debt == HOOK_COUNT);

    for (int i = HOOK_COUNT - 1; i >= 0; i--) {
        readers[i]--;
        CHECK(hook_item_try_claim_drain(&states[i], &readers[i]));
        hook_item_finish_remove(&states[i], &counted[i], &debt);
        if (i != 0) CHECK(debt != 0);
    }
    CHECK(debt == 0);
    for (int i = 0; i < HOOK_COUNT; i++)
        CHECK(states[i] == CHAIN_ITEM_STATE_EMPTY && counted[i] == 0);
    return EXIT_SUCCESS;
}

int main(void)
{
    int8_t state = CHAIN_ITEM_STATE_READY;
    uint8_t counted = 0;
    volatile int32_t readers = 1;
    volatile int32_t debt = 0;

    CHECK(hook_item_begin_remove(&state, &counted, &readers, &debt) ==
          HOOK_REMOVE_DEFERRED);
    CHECK(state == CHAIN_ITEM_STATE_BUSY);
    CHECK(counted == 1 && debt == 1);
    CHECK(hook_item_begin_remove(&state, &counted, &readers, &debt) ==
          HOOK_REMOVE_DEFERRED);
    CHECK(debt == 1);

    readers = 0;
    CHECK(hook_item_begin_remove(&state, &counted, &readers, &debt) ==
          HOOK_REMOVE_READY);
    CHECK(state == CHAIN_ITEM_STATE_DRAINING);
    hook_item_finish_remove(&state, &counted, &debt);
    CHECK(state == CHAIN_ITEM_STATE_EMPTY);
    CHECK(counted == 0 && debt == 0);

    state = CHAIN_ITEM_STATE_READY;
    readers = 1;
    CHECK(hook_item_begin_remove(&state, &counted, &readers, &debt) ==
          HOOK_REMOVE_DEFERRED);
    CHECK(state == CHAIN_ITEM_STATE_BUSY && debt == 1);
    readers--;
    CHECK(readers == 0);
    CHECK(hook_item_try_claim_drain(&state, &readers));
    hook_item_finish_remove(&state, &counted, &debt);
    CHECK(state == CHAIN_ITEM_STATE_EMPTY);
    CHECK(counted == 0 && debt == 0);

    state = CHAIN_ITEM_STATE_READY;
    CHECK(hook_item_begin_remove(&state, &counted, &readers, &debt) ==
          HOOK_REMOVE_READY);
    CHECK(state == CHAIN_ITEM_STATE_DRAINING);
    hook_item_finish_remove(&state, &counted, &debt);
    CHECK(debt == 0);
    CHECK(test_many_hook_exit_drain() == EXIT_SUCCESS);
    puts("hook_lifecycle_test PASS");
    return EXIT_SUCCESS;
}

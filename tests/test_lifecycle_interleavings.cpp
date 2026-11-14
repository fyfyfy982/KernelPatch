/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <thread>

#include "../kernel/include/hook_lifecycle.h"
#include "../kernel/patch/include/module_lifecycle.h"
#include "../kernel/patch/include/syscall_route.h"

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            std::fprintf(stderr, "FAIL line=%d expression=%s\n", __LINE__,    \
                         #condition);                                           \
            return EXIT_FAILURE;                                                \
        }                                                                       \
    } while (0)

class Barrier {
public:
    explicit Barrier(unsigned int count) : threshold_(count), count_(count) {}

    void wait()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const unsigned int generation = generation_;
        if (--count_ == 0) {
            generation_++;
            count_ = threshold_;
            cv_.notify_all();
            return;
        }
        cv_.wait(lock, [&] { return generation != generation_; });
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    const unsigned int threshold_;
    unsigned int count_;
    unsigned int generation_ = 0;
};

struct HookFixture {
    int8_t state = CHAIN_ITEM_STATE_READY;
    uint8_t counted = 0;
    volatile int32_t readers = 1;
    volatile int32_t debt = 0;
    void *udata = reinterpret_cast<void *>(1);
    void *before = reinterpret_cast<void *>(2);
    void *after = reinterpret_cast<void *>(3);
};

static int finish_claimed(HookFixture &fixture)
{
    fixture.udata = nullptr;
    fixture.before = nullptr;
    fixture.after = nullptr;
    hook_item_finish_remove(
        &fixture.state, &fixture.counted, &fixture.debt);
    return fixture.state == CHAIN_ITEM_STATE_EMPTY &&
           fixture.counted == 0 && fixture.debt == 0 &&
           fixture.udata == nullptr && fixture.before == nullptr &&
           fixture.after == nullptr;
}

using ReaderRelease = int (*)(HookFixture &fixture);

static int inline_reader_release(HookFixture &fixture)
{
    return hook_item_reader_release(
        &fixture.state, &fixture.readers, &fixture.counted, &fixture.debt,
        &fixture.udata, &fixture.before, &fixture.after);
}

static int fp_reader_release(HookFixture &fixture)
{
    return hook_item_reader_release(
        &fixture.state, &fixture.readers, &fixture.counted, &fixture.debt,
        &fixture.udata, &fixture.before, &fixture.after);
}

static int test_snapshot_cancel_last_reader(ReaderRelease release)
{
    HookFixture fixture;
    fixture.readers = 0;
    Barrier first_ready_observed(2);
    Barrier removal_published(2);
    std::atomic<int> failed{0};

    std::thread snapshot([&] {
        if (__atomic_load_n(&fixture.state, __ATOMIC_ACQUIRE) !=
            CHAIN_ITEM_STATE_READY)
            failed = 1;
        __atomic_add_fetch(&fixture.readers, 1, __ATOMIC_ACQ_REL);
        first_ready_observed.wait();
        removal_published.wait();
        if (__atomic_load_n(&fixture.state, __ATOMIC_ACQUIRE) ==
            CHAIN_ITEM_STATE_READY)
            failed = 1;
        if (!release(fixture)) failed = 1;
    });
    std::thread remover([&] {
        first_ready_observed.wait();
        if (hook_item_begin_remove(
                &fixture.state, &fixture.counted, &fixture.readers,
                &fixture.debt) != HOOK_REMOVE_DEFERRED)
            failed = 1;
        if (fixture.state != CHAIN_ITEM_STATE_BUSY ||
            fixture.counted != 1 || fixture.debt != 1)
            failed = 1;
        removal_published.wait();
    });
    snapshot.join();
    remover.join();
    CHECK(!failed.load());
    CHECK(fixture.state == CHAIN_ITEM_STATE_EMPTY);
    CHECK(fixture.readers == 0 && fixture.debt == 0);
    CHECK(fixture.udata == nullptr && fixture.before == nullptr &&
          fixture.after == nullptr);
    return EXIT_SUCCESS;
}

static int test_reader_before_debt_publish()
{
    HookFixture fixture;
    Barrier claimed(2);
    Barrier reader_released(2);
    std::atomic<int> failed{0};

    std::thread remover([&] {
        if (!hook_item_claim_state(&fixture.state, CHAIN_ITEM_STATE_READY,
                                   CHAIN_ITEM_STATE_REMOVING))
            failed = 1;
        claimed.wait();
        reader_released.wait();
        hook_item_publish_debt(&fixture.counted, &fixture.debt);
        if (!hook_item_try_claim_removing_drain(
                &fixture.state, &fixture.readers) ||
            !finish_claimed(fixture))
            failed = 1;
    });
    std::thread reader([&] {
        claimed.wait();
        __atomic_sub_fetch(&fixture.readers, 1, __ATOMIC_ACQ_REL);
        if (hook_item_try_claim_drain(&fixture.state, &fixture.readers))
            failed = 1;
        reader_released.wait();
    });
    remover.join();
    reader.join();
    CHECK(!failed.load());
    return EXIT_SUCCESS;
}

static int test_reader_after_debt_before_waiting()
{
    HookFixture fixture;
    Barrier debt_published(2);
    Barrier reader_released(2);
    std::atomic<int> failed{0};

    std::thread remover([&] {
        if (!hook_item_claim_state(&fixture.state, CHAIN_ITEM_STATE_READY,
                                   CHAIN_ITEM_STATE_REMOVING))
            failed = 1;
        hook_item_publish_debt(&fixture.counted, &fixture.debt);
        debt_published.wait();
        reader_released.wait();
        if (!hook_item_try_claim_removing_drain(
                &fixture.state, &fixture.readers) ||
            !finish_claimed(fixture))
            failed = 1;
    });
    std::thread reader([&] {
        debt_published.wait();
        __atomic_sub_fetch(&fixture.readers, 1, __ATOMIC_ACQ_REL);
        if (hook_item_try_claim_drain(&fixture.state, &fixture.readers))
            failed = 1;
        reader_released.wait();
    });
    remover.join();
    reader.join();
    CHECK(!failed.load());
    return EXIT_SUCCESS;
}

static int test_reader_after_waiting_publish()
{
    HookFixture fixture;
    Barrier waiting_published(2);
    Barrier reader_finished(2);
    std::atomic<int> failed{0};

    std::thread remover([&] {
        if (!hook_item_claim_state(&fixture.state, CHAIN_ITEM_STATE_READY,
                                   CHAIN_ITEM_STATE_REMOVING))
            failed = 1;
        hook_item_publish_debt(&fixture.counted, &fixture.debt);
        hook_item_publish_waiting(&fixture.state);
        waiting_published.wait();
        reader_finished.wait();
        if (fixture.state != CHAIN_ITEM_STATE_EMPTY ||
            fixture.counted != 0 || fixture.debt != 0)
            failed = 1;
    });
    std::thread reader([&] {
        waiting_published.wait();
        __atomic_sub_fetch(&fixture.readers, 1, __ATOMIC_ACQ_REL);
        if (!hook_item_try_claim_drain(&fixture.state, &fixture.readers) ||
            !finish_claimed(fixture))
            failed = 1;
        reader_finished.wait();
    });
    remover.join();
    reader.join();
    CHECK(!failed.load());
    return EXIT_SUCCESS;
}

static int test_route_operation_does_not_spin()
{
    syscall_hook_route route{};
    syscall_hook_route_claim install_claim{};
    syscall_hook_route_claim competing_claim{};
    Barrier claimed(2);
    Barrier competitor_done(2);
    std::atomic<int> failed{0};

    std::thread installer([&] {
        if (syscall_hook_route_begin_install(
                &route, 0x1000, 0, &install_claim) != 0)
            failed = 1;
        claimed.wait();
        competitor_done.wait();
        syscall_hook_route_finish_install(&route, &install_claim, 1);
    });
    std::thread competitor([&] {
        claimed.wait();
        if (syscall_hook_route_begin_remove(
                &route, &competing_claim) != -2)
            failed = 1;
        if (syscall_hook_route_begin_install(
                &route, 0, 0x2000, &competing_claim) != -2)
            failed = 1;
        competitor_done.wait();
    });
    installer.join();
    competitor.join();
    CHECK(!failed.load());
    CHECK(route.state == SYSCALL_ROUTE_BOUND);
    CHECK(route.backend == SYSCALL_HOOK_FUNCTION_POINTER);
    CHECK(route.target == 0x1000);

    CHECK(syscall_hook_route_begin_remove(&route, &competing_claim) == 0);
    CHECK(syscall_hook_route_begin_install(
              &route, 0, 0x3000, &install_claim) == -2);
    syscall_hook_route_finish_remove(&route);
    CHECK(syscall_hook_route_begin_install(
              &route, 0, 0x3000, &install_claim) == 0);
    CHECK(install_claim.backend == SYSCALL_HOOK_FUNCTION_POINTER);
    CHECK(install_claim.target == 0x1000 && install_claim.was_bound);
    syscall_hook_route_finish_install(&route, &install_claim, 1);
    return EXIT_SUCCESS;
}

static int test_retiring_owner_window()
{
    module_lifecycle lifecycle;
    module_lifecycle_init(&lifecycle);
    module_lifecycle_mark_live(&lifecycle);
    std::mutex lock;
    Barrier retiring(2);
    Barrier second_checked(2);
    std::atomic<int> failed{0};

    std::thread first([&] {
        module_lifecycle_state previous;
        bool exit_done;
        {
            std::lock_guard<std::mutex> guard(lock);
            if (!module_lifecycle_begin_unload(
                    &lifecycle, &previous, &exit_done) || exit_done)
                failed = 1;
            module_lifecycle_mark_retiring(&lifecycle);
        }
        retiring.wait();
        second_checked.wait();
        std::lock_guard<std::mutex> guard(lock);
        module_lifecycle_mark_exit_done(&lifecycle);
        lifecycle.exit_error = -38;
    });
    std::thread second([&] {
        module_lifecycle_state previous;
        bool exit_done;
        retiring.wait();
        {
            std::lock_guard<std::mutex> guard(lock);
            if (module_lifecycle_begin_unload(
                    &lifecycle, &previous, &exit_done))
                failed = 1;
        }
        second_checked.wait();
    });
    first.join();
    second.join();
    CHECK(!failed.load());

    module_lifecycle_state previous;
    bool exit_done;
    {
        std::lock_guard<std::mutex> guard(lock);
        CHECK(module_lifecycle_begin_unload(
            &lifecycle, &previous, &exit_done));
    }
    CHECK(previous == MODULE_STATE_EXIT_DONE && exit_done);
    return EXIT_SUCCESS;
}

int main()
{
    if (test_reader_before_debt_publish()) return EXIT_FAILURE;
    if (test_reader_after_debt_before_waiting()) return EXIT_FAILURE;
    if (test_reader_after_waiting_publish()) return EXIT_FAILURE;
    if (test_snapshot_cancel_last_reader(inline_reader_release))
        return EXIT_FAILURE;
    if (test_snapshot_cancel_last_reader(fp_reader_release))
        return EXIT_FAILURE;
    if (test_route_operation_does_not_spin()) return EXIT_FAILURE;
    if (test_retiring_owner_window()) return EXIT_FAILURE;
    std::puts("lifecycle_interleavings_test PASS");
    return EXIT_SUCCESS;
}

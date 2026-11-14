from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def function_body(source: str, name: str) -> str:
    match = re.search(
        rf"(?m)^[ \t]*(?:static[ \t]+)?[^;\n]*\b{name}\s*\([^;]*?\)\s*\{{",
        source,
        re.S,
    )
    if not match:
        raise AssertionError(f"function not found: {name}")
    depth = 0
    for index in range(match.end() - 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[match.start() : index + 1]
    raise AssertionError(f"unterminated function: {name}")


def main() -> None:
    rcupdate = (ROOT / "kernel/linux/include/linux/rcupdate.h").read_text()
    module = (ROOT / "kernel/patch/module/module.c").read_text()
    syscall = (ROOT / "kernel/patch/common/syscall.c").read_text()
    hook = (ROOT / "kernel/base/hook.c").read_text()
    fphook = (ROOT / "kernel/base/fphook.c").read_text()
    hook_lifecycle = (ROOT / "kernel/include/hook_lifecycle.h").read_text()
    route = (ROOT / "kernel/patch/include/syscall_route.h").read_text()

    sync_body = function_body(rcupdate, "synchronize_rcu")
    assert "kfunc_call(synchronize_rcu)" in sync_body
    assert "rcu_barrier_tasks_rude" not in sync_body

    retire = function_body(module, "module_retire")
    assert "if (!kfunc(synchronize_rcu))" in retire
    assert retire.find("list_del_rcu") < retire.find("synchronize_rcu();")
    assert retire.find("synchronize_rcu();") < retire.find("return 0;")
    assert "list_for_each_entry_rcu" in function_body(module, "find_module")
    unload = function_body(module, "unload_module")
    assert unload.find("module_retire(mod)") < unload.find("module_destroy(mod)")
    assert "module_lifecycle_is_control_owner" in unload
    assert unload.find("module_lifecycle_mark_retiring") < unload.find(
        "module_retire(mod)"
    )
    assert "module_lifecycle_mark_exit_done" in unload

    wrap = function_body(syscall, "hook_syscalln")
    unwrap = function_body(syscall, "unhook_syscalln_checked")
    compat_wrap = function_body(syscall, "hook_compat_syscalln")
    compat_unwrap = function_body(syscall, "unhook_compat_syscalln_checked")
    assert "syscall_wrap_recorded" in wrap
    assert "syscall_unwrap_recorded" in unwrap
    assert "sys_call_table" not in unwrap
    assert "syscall_wrap_recorded" in compat_wrap
    assert "syscall_unwrap_recorded" in compat_unwrap
    assert "compat_sys_call_table" not in compat_unwrap
    assert "syscall_route_guard" not in syscall
    recorded_wrap = function_body(syscall, "syscall_wrap_recorded")
    recorded_unwrap = function_body(syscall, "syscall_unwrap_recorded")
    assert recorded_wrap.find("syscall_hook_route_begin_install") < recorded_wrap.find(
        "fp_hook_wrap"
    )
    assert recorded_wrap.find("hook_wrap") < recorded_wrap.find(
        "syscall_hook_route_finish_install"
    )
    assert recorded_unwrap.find("syscall_hook_route_begin_remove") < recorded_unwrap.find(
        "fp_hook_unwrap_checked"
    )
    assert recorded_unwrap.find("hook_unwrap_remove_checked") < recorded_unwrap.find(
        "syscall_hook_route_finish_remove"
    )
    assert "while" not in function_body(route, "syscall_hook_route_begin_install")
    assert "while" not in function_body(route, "syscall_hook_route_begin_remove")

    begin_remove = function_body(hook_lifecycle, "hook_item_begin_remove")
    finish_remove = function_body(hook_lifecycle, "hook_item_finish_remove")
    assert begin_remove.find("CHAIN_ITEM_STATE_REMOVING") < begin_remove.find(
        "hook_item_publish_debt"
    )
    assert begin_remove.find("hook_item_publish_debt") < begin_remove.find(
        "hook_item_publish_waiting"
    )
    assert finish_remove.find("hook_item_debt_dec") < finish_remove.find(
        "CHAIN_ITEM_STATE_EMPTY"
    )
    inline_snapshot = function_body(hook, "hook_chain_snapshot_items")
    inline_release = function_body(hook, "hook_chain_release_items")
    fp_snapshot = function_body(fphook, "fp_chain_snapshot_items")
    fp_release = function_body(fphook, "fp_chain_release_items")
    assert inline_snapshot.count("hook_item_reader_release") == 1
    assert inline_release.count("hook_item_reader_release") == 1
    assert fp_snapshot.count("hook_item_reader_release") == 1
    assert fp_release.count("hook_item_reader_release") == 1

    plain = function_body(hook, "unhook_checked")
    assert "hook_mem_mark_cleanup_debt" in plain
    assert "return -HOOK_DEFERRED" in plain
    assert "hook_uninstall" not in plain

    print("lifecycle_source_contract PASS")


if __name__ == "__main__":
    main()

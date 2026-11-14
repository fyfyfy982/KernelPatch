#!/usr/bin/env python3

import argparse
import pathlib
import re
import subprocess
import tempfile


SECTIONS = (
    ".transit0.text",
    ".transit4.text",
    ".transit8.text",
    ".transit12.text",
    ".fp.transit0.text",
    ".fp.transit4.text",
    ".fp.transit8.text",
    ".fp.transit12.text",
)


def run(command: list[str], cwd: pathlib.Path) -> str:
    result = subprocess.run(command, cwd=cwd, check=True, text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clang", required=True)
    parser.add_argument("--objdump", required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    hook_header = (root / "kernel/include/hook.h").read_text(encoding="utf-8")
    capacity_match = re.search(
        r"^#define\s+TRANSIT_INST_NUM\s+(0x[0-9a-fA-F]+|[0-9]+)",
        hook_header,
        re.MULTILINE,
    )
    if not capacity_match:
        raise SystemExit("TRANSIT_INST_NUM is missing")
    transit_capacity = int(capacity_match.group(1), 0)
    includes = [
        "-Ikernel",
        "-Ikernel/include",
        "-Ikernel/patch/include",
        "-Ikernel/linux",
        "-Ikernel/linux/include",
        "-Ikernel/linux/arch/arm64/include",
        "-Ikernel/linux/tools/arch/arm64/include",
    ]

    with tempfile.TemporaryDirectory(prefix="kp-transit-pic-") as tmp:
        tmpdir = pathlib.Path(tmp)
        objects = []
        compiler = [args.clang]
        if "clang" in pathlib.Path(args.clang).name.lower():
            compiler.append("--target=aarch64-none-elf")
        for source in ("kernel/base/hook.c", "kernel/base/fphook.c"):
            output = tmpdir / (pathlib.Path(source).stem + ".o")
            run([
                *compiler,
                "-fno-builtin",
                "-std=gnu11",
                "-nostdinc",
                "-DANDROID",
                "-O2",
                *includes,
                "-c",
                source,
                "-o",
                str(output),
            ], root)
            objects.append(output)

        seen = set()
        sizes = {}
        for obj in objects:
            headers = run([args.objdump, "-h", str(obj)], root)
            for section in SECTIONS:
                match = re.search(
                    rf"^\s*\d+\s+{re.escape(section)}\s+([0-9a-fA-F]+)\s",
                    headers,
                    re.MULTILINE,
                )
                if match:
                    sizes[section] = int(match.group(1), 16)
                    seen.add(section)

                    disassembly = run(
                        [args.objdump, "-d", f"--section={section}", str(obj)],
                        root,
                    )
                    mnemonics = re.findall(
                        r"^\s*[0-9a-f]+:\s+[0-9a-f]{8}\s+([a-z0-9.]+)",
                        disassembly,
                        re.MULTILINE,
                    )
                    if "bl" in mnemonics:
                        raise SystemExit(f"{section}: external/direct BL present")
                    relocations = run(
                        [args.objdump, "-r", f"--section={section}", str(obj)],
                        root,
                    )
                    if "R_AARCH64_" in relocations:
                        raise SystemExit(f"{section}: relocation present")
                    if "ldaxr" not in mnemonics or "stlxr" not in mnemonics:
                        raise SystemExit(
                            f"{section}: reader count is not inline LL/SC"
                        )

        missing = set(SECTIONS) - seen
        if missing:
            raise SystemExit(f"missing transit sections: {sorted(missing)}")
        oversized = {
            section: size for section, size in sizes.items()
            if size // 4 + 2 > transit_capacity
        }
        if oversized:
            raise SystemExit(f"transit buffer overflow: {oversized}")

    print("transit_pic_test PASS", " ".join(
        f"{section}={sizes[section]}" for section in SECTIONS
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

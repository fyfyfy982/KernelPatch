#!/usr/bin/env sh
set -eu

repo="$(git rev-parse --show-toplevel)"
patch="$repo/artifacts/hook-module-lifecycle-20261114/transaction/DIFF_FILE"
base="0d80e994f26b7c25fc03a45753ed2c93be430554"

git -C "$repo" apply --check -R "$patch"
git -C "$repo" diff --name-only "$base..HEAD" -- kernel tests |
while IFS= read -r path; do
    [ -n "$path" ] || continue
    git -C "$repo" restore --source="$base" --worktree -- "$path"
done

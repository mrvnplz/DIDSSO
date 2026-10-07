#!/usr/bin/env bash
set -euo pipefail

readonly STWO_REPOSITORY="https://github.com/starkware-libs/stwo-cairo.git"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REVISION_FILE="$SCRIPT_DIR/STWO_COMMIT"
readonly PATCH_FILE="$SCRIPT_DIR/patches/stwo-cairo-public-segment-context.patch"

STWO_COMMIT="$(tr -d '[:space:]' < "$REVISION_FILE")"
STWO_SOURCE_DIR="${STWO_SOURCE_DIR:-$HOME/stwo-cairo}"
STWO_SKIP_BUILD="${STWO_SKIP_BUILD:-0}"

if [[ ! "$STWO_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    echo "STWO_COMMIT must contain one full Git commit hash" >&2
    exit 1
fi

if [[ -e "$STWO_SOURCE_DIR" && ! -d "$STWO_SOURCE_DIR/.git" ]]; then
    echo "STWO_SOURCE_DIR exists but is not a Git repository: $STWO_SOURCE_DIR" >&2
    exit 1
fi

if [[ ! -d "$STWO_SOURCE_DIR/.git" ]]; then
    git clone "$STWO_REPOSITORY" "$STWO_SOURCE_DIR"
fi

current_commit="$(git -C "$STWO_SOURCE_DIR" rev-parse HEAD)"
if [[ "$current_commit" != "$STWO_COMMIT" ]]; then
    if [[ -n "$(git -C "$STWO_SOURCE_DIR" status --porcelain --untracked-files=all)" ]]; then
        echo "Refusing to change revision in a dirty STWO checkout: $STWO_SOURCE_DIR" >&2
        exit 1
    fi
    if ! git -C "$STWO_SOURCE_DIR" cat-file -e "$STWO_COMMIT^{commit}" 2>/dev/null; then
        git -C "$STWO_SOURCE_DIR" fetch --depth 1 origin "$STWO_COMMIT"
    fi
    git -C "$STWO_SOURCE_DIR" checkout --detach "$STWO_COMMIT"
fi

if git -C "$STWO_SOURCE_DIR" apply --unidiff-zero --reverse --check --ignore-space-change "$PATCH_FILE" >/dev/null 2>&1; then
    echo "STWO compatibility patch is already applied"
elif git -C "$STWO_SOURCE_DIR" apply --unidiff-zero --check --ignore-space-change "$PATCH_FILE"; then
    git -C "$STWO_SOURCE_DIR" apply --unidiff-zero --ignore-space-change "$PATCH_FILE"
    echo "Applied STWO compatibility patch"
else
    echo "The STWO compatibility patch is neither applicable nor already applied" >&2
    exit 1
fi

mapfile -t dirty_paths < <(
    git -C "$STWO_SOURCE_DIR" status --porcelain --untracked-files=all |
        cut -c4-
)
for dirty_path in "${dirty_paths[@]}"; do
    case "$dirty_path" in
        stwo_cairo_prover/crates/adapter/src/adapter.rs | \
        stwo_cairo_prover/crates/adapter/src/opcodes.rs | \
        stwo_cairo_prover/crates/dev_utils/src/vm_utils.rs)
            ;;
        *)
            echo "Unexpected local STWO change: $dirty_path" >&2
            exit 1
            ;;
    esac
done

if [[ "$STWO_SKIP_BUILD" == "1" ]]; then
    echo "Pinned STWO checkout and patch are ready at $STWO_SOURCE_DIR"
    exit 0
fi

(
    cd "$STWO_SOURCE_DIR/stwo_cairo_prover"
    export RUSTFLAGS="${RUSTFLAGS:--C target-cpu=native -C opt-level=3}"
    cargo build --release --locked --bin run_and_prove --bin verify
)

echo "STWO prover and verifier are ready at $STWO_SOURCE_DIR/stwo_cairo_prover/target/release"

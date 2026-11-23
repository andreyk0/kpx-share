default: check

fmt:
    cargo fmt

lint:
    cargo clippy --all-targets -- -D warnings

test:
    cargo test

build:
    cargo build --release

# Replace ~/.cargo/bin/kpx-share with the release build.
install: build
    install -m 755 target/release/kpx-share ~/.cargo/bin/kpx-share

# Empties target/. On btrfs it keeps target/ a subvolume, so filesystem snapshots skip build
# output: `cargo clean` would delete the subvolume, and the next build would make a plain directory.
clean:
    #!/usr/bin/env bash
    set -euo pipefail
    shopt -s inherit_errexit
    fs=$(stat -f -c %T .)
    if [[ "$fs" != btrfs ]]; then
        cargo clean
    # A btrfs subvolume root always has inode 256.
    elif [[ -e target && "$(stat -c %i target)" == 256 ]]; then
        find target -mindepth 1 -delete
    else
        rm -rf target
        btrfs subvolume create target
    fi

# What "ready" means: formatted, lint-clean, tests green.
check:
    cargo fmt --check
    just lint
    just test

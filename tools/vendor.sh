#!/bin/sh
# Puts every crate the lockfile names in vendor/, so a package build needs
# no network. vendor/ is not in git.
set -e
cd "$(dirname "$0")/.."
cargo vendor --locked --versioned-dirs vendor >/dev/null 2>&1
echo "vendor/: $(ls vendor | wc -l) crates"

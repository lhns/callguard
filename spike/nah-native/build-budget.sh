#!/bin/sh
# Builds the spike against nah with nah-budget.patch: a clone of the pinned rev,
# patched, and a copy of this crate whose manifest points at it.
# usage: build-budget.sh WORKDIR [cargo args]
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$1
shift
rev=07fea9d900b4a3c012d0a8ec1bc60c7dab18c8d7
mkdir -p "$work"
if [ ! -d "$work/nah/.git" ]; then
  git clone -q https://github.com/manuelschipper/nah "$work/nah"
  git -C "$work/nah" checkout -q "$rev"
  git -C "$work/nah" apply --ignore-whitespace "$here/nah-budget.patch"
fi
rm -rf "$work/spike"
mkdir -p "$work/spike"
cp -r "$here/src" "$here/Cargo.toml" "$here/Cargo.lock" "$here/rust-toolchain.toml" "$work/spike/"
cat >>"$work/spike/Cargo.toml" <<EOF

[patch."https://github.com/manuelschipper/nah"]
nah-cli = { path = "../nah/crates/nah-cli" }
nah-proto = { path = "../nah/crates/nah-proto" }
nah-observe = { path = "../nah/crates/nah-observe" }
EOF
cd "$work/spike"
cargo build --features budget "$@"

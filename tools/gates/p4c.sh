#!/bin/sh
set -eu

timeout 600 cargo test -p arinsal-vm --features difftest --test stage1 -- --nocapture
ARINSAL_GC_STRESS=1 timeout 600 cargo test -p arinsal-vm --features difftest --test stage1 -- --nocapture
ARINSAL_GC_STRESS=1 timeout 600 cargo test -p arinsal-vm --test native_abi

#!/bin/sh
export LLVM_PROFILE_FILE="../profile/default_%m_%p.profraw"

RUSTFLAGS="-C instrument-coverage" cargo test --all-features --all-targets --tests -- --nocapture


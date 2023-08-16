#!/bin/sh

export LLVM_PROFILE_FILE="${PWD}/profile/%p-%m.profraw"

RUSTFLAGS="-C instrument-coverage" cargo build 

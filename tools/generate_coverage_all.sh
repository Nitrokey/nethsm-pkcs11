#!/bin/sh -x

set -e

./tools/build_profiling.sh
./tools/ci_integration_tests.sh
./tools/test_profiling.sh
./tools/get_coverage.sh

SYSROOT=$(rustc --print sysroot)

cov=$(find $SYSROOT -name "llvm-cov")
objects=$(cat _test_objects)
$cov report ${objects} -Xdemangler=rustfilt target/debug/libnethsm_pkcs11.so -instr-profile=profile/libnethsm.profdata  --ignore-filename-regex='/.cargo' --ignore-filename-regex='rustc/'

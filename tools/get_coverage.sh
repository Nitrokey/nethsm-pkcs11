#!/bin/sh

SYSROOT=$(rustc --print sysroot)

profdata=$(find $SYSROOT -name "llvm-profdata")
cov=$(find $SYSROOT -name "llvm-cov")

objects=$(cat _test_objects)

$profdata merge -sparse profile/*.profraw -o profile/libnethsm.profdata
$cov export ${objects} -Xdemangler=rustfilt target/debug/libnethsm_pkcs11.so -instr-profile=profile/libnethsm.profdata  --ignore-filename-regex='/.cargo' --ignore-filename-regex='rustc/'  --format=lcov > coverage.txt

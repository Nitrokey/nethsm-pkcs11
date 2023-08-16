#!/bin/sh

rust-profdata merge -sparse profile/*.profraw -o profile/libnethsm.profdata
rust-cov export  -Xdemangler=rustfilt target/debug/libnethsm_pkcs11.so -instr-profile=profile/libnethsm.profdata  --ignore-filename-regex='/.cargo' --ignore-filename-regex='rustc/'  --format=lcov > coverage.txt

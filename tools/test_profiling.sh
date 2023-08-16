#!/bin/bash

export LLVM_PROFILE_FILE="${PWD}/profile/%p-%m.profraw"
echo $LLVM_PROFILE_FILE

rm -rf _test_objects

RUSTFLAGS="-C instrument-coverage" cargo test --all-features --all-targets 


files=$(RUSTFLAGS="-C instrument-coverage" cargo test --tests --no-run --message-format=json | jq -r "select(.profile.test == true) | .filenames[]" | grep -v dSYM - )

for file in $files;
do 
  printf "%s %s " -object $file >> _test_objects
done
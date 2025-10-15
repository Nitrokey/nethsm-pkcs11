#!/bin/sh -x

set -e

mkdir -p profile

export LLVM_PROFILE_FILE="${PWD}/profile/%p-%m.profraw"

echo $LLVM_PROFILE_FILE

echo "Starting tests"

export P11NETHSM_CONFIG_FILE=./p11nethsm.conf

# execute all scripts in the tests directory
for f in ./tools/tests/*.sh; do
    echo "Executing $f"
    bash $f
done

echo "All tests passed"

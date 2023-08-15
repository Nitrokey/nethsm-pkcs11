#!/bin/sh -x

set -e

echo "Starting tests"

export P11NETHSM_CONFIG_FILE=./p11nethsm.conf

# execute all scripts in the tests directory
for f in ./tools/tests/*.sh; do
    echo "Executing $f"
    sh $f
done

echo "All tests passed"
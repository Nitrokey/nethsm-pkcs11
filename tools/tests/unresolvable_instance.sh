#!/bin/bash -x

set -e

export P11NETHSM_CONFIG_FILE=./tools/tests/p11nethsm.unresolvable.conf

output=$(pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so -O 2>&1 || true)
echo "$output"

! grep --quiet panic <<< "$output"
grep --quiet "C_GetSlotInfo failed: rv = CKR_DEVICE_REMOVED" <<< "$output"

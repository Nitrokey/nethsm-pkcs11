#!/bin/bash -x

set -e

if [[ $NETHSM_VERSION == v3.0 ]]
then
  exit
fi

pkcs11-tool --module target/debug/libnethsm_pkcs11.so -p opPassphrase --test

#!/bin/sh -x

mkdir /tmp

P11NETHSM_CONFIG_FILE=./tools/invalid_cert.conf pkcs11-tool --module target/debug/libnethsm_pkcs11.so -O

if [ $? -eq 0 ]; then
    cat /tmp/hsm.log
    exit 1
fi

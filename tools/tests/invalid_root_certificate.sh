#!/bin/sh -x

P11NETHSM_CONFIG_FILE=./tools/invalid_root_cert.conf pkcs11-tool --module target/debug/libnethsm_pkcs11.so -O 

if [ $? -eq 0 ]; then
    exit 1
fi

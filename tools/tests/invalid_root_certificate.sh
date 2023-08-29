#!/bin/sh -x

if P11NETHSM_CONFIG_FILE=./tools/invalid_root_cert.conf pkcs11-tool --module target/debug/libnethsm_pkcs11.so -O ; then
    exit 1
fi

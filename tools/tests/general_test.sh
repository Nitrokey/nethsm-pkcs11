#!/bin/sh -x

set -e

# pkcs11-tool --test tries to sign 35 bytes of data with RSA_PKCS1. NetHSM v3.0 only accepts
# digests with the correct length in PKCS1 mode. Therefore we have to disable this test.

# pkcs11-tool --module target/debug/libnethsm_pkcs11.so -p opPassphrase --test

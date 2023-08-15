#!/bin/sh -x

set -e

pkcs11-tool --module target/debug/libnethsm_pkcs11.so -p opPassphrase --test
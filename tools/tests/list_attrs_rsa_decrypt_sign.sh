#!/bin/sh -x

set -e

KEYID=rsakey3
HEXID=$(echo -n ${KEYID} | xxd -ps)

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so -O --id $HEXID > _list_rsa_decrypt_sign.txt

grep -E "^  Usage:      decrypt, sign$" _list_rsa_decrypt_sign.txt

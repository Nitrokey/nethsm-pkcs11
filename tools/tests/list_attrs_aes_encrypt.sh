#!/bin/sh -x

set -e

KEYID=aeskey1
HEXID=$(echo -n ${KEYID} | xxd -ps)

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so -O --id $HEXID > _list_aes_encrypt.txt

grep -E "^  Usage:      encrypt$" _list_aes_encrypt.txt

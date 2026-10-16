#!/bin/sh -x

set -e

KEYID=aeskey3
HEXID=$(echo -n ${KEYID} | xxd -ps)

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so -O --id $HEXID > _list_aes_encrypt_decrypt.txt

grep -E "^  Usage:      encrypt, decrypt$" _list_aes_encrypt_decrypt.txt

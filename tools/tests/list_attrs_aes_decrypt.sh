#!/bin/sh -x

set -e 

KEYID=aeskey2
HEXID=$(echo -n ${KEYID} | xxd -ps)

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so -O --id $HEXID > _list_aes_decrypt.txt

grep -E "^  Usage:      decrypt$" _list_aes_decrypt.txt

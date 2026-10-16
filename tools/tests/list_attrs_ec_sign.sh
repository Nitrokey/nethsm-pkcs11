#!/bin/sh -x

set -e

KEYID=eckey256
HEXID=$(echo -n ${KEYID} | xxd -ps)

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so -O --id $HEXID > _list_ec_sign.txt

grep -E "^  Usage:      sign$" _list_ec_sign.txt

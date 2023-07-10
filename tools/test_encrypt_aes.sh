#!/bin/sh -x

set -e 

KEYID=aeskey

HEXID=$(echo -n ${KEYID} | xxd -ps)

rm -rf _data.crypt _public.pem

IV=$(openssl rand -hex 16)

echo "NetHSM rulez!" | pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v --encrypt \
  --mechanism AES-CBC --id $HEXID \
  --output-file _data.crypt --iv $IV

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v --decrypt \
  --mechanism AES-CBC --input-file _data.crypt --id $HEXID \
  --iv $IV
  
#!/bin/sh -x

set -e

echo "Starting tests"

export P11NETHSM_CONFIG_FILE=./p11nethsm.conf

./tools/tests/decrypt_rsa_sha1.sh
./tools/tests/decrypt_rsa_sha256.sh
./tools/tests/decrypt_rsa_sha512.sh
./tools/tests/decrypt_rsa.sh
./tools/tests/encrypt_aes.sh
./tools/tests/sign_ec_p224.sh
./tools/tests/sign_ec_p256.sh
./tools/tests/sign_ec_p384.sh
./tools/tests/sign_ec_p521.sh
./tools/tests/sign_ed.sh
./tools/tests/sign_rsa.sh
./tools/tests/sign_rsa_sha1.sh
./tools/tests/sign_rsa_sha256.sh
./tools/tests/upload_ed_key_id.sh
./tools/tests/upload_ec_key.sh
./tools/tests/upload_ec_key_id.sh
./tools/tests/upload_aes_key.sh
# doesn't work, pkcs11-tool can't read the key on 0.23 
# ./tools/tests/upload_rsa_key.sh
# ./tools/tests/upload_certificate.sh
./tools/tests/delete_key.sh
./tools/tests/generate_rsa_id.sh
./tools/tests/generate_ec_p224_id.sh
./tools/tests/generate_ec_p256_id.sh
./tools/tests/generate_ec_p384_id.sh
./tools/tests/generate_ec_p521_id.sh
./tools/tests/generate_ed_id.sh
./tools/tests/generate_generic_id.sh


./tools/tests/general_test.sh
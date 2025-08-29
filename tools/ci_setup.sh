#/bin/sh

set -e

echo "Provisioning the HSM"

./tools/provision.sh
./tools/create_operator.sh
./tools/create_aes_key.sh
./tools/create_ec_p256_key.sh
./tools/create_ec_p384_key.sh
./tools/create_ec_p521_key.sh
./tools/create_ed_key.sh
./tools/create_rsa_key.sh
./tools/create_web_key.sh



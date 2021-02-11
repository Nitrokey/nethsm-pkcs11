#!/usr/bin/env sh
set -e
# Sign zone with RSA
echo "Signing zone example.com with RSA keys..."
./dns-tools sign pkcs11 -p ./dtc.so -f ./example.com -3 -z example.com -o example.com.signed -c -a rsa || {
  echo "Cannot sign properly"
  exit 1
}

echo "Signing successful!"

# Verify the zone already signed
echo "Verifying previous signature..."
./dns-tools verify -f ./example.com.signed -z example.com || {
  echo "Cannot verify signature :("
  exit 1
}

echo "Verification successful!"

# Sign again but without a working node
NODE_TO_KILL=$((1 + RANDOM % 5))
echo "Killing node $NODE_TO_KILL..."

docker stop "dtcnode$NODE_TO_KILL"

# Sign zone with RSA
echo "Signing zone example.com with a node down, RSA keys and without key creation"
./dns-tools sign pkcs11 -p ./dtc.so -f ./example.com -3 -z example.com -o example.com.signed -a rsa || {
  echo "Cannot sign properly"
  exit 1
}

echo "Signing successful!"

# Verify the zone already signed
echo "Verifying previous signature..."
./dns-tools verify -f ./example.com.signed -z example.com || {
  echo "Cannot verify signature :("
  exit 1
}

echo "Verification successful!"

# Restart killed node
docker start "dtcnode$NODE_TO_KILL"


# Reset HSM keys
echo "Resetting keys..."
./dns-tools reset-pkcs11-keys -p ./dtc.so || {
  echo "Cannot reset keys :("
  exit 1
}

echo "Reset successful!"

# Sign zone with ECDSA
echo "Signing zone example.com with ECDSA keys..."
./dns-tools sign pkcs11 -p ./dtc.so -f ./example.com -3 -z example.com -o example.com.signed -c -a ecdsa || {
  echo "Cannot sign properly"
  exit 1
}

echo "Signing successful!"

# Verify the zone already signed
echo "Verifying previous signature..."
./dns-tools verify -f ./example.com.signed -z example.com || {
  echo "Cannot verify signature :("
  exit 1
}

echo "Verification successful!"

# Sign again but without a working node
NODE_TO_KILL=$((1 + RANDOM % 5))
echo "Killing node $NODE_TO_KILL..."

docker stop "dtcnode$NODE_TO_KILL"

# Sign zone with ECDSA
echo "Signing zone example.com with a node down, ECDSA keys and without key creation"
./dns-tools sign pkcs11 -p ./dtc.so -f ./example.com -3 -z example.com -o example.com.signed -a ecdsa || {
  echo "Cannot sign properly"
  exit 1
}

echo "Signing successful!"

# Verify the zone already signed
echo "Verifying previous signature..."
./dns-tools verify -f ./example.com.signed -z example.com || {
  echo "Cannot verify signature :("
  exit 1
}

echo "Verification successful!"

# Restart killed node
docker start "dtcnode$NODE_TO_KILL"

# Reset HSM keys
echo "Resetting keys..."
./dns-tools reset-pkcs11-keys -p ./dtc.so || {
  echo "Cannot reset keys :("
  exit 1
}

echo "Reset successful!"

echo "All tests passed. please kill this process with ^C."

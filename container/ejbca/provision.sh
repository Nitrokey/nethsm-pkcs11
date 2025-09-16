#!/bin/bash

HOST=nethsm:8443

while ! curl -f -k -s https://${HOST}/api/v1/health/alive ; do sleep 1 ; done

curl -k -v "https://${HOST}/api/v1/provision"   -X POST   -d '{"unlockPassphrase":"UnlockPassphrase","adminPassphrase":"AdminPassphrase","systemTime":"'$(date -u "+%Y-%m-%dT%H:%M:%SZ")'"}'
curl -k -v "https://admin:AdminPassphrase@${HOST}/api/v1/users/operator"   -X PUT   -d '{"role":"Operator", "passphrase":"OperatorOperator","realName":"Operator"}'  -H "Content-Type: application/json"
#curl -k -v "https://admin:AdminPassphrase@${HOST}/api/v1/keys/generate"   -X POST   -d '{ "mechanisms": ["ECDSA_Signature"], "type": "EC_P256", "id": "p256"}'  -H "Content-Type: application/json"
#curl -k -v "https://admin:AdminPassphrase@${HOST}/api/v1/keys/generate"   -X POST   -d '{ "mechanisms": ["ECDSA_Signature"], "type": "EC_P521", "id": "p521"}'  -H "Content-Type: application/json"
#curl -k -v "https://admin:AdminPassphrase@${HOST}/api/v1/keys/generate"   -X POST   -d '{ "mechanisms": ["RSA_Signature_PKCS1", "RSA_Decryption_PKCS1"], "type": "RSA", "length": 2048, "id":"rsa2048" }'  -H "Content-Type: application/json"
#curl -k -v "https://admin:AdminPassphrase@${HOST}/api/v1/keys/generate"   -X POST   -d '{ "mechanisms": ["RSA_Signature_PKCS1", "RSA_Decryption_PKCS1"], "type": "RSA", "length": 4096, "id":"rsa4096" }'  -H "Content-Type: application/json"
#curl -k -v "https://admin:AdminPassphrase@${HOST}/api/v1/keys/generate"   -X POST   -d '{ "mechanisms": ["EdDSA_Signature"], "type": "Curve25519", "id": "ed25519"}'  -H "Content-Type: application/json"

#curl -k -v "https://admin:AdminPassphrase@${HOST}/api/v1/config/logging"   -X PUT   -d '{"ipAddress":"0.0.0.0","port":0,"logLevel":"warning"}' -H "content-type: application/json"


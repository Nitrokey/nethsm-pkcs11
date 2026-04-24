#!/bin/bash

HOST=nethsm:8443

while ! curl -f -k -s https://${HOST}/api/v1/health/alive ; do echo "Waiting for NetHSM so be alive..."; sleep 1 ; done

if curl -k -s https://${HOST}/api/v1/health/state | grep -q "Unprovisioned"; then
    echo "NetHSM unprovisioned. Provisioning now!"
    curl -k -v "https://${HOST}/api/v1/provision" -d '{"unlockPassphrase":"UnlockPassphrase","adminPassphrase":"AdminPassphrase","systemTime":"'$(date -u "+%Y-%m-%dT%H:%M:%SZ")'"}'
    curl -k -v "https://admin:AdminPassphrase@${HOST}/api/v1/users/operator" -X PUT -d '{"role":"Operator", "passphrase":"OperatorOperator","realName":"Operator"}' -H "Content-Type: application/json"
    curl -k -v "https://admin:AdminPassphrase@${HOST}/api/v1/keys/generate" -d '{ "mechanisms": ["RSA_Decryption_OAEP_SHA256"], "type": "RSA", "length": 2048, "id": "bao-root-rsa"}' -H "Content-Type: application/json"
else
    echo "NetHSM already provisioned!"
    if [ "${NETHSM_AUTO_UNLOCK}" = "true" ]; then
        echo "Auto unlocking NetHSM now!"
        curl -k -v "https://admin:AdminPassphrase@${HOST}/api/v1/unlock" -d '{ "passphrase": "UnlockPassphrase" }' -H "Content-Type: application/json"
    fi
    while ! curl -f -k -s https://${HOST}/api/v1/health/ready ; do echo "Waiting for NetHSM to be ready..."; sleep 1 ; done
fi
echo "Finished provisioning!"
exit 0

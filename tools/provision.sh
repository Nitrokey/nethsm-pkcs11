#!/bin/sh

curl  --fail-with-body -k -i  \
  https://localhost:8443/api/v1/provision  -X POST \
  -H "content-type: application/json" -d '{"unlockPassphrase": "UnlockPassphrase",  "adminPassphrase": "Administrator", "systemTime": "2018-10-30T11:20:50Z"  }'
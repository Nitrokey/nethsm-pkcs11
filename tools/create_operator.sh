#!/bin/bash

curl -k -i -w '\n' -u admin:Administrator \
  https://localhost:8443/api/v1/users/operator  -X PUT \
  -H "content-type: application/json" -d "{\"realName\": \"Jane User\",  \
  \"role\": \"Operator\", \"passphrase\": \"opPassphrase\"}"

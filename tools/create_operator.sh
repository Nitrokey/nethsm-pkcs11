#!/bin/bash

curl -i -w '\n' -u admin:adminadmin \
  "https://nethsmdemo.nitrokey.com/api/v1/users/operator" -X PUT \
  -H "content-type: application/json" -d "{\"realName\": \"Jane User\",  \
  \"role\": \"Operator\", \"passphrase\": \"opPassphrase\"}"

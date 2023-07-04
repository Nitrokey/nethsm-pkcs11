#!/bin/bash

#NETHSM_DIR=../nethsm
API_DIR=api

#node $NETHSM_DIR/tools/api/convert_validate.js < $NETHSM_DIR/docs/nethsm-api.raml

#docker run --rm -ti -v "${PWD}:/local" \
#  -e GO_POST_PROCESS_FILE="/usr/local/bin/gofmt -w" \
#  openapitools/openapi-generator-cli generate -g go \
#  -i /local/gen_nethsm_api_oas20.json -o /local/api \
#  -c /local/tools/generator_conf.yaml

docker run --rm -u $UID -v "${PWD}/api:/out" openapitools/openapi-generator-cli generate -i=https://nethsmdemo.nitrokey.com/api_docs/nethsm-api.yaml -o out -g rust
cargo fmt
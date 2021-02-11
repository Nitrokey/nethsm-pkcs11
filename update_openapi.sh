#!/bin/bash

NETHSM_DIR=../nethsm

node $NETHSM_DIR/tools/api/convert_validate.js < $NETHSM_DIR/docs/nethsm-api.raml
docker run --rm -ti -v "${PWD}:/local" \
  -e GO_POST_PROCESS_FILE="/usr/local/bin/gofmt -w" \
  openapitools/openapi-generator-cli generate -g go \
  -i /local/gen_nethsm_api_oas20.json -o /local/openapi \
  -c /local/generator_conf.yaml

rm openapi/go.*

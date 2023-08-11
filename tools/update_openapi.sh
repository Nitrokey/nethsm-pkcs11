#!/bin/bash

docker run --rm -u $UID -v "${PWD}/openapi:/out" -v "${PWD}/tools/generator_conf.yaml:/conf.yaml" crust:latest generate -i=https://nethsmdemo.nitrokey.com/api_docs/nethsm-api.yaml -o out -g crust -c /conf.yaml
cargo fmt
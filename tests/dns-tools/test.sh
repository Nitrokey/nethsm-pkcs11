#!/usr/bin/env bash
set -e
cd "$(dirname $0)" || exit
docker-compose rm -fsv
docker-compose build
go run github.com/niclabs/dtcconfig create \
  -n dtcnode1:2030,dtcnode2:2030,dtcnode3:2030,dtcnode4:2030,dtcnode5:2030 \
  -t 3 \
  -H "dtcclient" \
  -c "dtc/config/dtc-config.yaml" \
  -k "dtcnode/config/"
docker-compose up --remove-orphans

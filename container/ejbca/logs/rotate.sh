#!/bin/bash

TIMESTAMP=$(date "+%y%m%d%H%M%S")

mkdir -p saved

for i in *.log ; do
  cp $i saved/${TIMESTAMP}_$i
  cat /dev/null >$i
  cat /dev/null >$i
done

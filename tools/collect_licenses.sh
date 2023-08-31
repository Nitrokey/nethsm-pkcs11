#!/bin/sh

set -e 

cargo license -d -a > _licenses.txt

cat LICENSE _licenses.txt > _LICENSE
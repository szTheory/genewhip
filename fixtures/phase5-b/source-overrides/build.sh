#!/bin/sh
set -eu
exec make -j4 -f build.mk

#!/bin/sh
# Run on a prepared disposable Linux box; package provisioning is separate.
set -eu
suite_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec sh "$suite_dir/BOX-SUITE.sh"

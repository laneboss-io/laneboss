#!/bin/sh
set -eu
exec ./child-probe "$(cat probe-target)"

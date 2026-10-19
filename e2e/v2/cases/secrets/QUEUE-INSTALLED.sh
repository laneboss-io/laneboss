#!/bin/sh
# Opt-in root entry on the lane's authorized disposable Ubuntu queue box.
set -eu
test "$(id -u)" -eq 0
printf '%s\n' 'secrets queue: public prerequisites'
DEBIAN_FRONTEND=noninteractive apt-get update
DEBIAN_FRONTEND=noninteractive apt-get --assume-yes --no-install-recommends install git jq tmux bubblewrap iproute2 nftables libcap2-bin python3 ca-certificates
printf '%s\n' 'secrets queue: installed stand-in starting'
exec python3 -I -B e2e/v2/cases/secrets/installed.py --source "$1" --evidence "$2"

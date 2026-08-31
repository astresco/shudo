#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
	echo "The development daemon executes as root. Run the clean-environment command printed by: make dev" >&2
	exit 1
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dev_root=$(mktemp -d /tmp/shudo-dev.XXXXXX)
trap 'case "$dev_root" in /tmp/shudo-dev.*) rm -rf -- "$dev_root";; esac' EXIT INT TERM
socket_gid=$(getent group shudo | awk -F: '{print $3}')

sed \
  -e "s|@SHUDO_SOCKET_GID@|$socket_gid|" \
  -e "s|/run/shudo/shudo.sock|$dev_root/shudo.sock|" \
  -e "s|/var/lib/shudo/shudo.db|$dev_root/shudo.db|" \
  -e "s|/etc/shudo/policy.yaml|$repo_root/deploy/systemd/policy.example.yaml|" \
  "$repo_root/deploy/systemd/config.example.yaml" > "$dev_root/config.yaml"

echo "Development socket: $dev_root/shudo.sock" >&2
echo "Use another terminal with: SHUDO_SOCKET_PATH=$dev_root/shudo.sock $repo_root/build/shudo ..." >&2
cd "$repo_root"
exec "$repo_root/build/shudod" --config "$dev_root/config.yaml"

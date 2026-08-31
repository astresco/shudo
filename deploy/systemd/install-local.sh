#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer through sudo or from an existing root session." >&2
  exit 1
fi
if [ "${SHUDO_UNSAFE_LOCAL_INSTALL:-}" != "1" ]; then
  echo "This source-tree installer is development-only. Use a reviewed, checksummed production package." >&2
  exit 1
fi

if [ -n "${SHUDO_REPO_ROOT:-}" ]; then
  repo_root=$SHUDO_REPO_ROOT
else
  repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
fi
if [ "${repo_root#/}" = "$repo_root" ] || [ ! -d "$repo_root" ]; then
  echo "SHUDO_REPO_ROOT must name the absolute Shudo source directory." >&2
  exit 1
fi
for required in getent install sed systemctl systemd-tmpfiles; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "Required command is missing: $required" >&2
    exit 1
  }
done
for artifact in "$repo_root/build/shudod" "$repo_root/build/shudo"; do
	[ -f "$artifact" ] || { echo "Missing build artifact: $artifact (run make build first)" >&2; exit 1; }
done

getent group shudo >/dev/null 2>&1 || groupadd --system shudo
operator=${SUDO_USER:-}
if [ -n "$operator" ] && id "$operator" >/dev/null 2>&1; then
  usermod --append --groups shudo "$operator"
fi
socket_gid=$(getent group shudo | awk -F: '{print $3}')

systemctl stop shudod.service 2>/dev/null || true
install -o root -g root -m 0755 "$repo_root/build/shudod" /usr/local/sbin/shudod
install -o root -g root -m 0755 "$repo_root/build/shudo" /usr/local/bin/shudo
install -d -o root -g root -m 0700 /etc/shudo /var/lib/shudo
install -d -o root -g root -m 0755 /usr/share/doc/shudo
install -o root -g root -m 0644 "$repo_root/README.md" "$repo_root"/docs/*.md /usr/share/doc/shudo/

if [ ! -f /etc/shudo/policy.yaml ]; then
  install -o root -g root -m 0644 "$repo_root/deploy/systemd/policy.example.yaml" /etc/shudo/policy.yaml
fi
sed "s/@SHUDO_SOCKET_GID@/$socket_gid/" "$repo_root/deploy/systemd/config.example.yaml" > /etc/shudo/config.yaml.new
chown root:root /etc/shudo/config.yaml.new
chmod 0644 /etc/shudo/config.yaml.new
mv /etc/shudo/config.yaml.new /etc/shudo/config.yaml

install -o root -g root -m 0644 "$repo_root/deploy/systemd/shudod.service" /etc/systemd/system/shudod.service
install -o root -g root -m 0644 "$repo_root/deploy/systemd/shudo-tmpfiles.conf" /etc/tmpfiles.d/shudo.conf
systemd-tmpfiles --create /etc/tmpfiles.d/shudo.conf
systemctl daemon-reload
systemctl enable --now shudod.service
systemctl --quiet is-active shudod.service

echo "shudod is active. Re-login (or use 'newgrp shudo') before submitting requests."

#!/bin/sh
set -eu

BINARY=${1:-bin/marsec}
UNIT_DIR=/etc/systemd/system
CONFIG_DIR=/etc/marstack-secrets
DATA_DIR=/var/lib/marstack-secrets
USER=marstack-secrets

if [ "$(id -u)" -ne 0 ]; then
	echo "this script must run as root" >&2
	exit 1
fi

if ! id "$USER" >/dev/null 2>&1; then
	useradd --system --no-create-home --shell /usr/sbin/nologin "$USER"
fi

install -m 0755 "$BINARY" /usr/local/bin/marsec

install -d -m 0750 -o "$USER" -g "$USER" "$CONFIG_DIR"
install -d -m 0700 -o "$USER" -g "$USER" "$DATA_DIR"

if [ ! -f "$CONFIG_DIR/environment" ]; then
	install -m 0640 -o root -g "$USER" \
		"$(dirname "$0")/environment.example" "$CONFIG_DIR/environment"
fi

install -m 0644 "$(dirname "$0")/marstack-secrets.service" "$UNIT_DIR/marstack-secrets.service"
systemctl daemon-reload

echo "installed; put a TLS certificate and key in $CONFIG_DIR/tls, then run:"
echo "  systemctl enable --now marstack-secrets"

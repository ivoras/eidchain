#!/bin/sh
# Build eidchain and (re)install its systemd unit and nginx config on this host.
# Idempotent; needs sudo. The repo copies in deploy/ are the source of truth.
set -eu
cd "$(dirname "$0")/.."

echo "== build"
mkdir -p bin
go build -o bin/eidchain ./cmd/eidchain

if [ ! -f data/genesis.json ]; then
  echo "no chain in ./data yet: create one first, e.g." >&2
  echo "  ./bin/eidchain genesis --message 'your headline or text'" >&2
  exit 1
fi

echo "== systemd unit"
sudo cp deploy/eidchain.service /etc/systemd/system/eidchain.service
sudo systemctl daemon-reload
sudo systemctl enable eidchain
sudo systemctl restart eidchain

echo "== nginx"
# The eID CA bundle that nginx uses to verify client certificates.
sudo cp www/hr-eid-ca.pem /etc/nginx/hr-eid-ca.pem
# The live site config is managed by certbot too; only replace it if it differs.
if ! sudo cmp -s deploy/nginx-eidchain.conf /etc/nginx/sites-available/eidchain; then
  sudo cp deploy/nginx-eidchain.conf /etc/nginx/sites-available/eidchain
fi
sudo ln -sf /etc/nginx/sites-available/eidchain /etc/nginx/sites-enabled/eidchain
sudo nginx -t
sudo systemctl reload nginx

echo "== status"
sleep 1
systemctl --no-pager --lines=5 status eidchain || true

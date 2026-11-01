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

echo "== nginx"
# Test the new config before committing to it, and put the old one back if it fails,
# so a mistake here cannot stop nginx at its next restart. The site also serves
# other pages, so do this before touching the node.
live=/etc/nginx/sites-available/eidchain
backup="$(mktemp)"
sudo cp "$live" "$backup" 2>/dev/null || : > "$backup"
# The eID CA bundle that nginx uses to verify client certificates.
sudo cp www/hr-eid-ca.pem /etc/nginx/hr-eid-ca.pem
sudo cp deploy/nginx-eidchain.conf "$live"
sudo ln -sf "$live" /etc/nginx/sites-enabled/eidchain
if ! sudo nginx -t; then
  echo "nginx rejected the new config; restoring the previous one" >&2
  if [ -s "$backup" ]; then sudo cp "$backup" "$live"; else sudo rm -f "$live" /etc/nginx/sites-enabled/eidchain; fi
  rm -f "$backup"
  exit 1
fi
rm -f "$backup"

echo "== systemd unit"
sudo cp deploy/eidchain.service /etc/systemd/system/eidchain.service
sudo systemctl daemon-reload
sudo systemctl enable eidchain
sudo systemctl restart eidchain

sudo systemctl reload nginx

echo "== status"
sleep 1
systemctl --no-pager --lines=5 status eidchain || true

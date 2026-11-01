#!/bin/sh
# The example web app embedded in the binary reuses the browser modules of the
# /signer page (www/signer). Run this after changing them, then rebuild.
set -eu
cd "$(dirname "$0")/.."
for f in webeid-client.js der.js cades.js; do
  cp "www/signer/$f" "internal/webapp/static/$f"
done
echo "synced Web eID client, DER helpers and CAdES builder into internal/webapp/static"

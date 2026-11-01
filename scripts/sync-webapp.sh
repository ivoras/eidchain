#!/bin/sh
# The example web app embedded in the binary shares code with the website:
# the Web eID client, DER helpers and CAdES builder of the /signer page, and
# the design system (site.css) and nav bar (nav.js). The sources of truth are in
# www/; run this after changing them, then rebuild.
set -eu
cd "$(dirname "$0")/.."
for f in signer/webeid-client.js signer/der.js signer/cades.js site.css nav.js; do
  cp "www/$f" "internal/webapp/static/$(basename "$f")"
done
echo "synced shared browser code and styles into internal/webapp/static"

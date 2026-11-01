# eidchain

A proof-of-concept blockchain in Go where

- **blocks are JSON documents**,
- **blocks are signed by one of a set of ECDSA authority keys** (proof of authority),
- **block payloads are JSON records signed with eID smart cards** (Croatian eID by default, other EU cards by configuration),
- payloads are stored **verbatim as JSON strings** and their signatures are **detached** (CAdES-B-B, made in the browser).

It is a PoC: read [Limitations](#limitations) before relying on it.

The repository also holds the website that runs at `eidchain.ivoras.net` (`www/`, served by nginx, including the browser-only `/signer/` page). The chain itself is the Go program in `cmd/` and `internal/`.

## Features

- **One static binary.** The example web app (HTML/JS/CSS) and the default eID CA certificates are embedded with `go:embed`; nothing is read from disk at runtime except your data directory.
- **Proof of authority with any-key-signs-any-block.** Any key in the authority set may sign any block. Forks are resolved by *highest chain wins, ties broken by the lowest block hash*. A key may not sign if it signed one of the previous `floor(N/2)` blocks (the Clique rule), so rewriting history takes a majority of the keys.
- **Authority key rotation inside the chain.** A block may carry `rotations`: control messages that replace one authority key with another. They must be approved by at least a quorum (default: a majority) of the keys that are valid *at that point in the chain*, and they take effect from the next block. Old blocks stay valid under the keys that were current when they were signed.
- **eID-signed payloads.** A payload is a JSON object (at most 10 KiB). Its signature is a detached CAdES-B-B CMS signature over the exact payload bytes, made by the signing certificate on the card. Every node re-verifies the signature and the certificate chain.
- **Configurable eID CAs.** The trusted CA certificates are chosen when a chain is created (default: the Croatian AKDCA Root, HRIDCA and HRIDCA 2025, embedded). Certificates from other EU countries can be added in the config file.
- **OCSP at submission.** When a payload is submitted, the node asks the signer certificate's OCSP responder and fails closed. The signed OCSP response is stored in the block next to the payload so anyone can audit it later (it is committed to by the block hash but is *not* a block validity rule, because revocation answers change over time).
- **Gossip and pull.** Nodes push new blocks, payloads and rotation approvals to configured peers and also pull from them periodically. `eidchain pull` downloads a chain from a running node with `docker pull` semantics: you name the chain by its genesis hash, everything is verified locally from the genesis, and a repeated pull fetches only what is new.
- **Block production every 10 minutes.** If any payloads are waiting, an authority node cuts a block on every 10-minute wall-clock boundary, regardless of how many payloads there are.
- **Example web app.** Anyone can type a message, sign it with their eID card in the browser, and add it to the next block. No accounts.
- **Genesis from a headline.** A new chain is started with `eidchain genesis`; the genesis block holds a free-text message, and the PoC chain's genesis records a BBC News headline from 1 November 2026.

## Quick start

Requires Go 1.26 or newer.

```sh
go build -o bin/eidchain ./cmd/eidchain

# 1. Create a chain: 3 authority keys, the AKD eID CAs, a message.
./bin/eidchain genesis --message 'BBC News, 1 November 2026: "Shops looted as German cost-of-living protests turn violent"'
#   -> ./data/genesis.json, ./data/keys/authority-{1,2,3}.key, ./data/config.json

# 2. Run a node (serves the API and the web app on :8080).
./bin/eidchain node

# 3. Open http://localhost:8080/ , type a message, sign it with your eID card.
#    (Web eID only works on https:// pages and on localhost.)

# 4. On another machine (or directory): pull the chain, verified.
./bin/eidchain pull --data ./other --genesis-hash <genesis-hash> http://host:8080
./bin/eidchain verify --data ./other
```

The data directory defaults to `./data`; change it with `--data DIR` or the `EIDCHAIN_DATA` environment variable.

### The PoC chain

`genesis/poc-genesis.json` is the genesis of the PoC chain created on 2026-11-01 from the lead BBC News headline. Its hash is

```
1a96878e47753109e410c9a7980397182502a4930cd9f495957da20ae2645a82
```

The genesis file is public. The three authority *private* keys exist only in `data/keys/` on the machine that created it (that directory is git-ignored).

## Concepts

### Genesis block

A JSON document that fixes everything the consensus rules depend on:

| Field | Meaning |
| --- | --- |
| `message` | Free text, e.g. a news headline |
| `created` | Unix time |
| `authorities` | Initial ECDSA P-256 public keys (base64 SPKI) |
| `trustAnchors` | PEM CA certificates (roots and intermediates) accepted for eID signatures |
| `rules.requireNonRepudiation` | Payload signing certificates must have the non-repudiation key usage (keeps *authentication* certificates from signing records) |
| `rules.maxPayloadBytes` | Payload size cap (10240) |
| `rules.rotationQuorum` | Approvals needed to rotate an authority key (default `N/2+1`) |
| `rules.maxRotationsPerBlock` | Cap on control messages per block |

The **genesis hash** (SHA-256 over the canonical JSON) is the chain's identity. Nodes refuse chains with a different genesis hash, which is why `--genesis-hash` is configurable and why `genesis` can start new chains at will.

### Block format

```json
{
  "header": {
    "version": 1,
    "height": 7,
    "prev": "<hash of the parent block>",
    "time": 1793550000,
    "payloadsRoot": "<Merkle root of the payload entries>",
    "payloadCount": 2,
    "rotationsRoot": "<Merkle root of the rotations, or zeros>",
    "rotationCount": 0,
    "signer": "<key ID of the authority that signed this block>"
  },
  "payloads": [
    {
      "payload": "{\"type\":\"message\",\"text\":\"hello\",\"created\":\"2026-11-01T12:00:00.000Z\"}",
      "signature": "<base64 DER of the detached CAdES-B-B signature over the payload string's bytes>",
      "ocsp": "<base64 DER OCSP response obtained at submission, optional>"
    }
  ],
  "rotations": [],
  "signature": "<base64 ASN.1 ECDSA signature over the block hash>"
}
```

- `payload` is a JSON **string** that holds JSON text. Its bytes are kept exactly as signed; nothing re-serialises them.
- The **block hash** is SHA-256 over `"eidchain/block/v1\n"` plus the canonical JSON of `header` (fields in declaration order, compact, no HTML escaping). The authority signs that hash.
- `payloadsRoot` is an RFC 6962 style Merkle tree over leaves that commit to the payload text, the signature and the OCSP response.
- A block must contain at least one payload or rotation.

### Block validation (consensus rules)

A node accepts a block only if all of these hold:

1. It builds on a known parent, height is parent + 1, and `time` is not before the parent's and not more than 5 minutes in the future.
2. The signer is an authority **in the parent's authority state** and did not sign any of the previous `floor(N/2)` blocks. The block signature is valid.
3. `payloadCount`, `rotationCount`, `payloadsRoot` and `rotationsRoot` match the body.
4. Every payload: valid UTF-8, a JSON object, within the size cap; a valid detached CAdES-B-B signature (RSA PKCS#1 v1.5 or ECDSA with SHA-256/384/512; RSA-PSS is not supported); the signer certificate chains to the genesis trust anchors **judged at the block's timestamp**; non-repudiation key usage if the genesis requires it; no duplicate payload inside the block.
5. Every rotation: for this chain, `seq` equals the number of rotations applied so far (no replays), replaces a current authority with a new P-256 key that is not already one, and carries valid approvals from at least `rotationQuorum` distinct keys of the parent's state.

Revocation (OCSP) is deliberately **not** part of these rules, so validation is deterministic and works offline.

### Fork choice

The canonical chain is the highest one; at equal height the lowest block hash wins. When the head changes, payloads and rotations from orphaned blocks go back to the pending pool unless they are on the new chain.

### Key rotation

A rotation replaces authority key `old` with `newKey`. Signing it works like a multi-signature file:

```sh
# Anyone: create the proposal (generates the new key file if it does not exist).
eidchain rotate create --server http://host:8080 --old a2e51a21 --new-key new.key --out rotation.json

# Each approving authority adds its signature to the same file.
eidchain rotate sign --key data/keys/authority-2.key rotation.json
eidchain rotate sign --key data/keys/authority-3.key rotation.json

# Submit it (can also be submitted after each signature; nodes merge approvals).
eidchain rotate submit --server http://host:8080 rotation.json
```

Once the quorum is reached, the next block a node cuts includes the rotation. Put the new key's file into the signing nodes' keys directory so they can use it. A block that carries the rotation may still be signed by the key it retires: the change applies from the *next* block.

### Which eID certificates are accepted

Payload signatures are checked against the CA certificates in the genesis block. They are chosen **when the chain is created**, because every node must apply the same rules; a node cannot change them locally. Choose them with, in order of precedence:

1. `eidchain genesis --trust-ca FILE` (repeatable; `builtin:hr` names the embedded AKD CA bundle),
2. `trustCAs` in `<data>/config.json`,
3. the default `builtin:hr`: AKDCA Root, HRIDCA (cards issued before May 2025) and HRIDCA 2025 (newer AKD eID 2.0 cards). The first two are published at [eid.hr](https://eid.hr/en/certificates/certificates-akdca-root-and-hridca); HRIDCA 2025 at `https://eid.hr/cert/hridca2025.crt` (it is issued by AKDCA Root, which is how it was checked).

To accept cards from another EU country, put that country's qualified-certificate CA certificates (PEM, roots and intermediates) in files and list them:

```json
{
  "trustCAs": ["builtin:hr", "ee-sk-ca.pem", "/etc/eidchain/fi-vrk.pem"]
}
```

Relative paths are relative to the data directory. Then run `eidchain genesis`, which prints the CAs it fixed into the genesis.

A country's cards are "compatible" when: the browser can sign with them through Web eID (which supports a limited set of countries); the signing certificate carries the non-repudiation key usage; the signature algorithm is RSA PKCS#1 v1.5 or ECDSA with SHA-2; and the certificate has an OCSP responder address (required unless you run nodes with `--ocsp skip`). Getting the CA certificates is up to you: take them from the national trusted list or the EU List of Trusted Lists. `eidchain` does not download them.

Changing the CA set of an existing chain is not possible; start a new chain.

## Command line

```
eidchain node     [flags]                 run a node
eidchain pull     [flags] SERVER-URL      download and verify a chain
eidchain genesis  [flags]                 create a new chain
eidchain submit   [flags] PAYLOAD SIG     submit a signed record
eidchain rotate   create|sign|submit      rotate an authority key
eidchain verify   [flags]                 re-verify the local chain from the genesis
eidchain info     [flags] [SERVER-URL]    show a node's status
```

Flags may come before or after positional arguments. `-h` lists a command's flags.

### `node`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--data` | `./data` | Data directory |
| `--listen` | `:8080` | HTTP listen address |
| `--genesis-hash` | from `genesis.json` | Refuse any other chain |
| `--peer URL` | none | Peer to gossip with and pull from (repeatable) |
| `--block-interval` | `10m` | Cut a block on every multiple of this, if something is pending |
| `--sync-interval` | `30s` | How often to pull from peers |
| `--ocsp` | `required` | `required` (fail closed) or `skip` (testing only) |
| `--keys` | `<data>/keys` | Authority private keys (`*.key`, PKCS#8 PEM). A node may hold several, one, or none |
| `--no-web` | off | Do not serve the web app |

A node without keys still serves, validates, gossips and syncs; it just never cuts blocks. If several authority nodes run, give each a different subset of keys, list each other as `--peer`, and note that a single running node holding all keys can produce blocks alone.

### `pull`

```
$ eidchain pull --data ./other --genesis-hash 1a96878e… http://host:8080
Pulling chain 1a96878e4775 from http://host:8080
  "BBC News, 1 November 2026: …"
  Fetching blocks 1-42 of 42
Digest: sha256:51e123afc468…
Status: Downloaded newer chain for http://host:8080 (height 0 -> 42, 120ms)
```

The first pull in a directory needs the genesis hash (flag, `EIDCHAIN_GENESIS_HASH`, or `config.json`); `--trust-first-use` accepts whatever the server offers. Every block is validated locally. Later pulls are incremental and find the fork point if the remote's chain differs. The genesis hash and the server are remembered in `config.json`.

### `genesis`

```
eidchain genesis --message "…" [--authorities 3] [--authority-pubkey FILE|B64 …]
                 [--trust-ca FILE|builtin:hr …] [--rotation-quorum N]
                 [--keys DIR] [--out FILE] [--created RFC3339] [--force]
```

Generates `--authorities` new keys (default 3, or none if you pass existing public keys), writes the genesis and prints its hash. It refuses to replace an existing genesis without `--force`.

### `submit`

`eidchain submit [--server URL] PAYLOAD-FILE SIGNATURE-FILE` sends a record that you signed elsewhere, for example with the `/signer/` page (the signature file may be DER, PEM or Base64 `.p7s`). The payload file's exact bytes are what the signature covers.

## Configuration file

`<data>/config.json` provides defaults; flags win. All fields are optional.

```json
{
  "genesisHash": "1a96878e…",
  "listen": ":8080",
  "peers": ["http://other-node:8080"],
  "blockInterval": "10m",
  "syncInterval": "30s",
  "ocsp": "required",
  "keysDir": "keys",
  "trustCAs": ["builtin:hr"]
}
```

`trustCAs` is only read by `eidchain genesis`; a running chain uses the CAs from its genesis. Relative `keysDir` and `trustCAs` paths are relative to the data directory.

## Data directory

```
data/
  genesis.json       the chain's genesis block
  blocks/<hash>.json every valid block seen, including side branches
  pending.json       payloads waiting for the next block (survives restarts)
  keys/*.key         this node's authority private keys (mode 0600)
  config.json        defaults
```

Everything here is git-ignored. Blocks are re-validated when a node starts; invalid files are skipped with a warning.

## HTTP API

All under `/api/v1`, JSON, CORS open. There is no authentication: every write needs an eID signature (payloads) or authority signatures (rotations, blocks) anyway.

| Method and path | Purpose |
| --- | --- |
| `GET /info` | Status: genesis hash, height, head, authorities, pending counts, next block time, trust anchors |
| `GET /genesis` | The genesis document |
| `GET /hashes/{height}` | Canonical block hash at a height |
| `GET /blocks?from=H&limit=N` | Canonical blocks from height `H` (limit up to 200) |
| `GET /blocks/{hash}` | Any stored block |
| `POST /blocks` | Push a block (gossip); answers `added`, `known`, or `unknown-parent` |
| `POST /payloads` | Submit `{"payload": "...", "signature": "<base64 CAdES>"}`. Checks the signature, the certificate chain and OCSP; 422 on rejection |
| `GET /messages?limit=N` | Pending and recent confirmed records with their signer, for the web app |
| `GET /authorities` | Current authority key IDs, rotation sequence and quorum |
| `GET /rotations`, `POST /rotations` | Pending rotation proposals; submit or add approvals |

## The example web app

`eidchain node` serves it at `/`. It reuses the browser modules of the `/signer/` page: the Web eID client, DER helpers and the CAdES-B-B builder. The page builds `{"type":"message","text":…,"created":…}`, hashes it, asks the card to sign the CAdES signed attributes (PIN2 prompt) and posts the result. It needs the [Web eID](https://web-eid.eu) extension and app, plus the card middleware, and an **HTTPS or localhost** origin.

After changing `www/signer/{webeid-client,der,cades}.js`, run `scripts/sync-webapp.sh` and rebuild, so the embedded copies match.

## Deployment (systemd + nginx)

`deploy/` holds the files for running a node as a service behind nginx, as done for `https://eidchain.ivoras.net/chain/`:

| File | Purpose |
| --- | --- |
| `deploy/eidchain.service` | systemd unit: runs `eidchain node` on `127.0.0.1:8095` as user `ivoras`, with a sandbox (read-only filesystem except `data/`, no home directory, no extra privileges) |
| `deploy/nginx-eidchain.conf` | The site's nginx config, including the `/chain/` reverse proxy to the node. The app uses relative URLs, so it works under a prefix |
| `deploy/install.sh` | Builds the binary, installs the unit and the nginx config, reloads both |

```sh
./bin/eidchain genesis --message "…"   # once, to create the chain in ./data
./deploy/install.sh                     # build, install, (re)start
journalctl -u eidchain -f               # logs
```

The repository copies in `deploy/` are the source of truth; `install.sh` copies them to `/etc/systemd/system/` and `/etc/nginx/sites-available/`. The nginx file also contains the lines certbot manages (certificate paths), so keep it in sync if certbot changes the live file. To change the port, edit it in both the unit and the nginx file.

The node and its API are public: there is no authentication, rate limiting or per-IP control (see [Limitations](#limitations)). OCSP is `required`, so submissions fail unless the signer's OCSP responder answers.

## Development

```sh
go vet ./...
go test -race ./...
```

The tests cover CAdES verification (including signatures produced by the browser-side JavaScript signer), the consensus rules, forks and reorgs, key rotation (quorum, replay, retired keys), reopening and re-verifying a stored chain, and a multi-node run over real HTTP with gossip, pull, rotation and the embedded web app.

```
cmd/eidchain/        CLI
deploy/              systemd unit, nginx config, install script
internal/chain/      data model, hashing, CAdES verification, validation, store, fork choice
internal/node/       HTTP API, pools, block production, gossip, sync loop
internal/remote/     node API client and chain synchronisation (used by pull and by nodes)
internal/webapp/     embedded example web app
internal/hrca/       embedded AKDCA Root, HRIDCA and HRIDCA 2025 certificates
internal/config/     config.json
internal/testpki/    test-only CA and CAdES builder
genesis/             public genesis files
www/                 the eidchain.ivoras.net website, including /signer/
scripts/             helper scripts
```

## Limitations

- **Not tested with a real eID card, real OCSP responder or a real HRIDCA-issued certificate.** The CAdES verifier is tested against signatures from the browser-side signer, and the CA chain code against a test hierarchy, but the full path with a live Croatian card has not been run. Expect to adjust something (for example certificate extensions that Go's X.509 verifier treats strictly).
- **Time is whatever the signer's clock says.** There are no trusted timestamps; block times are checked only against the parent and a 5-minute future bound.
- **No finality.** A longer chain can replace a shorter one at any depth (bounded in practice by the recent-signer rule).
- **Duplicate records:** the same signed payload is rejected inside a block and in the pending pool, and when already on the canonical chain at submission, but this is not a consensus rule.
- **OCSP is only checked at submission** by the first node. Other nodes verify the stored response offline and do not re-query.
- **Trust anchors are fixed by the genesis.** Changing them means a new chain.
- **Only replacement rotations.** The authority count stays constant; adding or removing authorities is not implemented.
- **Peers are static.** There is no peer discovery; list peers with `--peer`.
- **Whole chain in memory.** Fine for a PoC.
- **No access control or rate limiting** on the API; the pending pool is capped at 5000 payloads.

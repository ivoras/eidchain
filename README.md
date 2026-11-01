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
- **Block production every 10 minutes.** If any payloads are waiting, an authority node cuts a block on every 10-minute wall-clock boundary, regardless of how few payloads there are. A block holds at most 8 MiB; anything beyond that waits for the next one.
- **Features by height.** Changes to the block format and rules can start at a chosen height, set in `config.json`, so a running chain can gain them without a new genesis.
- **Timestamped blocks.** With the `block-timestamps` feature, every block carries an RFC 3161 timestamp from Sectigo, or FreeTSA if Sectigo fails, and the block hash covers it.
- **Example web app and explorer.** Anyone can type a message, sign it with their eID card in the browser, and add it to the next block. No accounts. A built-in explorer shows blocks, messages (with the signer's certificate and OCSP result), authority keys and rotations, with search, behind a shared nav bar.
- **Strict JSON.** Duplicate keys and case-variant field names are refused everywhere, so a document cannot be read two ways.
- **PII-free logs.** Success paths never log signer names, certificate serials or client addresses; error handlers do, because that is what debugging needs.
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
    "version": 2,
    "height": 7,
    "prev": "<hash of the parent block>",
    "time": 1793550000,
    "payloadsRoot": "<Merkle root of the payload entries>",
    "payloadCount": 2,
    "rotationsRoot": "<Merkle root of the rotations, or zeros>",
    "rotationCount": 0,
    "signer": "<key ID of the authority that signed this block>",
    "timestampHash": "<SHA-256 of the timestamp token; version 2 only>"
  },
  "payloads": [
    {
      "payload": "{\"type\":\"message\",\"chain\":\"<genesis hash>\",\"text\":\"hello\",\"created\":\"2026-11-01T12:00:00.000Z\"}",
      "signature": "<base64 DER of the detached CAdES-B-B signature over the payload string's bytes>",
      "ocsp": "<base64 DER OCSP response obtained at submission, optional>"
    }
  ],
  "rotations": [],
  "timestamp": "<base64 RFC 3161 token over the content hash; version 2 only>",
  "signature": "<base64 ASN.1 ECDSA signature over the block hash>"
}
```

- `payload` is a JSON **string** that holds JSON text. Its bytes are kept exactly as signed; nothing re-serialises them.
- The **block hash** is SHA-256 over `"eidchain/block/v1\n"` plus the canonical JSON of `header` (fields in declaration order, compact, no HTML escaping). The authority signs that hash.
- `payloadsRoot` is an RFC 6962 style Merkle tree over leaves that commit to the payload text, the signature and the OCSP response.
- A block must contain at least one payload or rotation.

### Genesis block and block chaining

**The genesis is not a block.** It is a separate document (see the table above) with no `prev`, no `height`, no signer and no signature. It is trusted for one reason only: you give a node its hash (`--genesis-hash`, `EIDCHAIN_GENESIS_HASH` or `config.json`), and the node refuses any chain whose genesis hashes differently. It hashes as SHA-256 over `"eidchain/genesis/v1\n"` plus its canonical JSON. In the code it plays the part of a block at height 0 whose hash is the genesis hash.

**Block 1 points back at it.** Its `header.prev` is the genesis hash. On the PoC chain:

```
genesis                      block 1                              block 2
hash  G ◄────────────────── prev  = G                            prev  = H1
(no prev, no signature)      hash  H1 = SHA-256(header 1) ◄──────  hash  H2 = SHA-256(header 2)
                             payloadsRoot ── Merkle ── payload entries
                             signature = ECDSA(authority key, H1)
```

Each later block's `prev` is the hash of its parent. A block's hash covers its **header only**, but the header commits to everything else: `payloadsRoot` and `rotationsRoot` are Merkle roots over the body, and `signer` and `height` and `time` are in the header. So changing any message in an old block changes that block's Merkle root, hence its header, hence its hash, which no longer matches the `prev` of its child, and the whole chain after it breaks. Rewriting history needs a new valid signature on every block from that point on.

**Why storing the signature inside the block is not circular.** The `signature` field and the `payloads` array are outside the hash. The authority signs the hash, and anyone verifies by recomputing the hash from the header and checking `ECDSA(publicKey, hash, signature)`. The public key is the one the *parent's* authority state lists for `header.signer`, which is how rotations stay verifiable. ECDSA signatures are randomised, so one header could carry several valid signatures from the same key; the block hash is the same for all of them, so nodes treat them as one block.

**The hash comes from the parsed header, not from the bytes received.** The header is re-encoded canonically (fixed field order, compact, no HTML escaping) before hashing, so JSON key order, whitespace and string escapes in a file or request do not matter and cannot forge anything. To rule out documents that different JSON parsers might read differently, every JSON input is decoded strictly: duplicate object keys, field names that match only case-insensitively (`"HEIGHT"`), unknown fields and trailing data are all refused (`chain.StrictUnmarshal`, used for the genesis file, stored blocks, API request bodies, blocks fetched from peers and rotation files). Block files on disk are written by the node from the parsed block, so they are always in canonical form.

**Forks.** Two blocks can have the same parent. Both are stored; the canonical chain is the highest one, ties broken by the lowest hash (see [Fork choice](#fork-choice)). `eidchain verify` replays the canonical chain from the genesis: for each block it recomputes the hash and Merkle roots, checks the link to its parent, applies the signer rules to the parent's authority state, and verifies every message.

### Block validation (consensus rules)

A node accepts a block only if all of these hold:

0. The JSON it arrived in is unambiguous (no duplicate keys, exact-case field names, no unknown fields).
1. The `version` is the one the [feature schedule](#features) requires at this height, it builds on a known parent, height is parent + 1, and `time` is not before the parent's and not more than 5 minutes in the future.
2. The signer is an authority **in the parent's authority state** and did not sign any of the previous `floor(N/2)` blocks. The block signature is valid.
3. `payloadCount`, `rotationCount`, `payloadsRoot` and `rotationsRoot` match the body, and the block's JSON is at most 8 MiB. From the `block-timestamps` height, it carries a valid [timestamp](#block-timestamps).
4. Every payload: valid UTF-8, a JSON object with no duplicate or case-variant keys at any level, within the size cap; a valid detached CAdES-B-B signature (RSA PKCS#1 v1.5 or ECDSA with SHA-256/384/512; RSA-PSS is not supported); the signer certificate chains to the genesis trust anchors **judged at the block's timestamp**; non-repudiation key usage if the genesis requires it; no payload that already appears in the block or in its ancestors.
5. Every rotation: for this chain, `seq` equals the number of rotations applied so far (no replays), replaces a current authority with a new P-256 key that is not already one, and carries valid approvals from at least `rotationQuorum` distinct keys of the parent's state.

Revocation (OCSP) is deliberately **not** part of these rules, so validation is deterministic and works offline.

### Fork choice

The canonical chain is the highest one; at equal height the lowest block hash wins. When the head changes, payloads and rotations from orphaned blocks go back to the pending pool unless they are on the new chain.

Height costs nothing in proof of authority, so a running node also refuses to reorganise past two limits: it will not replace more than 64 blocks (`MaxReorgDepth`), and it will not undo a key rotation with 6 or more blocks after it (`RotationFinality`). The second limit is what makes a rotation final: until then, a quorum of the old keys could still fork from before it. These limits are local judgement rather than consensus rules. A node that was partitioned for longer than this refuses the other side's chain and logs `reorganisation refused`; repair it by pulling into a fresh directory. A node syncing from nothing has no chain to protect, so check the head against a source you trust.

### Features

A feature is a change to the block format or the consensus rules that starts at a chosen height. Blocks below that height keep the rules they were made under, and every feature raises the block `version`, so a block says which format it is in. Features are switched on in `config.json`:

```json
{ "features": { "block-timestamps": 4 } }
```

| Feature | Block version | What it requires |
| --- | --- | --- |
| `block-timestamps` | 2 | A timestamp in every block, covered by the block hash |

An unknown feature name, or height 0, stops the node with an error: a node must not ignore a rule it was told to enforce.

**This setting is a consensus rule, and it is not in the genesis, so nothing protects it but agreement.** Every node of a chain needs the same value. Set a height above the current head, and change every node before the chain reaches it. Nodes compare schedules through `/api/v1/info`: they refuse to sync from a peer with a different one and name the difference, and will not learn such a peer. If a height is lowered below blocks that do not comply, those blocks are skipped on startup and `eidchain verify` fails. `eidchain pull` copies the server's schedule when `config.json` has none.

To add a feature, name it with its block version in `internal/chain/features.go`, then branch on `Schedule.Active` wherever the rules or the format differ.

### Block timestamps

A block's `time` comes from its signer's clock, so it proves nothing by itself. A timestamp does: an outside authority signs a hash of the block and the time it saw it, which proves the block, and through its Merkle roots every message in it, existed by then. It sets a latest possible time for a message, not the moment it was signed, and a producer could still stamp a block and publish it later.

A token cannot cover a hash that depends on it, so these blocks have two hashes:

1. The producer builds the block and computes the **content hash**: SHA-256 over `"eidchain/block-content/v1\n"` plus the canonical header without `timestampHash`. It covers `prev`, the Merkle roots, the time and the signer, so a block cannot be stamped before its parent exists.
2. It sends only that hash to an authority: Sectigo, then FreeTSA if Sectigo fails. Neither sees messages or names.
3. It stores the token in the block's `timestamp` field and its SHA-256 in `header.timestampHash`.
4. The block hash covers the whole header, so changing the token changes the block hash. The authority key signs that.

From the feature's height a block is valid only if it has a token that verifies for its content hash, whose hash matches the header, and whose time is within 5 minutes of the block's `time`. Below that height a block must not have one. The token's certificate chain is judged at the token's own time, so the verdict does not change later. Revocation of the authority's certificate is not checked.

**Timestamps are required, so availability depends on the authorities.** If neither answers, no block is made: messages stay pending, and the node tries again at the next block boundary. The chain resumes when either service returns.

The roots of both services are pinned in `internal/tsa/roots/`. They are part of the consensus rules, so changing them means a new feature. Neither service issues qualified eIDAS timestamps, so these have no special legal standing, and both are free public services with no service guarantee. Verifying a block needs no network access. `openssl ts -verify` accepts FreeTSA's tokens, but OpenSSL 3.0.13 refuses Sectigo's with `ess cert id not found`, even though the first ESS entry names the signer and `eidchain verify` accepts them.

### Key rotation

A rotation replaces authority key `old` with `newKey`. Signing it works like a multi-signature file:

```sh
# Anyone: create the proposal (generates the new key file if it does not exist).
eidchain rotate create --server http://host:8080 --old a2e51a21 --new-key new.key --out rotation.json

# Each approving authority adds its signature to the same file.
eidchain rotate sign --key data/keys/authority-2.key rotation.json
eidchain rotate sign --key data/keys/authority-3.key rotation.json

# Submit it (can also be submitted after each signature; nodes merge approvals,
# but a proposal with no approvals at all is refused).
eidchain rotate submit --server http://host:8080 rotation.json
```

`rotate sign` shows the change and asks before signing, because the new key's holder becomes an authority: compare the new key's ID with its owner over a channel you trust. `--yes` skips the question for scripts.

Once the quorum is reached, the next block a node cuts includes the rotation. Put the new key's file into the signing nodes' keys directory so they can use it. A block that carries the rotation may still be signed by the key it retires: the change applies from the *next* block.

### Which eID certificates are accepted

Payload signatures are checked against the CA certificates in the genesis block. List every issuing CA as well as the root: intermediates embedded in a signature are ignored, so a certificate from a CA the genesis does not name is refused even if it is under a trusted root. They are chosen **when the chain is created**, because every node must apply the same rules; a node cannot change them locally. Choose them with, in order of precedence:

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
eidchain cert     [flags] CERT-FILE       inspect an eID certificate and check it against the chain's CAs
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
| `--advertise URL` | none | This node's public base URL (for example `https://host/chain`). Announced to peers so they gossip with it too |
| `--no-peer-exchange` | off | Use only the peers given with `--peer` |
| `--peers-allow-private` | off | Allow learned peers on private or loopback addresses (closed networks, testing) |

A node without keys still serves, validates, gossips and syncs; it just never cuts blocks. If several authority nodes run, give each a different subset of keys, make sure they can reach each other (list each other as `--peer`, or let [peer exchange](#peers-and-peer-exchange) connect them), and note that a single running node holding all keys can produce blocks alone.

### Peers and peer exchange

A node gossips with, and pulls from, its **peers**: the ones you name (`--peer`, or `peers` in `config.json`) and the ones it learns. Links are one-way by default: if A lists B, A pushes to and pulls from B, but B does nothing towards A. Peer exchange closes that gap in two small steps, run after every successful sync with a peer:

1. **Announce.** If the node has a public address (`--advertise https://host/chain`), it tells the peer (`POST /api/v1/peers`). The peer adds it, and from then on pushes to it and pulls from it.
2. **Learn.** The node asks the peer which peers it knows (`GET /api/v1/peers`: the peer itself, its public configured peers and its healthy learned ones) and adds the new ones.

So given only A→B and B→C, all three end up knowing each other and gossip flows between every pair (tested). Learned peers are kept in `<data>/peers.json`.

Because a node connects to addresses other nodes give it, learned peers are treated with care:

- **Verified before use.** The node fetches the candidate's `/api/v1/info` and requires the same genesis hash; a node on another chain, an unreachable address or a non-node is never added.
- **Public addresses only.** Loopback, private, link-local and carrier-grade-NAT addresses, `localhost` and `*.local` names are refused, and the check is made on the connection itself, so a host name that resolves to a private address is refused too. No redirects are followed and no proxy is used. Peers *you* configure are exempt (a private LAN is fine); `--peers-allow-private` lifts the rule for learned peers on closed networks.
- **Bounded.** At most 32 learned peers, and 2 per host name; peers sync independently, so a slow one delays nobody else; 20 announcements accepted per minute in total; a candidate that fails verification is not retried for 10 minutes; a learned peer that fails 6 syncs in a row is dropped; a peer list is capped at 20 addresses.
- **Strict input.** The announcement body gets the same strict JSON rules as every other request.
- **Not a trust decision.** A learned peer is only somewhere to push to and pull from. Everything it sends is fully validated like data from any peer.

A node behind NAT can still pull from and push to public nodes; it just can't be reached by them, so it leaves `--advertise` unset. `--no-peer-exchange` turns the whole thing off, and `GET`/`POST /api/v1/peers` then answer 404.

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

#### Pull a chain and run a node from it

The whole workflow, as tested against the live PoC chain:

```sh
# 1. Pull. The genesis hash is the chain's identity: get it from whoever runs the chain.
eidchain pull --data ./mychain \
    --genesis-hash 1a96878e47753109e410c9a7980397182502a4930cd9f495957da20ae2645a82 \
    https://eidchain.ivoras.net/chain

# 2. Optional: re-verify everything from the genesis, offline.
eidchain verify --data ./mychain

# 3. Run a node on it.
eidchain node --data ./mychain --listen :8080
```

- **Getting the hash.** Take it from a source you trust, not from the server you are pulling from: the server can only tell you what its own genesis hashes to. (`eidchain info URL` and the explorer's *node* page show it, which is handy for checking against what you were told.) `--trust-first-use` skips the check and says so loudly.
- **What the pull verifies.** The genesis must hash to the value you gave. Every block is then fully validated before it is stored: the authority signature, the Merkle roots, the link to its parent, the signer rules, every message's CAdES signature and certificate chain, and key rotations. A tampering or buggy server is refused (`block 1 from … rejected: block signature is invalid`) and the bad block is not stored. A pull that fails never leaves invalid data behind: if the server cannot be reached or the genesis does not match, no directory is created; if it fails later, the directory holds the verified genesis and the verified blocks fetched so far, and running the pull again continues from there.
- **Incremental.** A second `pull` into the same directory asks the server for its head, finds the last block both sides share (also when your copy had forked away) and fetches only what follows. If you already have the server's head it says `Chain is up to date`. A pull never moves your chain backwards.
- **One chain per directory.** Pulling a server with a different genesis into a directory that already holds a chain is refused.
- **Remembered settings.** `<data>/config.json` records the genesis hash and the server you pulled from as a peer, so later commands need no flags.
- **Running the node.** A node started on the directory is a *follower*: it serves the API, the web app and the explorer, re-verifies what it holds, accepts submitted messages and gossips them, and syncs from its peers (the server you pulled from, unless you add `--peer`) every `--sync-interval`, so it stays current by itself. It does not cut blocks, because it holds no authority key (`0 local signing key(s)` in its log; `canProduce: false` in `/api/v1/info`). A node refuses to start on a directory whose genesis does not match `--genesis-hash`.
- **Passing it on.** A follower serves the chain like any node, so others can `pull` from it.
- **Don't pull into a running node's directory.** The node keeps the chain in memory and would not notice blocks that `pull` wrote behind its back until it restarts, and it does not need them: it syncs by itself.
- **Becoming an authority.** Only a key that is in the chain's authority set (the genesis keys, as changed by rotations) can sign blocks. If you hold one, put its `*.key` file in `<data>/keys/` and restart the node. Otherwise an existing authority has to rotate you in; see [Key rotation](#key-rotation).
- **Behind nginx or on a sub-path.** The URL may include a path: `https://host/chain` works.

### `genesis`

```
eidchain genesis --message "…" [--authorities 3] [--authority-pubkey FILE|B64 …]
                 [--trust-ca FILE|builtin:hr …] [--rotation-quorum N]
                 [--keys DIR] [--out FILE] [--created RFC3339] [--force]
```

Generates `--authorities` new keys (default 3, or none if you pass existing public keys), writes the genesis and prints its hash. It refuses to replace an existing genesis without `--force`.

### `submit`

Commands that talk to a node use `--server URL`, else the first peer in `config.json`, else `localhost` on the port of `listen` in `config.json`, else `localhost:8080`.

`eidchain submit [--server URL] PAYLOAD-FILE SIGNATURE-FILE` sends a record that you signed elsewhere, for example with the `/signer/` page (the signature file may be DER, PEM or Base64 `.p7s`). The payload file's exact bytes are what the signature covers, and the record must be a JSON object with a `chain` field holding the chain's genesis hash. Nodes refuse submissions without it, so a signature cannot be replayed from another chain, and a signed document that was not written for this chain cannot be published on it.

### `cert`

`eidchain cert [--data DIR] CERT-FILE` prints a certificate (PEM or DER; the `/signer/` page's `.signer.pem` download works) and says whether the chain in the data directory would accept it for payload signatures. If not, it names the CA that is missing and where its certificate is published. This is how the newer cards' CA (HRIDCA 2025) was found.

## Configuration file

`<data>/config.json` provides defaults; flags win. All fields are optional, and an unknown field is an error, so a misspelt setting cannot be silently ignored.

```json
{
  "genesisHash": "1a96878e…",
  "listen": ":8080",
  "peers": ["http://other-node:8080"],
  "blockInterval": "10m",
  "syncInterval": "30s",
  "ocsp": "required",
  "keysDir": "keys",
  "advertise": "https://my-node.example/chain",
  "peerExchange": true,
  "features": { "block-timestamps": 4 },
  "trustCAs": ["builtin:hr"]
}
```

`trustCAs` is only read by `eidchain genesis`; a running chain uses the CAs from its genesis. Relative `keysDir` and `trustCAs` paths are relative to the data directory.

## Data directory

```
data/
  genesis.json       the chain's genesis block
  blocks/<hash>.json every valid block seen, including side branches
  pending.jsonl      payloads waiting for the next block (survives restarts)
  peers.json         peers learned through peer exchange
  keys/*.key         this node's authority private keys (mode 0600)
  config.json        defaults
```

Everything here is git-ignored. Blocks are re-validated when a node starts; invalid files are skipped with a warning, and `eidchain verify` fails if there are any. `verify` cannot notice blocks missing from the tip of the chain, because nothing local records how long it was: `eidchain pull` from another node catches that.

## HTTP API

All under `/api/v1`, JSON, CORS open. There is no authentication: every write needs an eID signature (payloads) or authority signatures (rotations, blocks) anyway.

| Method and path | Purpose |
| --- | --- |
| `GET /info` | Status: genesis hash, height, head, authorities, pending counts, next block time, trust anchors, feature schedule |
| `GET /genesis` | The genesis document |
| `GET /hashes/{height}` | Canonical block hash at a height |
| `GET /blocks?from=H&limit=N` | Canonical blocks from height `H` (limit up to 200; may return fewer, up to about 32 MiB) |
| `GET /blocks/{hash}` | Any stored block |
| `POST /blocks` | Push a block (gossip); answers `added`, `known`, or `unknown-parent` |
| `POST /payloads` | Submit `{"payload": "...", "signature": "<base64 CAdES>"}`. Checks the signature, the certificate chain, the payload's `chain` field and OCSP; 422 on rejection, 503 if the OCSP responder is unreachable or the pool is full (safe to retry) |
| `POST /check-cert` | Whether `{"certificate": "<base64 DER>"}` could sign here, so the web app can say so before the PIN |
| `GET /messages?limit=N` | Pending and recent confirmed records with their signer, for the web app (at most `N`, pending first) |
| `GET /authorities` | Current authority key IDs, rotation sequence and quorum |
| `GET /peers`, `POST /peers` | The peers this node shares (itself, public and healthy ones); announce a node's own address (`{"url": "..."}`), which is verified before it is added |
| `GET /rotations`, `POST /rotations` | Pending rotation proposals; submit or add approvals |
| `GET /explorer/blocks?before=H&limit=N` | Block summaries, newest first, with a cursor for older pages |
| `GET /explorer/block/{height or hash}` | A block with its messages, rotations, neighbours and confirmations |
| `GET /explorer/tx/{id}` | A message (its id is a hash of the payload and the signer's certificate): payload, signer certificate, CAdES and OCSP details, and where it is (or that it is pending) |
| `GET /explorer/authorities` | Current keys, rotation history, pending proposals and which keys this node holds |
| `GET /explorer/messages?before=H` | Messages from 20 blocks, newest first, with a cursor for older pages |
| `GET /explorer/pending?offset=N` | Pending messages, oldest first, 50 at a time, with the total and the next offset |
| `GET /explorer/search?q=` | Resolves a height, or a block hash, message id or authority key id, also in the shortened form the pages show |

## The example web app and explorer

`eidchain node` serves both at `/` (embedded in the binary):

- **Post a message** (`index.html`): type a message, sign it with your card, submit it. The page reuses the browser modules of the `/signer/` page (Web eID client, DER helpers, CAdES-B-B builder), builds `{"type":"message","chain":…,"text":…,"created":…}`, hashes it, asks the card to sign the CAdES signed attributes (PIN2 prompt) and posts the result. It needs the [Web eID](https://web-eid.eu) extension and app, plus the card middleware, and an **HTTPS or localhost** origin.
- **Explorer** (`explorer.html`, hash-routed): `#/blocks` (latest blocks, paged), `#/block/<height or hash>`, `#/messages`, `#/pending` (messages waiting for a block, oldest first, paged, linked from the blocks page), `#/tx/<message id>` (the message, the signer's certificate, the CAdES details and the stored OCSP result, and the payload verbatim), `#/authorities` (current keys, rotation history, proposals), `#/node` (genesis hash, trusted CAs, block timing) and a search box in the nav bar that takes a height, block hash, message id or authority key id. Times come from a block's timestamp if it has one, otherwise from `header.time`, and the block page says which. Lists show only the signer's common name; the detail page shows the certificate's subject fields except `serialNumber`, the personal ID number. That only limits what the API displays: the certificate itself is in the CAdES signature in every block, so the number stays readable from the raw block, and nothing written to the chain can be erased. The web app tells users this before they sign.
- **Nav bar and ticker** (`nav.js`): one small module builds the bar for both the website and the app, highlights the current page, and shows the chain's genesis message as a scrolling ticker.

The look (`site.css`) is shared by the whole website and the app: a pale periwinkle canvas, near-black type, lime and electric-blue accents, pill buttons, uppercase mono labels, automatic dark mode and a reduced-motion setting. It uses system fonts only and no images, so the pages run under a strict CSP with no inline scripts or styles (sent by the node for the app, and by `deploy/nginx-eidchain.conf` for the website).

The shared files live in `www/` (`site.css`, `nav.js`, `signer/{webeid-client,der,cades}.js`) and are copied into the app by `scripts/sync-webapp.sh`; run it after changing them and rebuild, so the embedded copies match. A test checks that every asset the embedded pages reference is in the binary.

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

The node and its API are public, with no authentication. The nginx config limits each client to 30 POSTs a minute (burst 30), caps request bodies at 300 KiB (9 MiB for pushed blocks), and sends HSTS and a CSP. The node has no limits of its own, so do not expose its port directly. OCSP is `required`, so submissions wait until the signer's OCSP responder answers; if it is down the web app keeps the signature and retries without another PIN.

## Development

```sh
go vet ./...
go test -race ./...
```

The tests cover pulling (including finding the fork point of a diverged chain and never moving backwards), CAdES verification (including signatures produced by the browser-side JavaScript signer), the consensus rules, forks and reorgs, key rotation (quorum, replay, retired keys), reopening and re-verifying a stored chain, peer exchange (discovery, verification, address safety, limits), features by height, timestamped blocks (including real Sectigo and FreeTSA tokens, and authority outages) and a multi-node run over real HTTP with gossip, pull, rotation and the embedded web app.

```
cmd/eidchain/        CLI
deploy/              systemd unit, nginx config, install script
internal/chain/      data model, hashing, CAdES verification, validation, store, fork choice
internal/node/       HTTP API, pools, block production, gossip, peer exchange, sync loop
internal/remote/     node API client and chain synchronisation (used by pull and by nodes)
internal/tsa/        RFC 3161 client and verifier, embedded authority roots
internal/webapp/     embedded example web app and explorer (HTML, JS, CSS)
internal/hrca/       embedded AKDCA Root, HRIDCA and HRIDCA 2025 certificates
internal/config/     config.json
internal/testpki/    test-only CA and CAdES builder
genesis/             public genesis files
www/                 the eidchain.ivoras.net website, including /signer/, and the shared site.css and nav.js
scripts/             helper scripts
```

### Keeping private keys out of git

Authority private keys (`data/keys/*.key`) and all chain data live in `data/`, which is git-ignored. Three layers stop a key from being published by accident:

1. **`.gitignore`** excludes `data/`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.pk8`, `id_*` and `.env`.
2. **`.githooks/pre-commit`** refuses a commit that adds a PEM/PGP private key block, a key-like file name, or anything under `data/` (even with `git add -f`).
3. **`.githooks/pre-push`** re-checks every commit about to be pushed, so a leak committed with `--no-verify` or buried in history is still caught.

Both hooks run `scripts/check-no-private-keys.sh`, which you can also run by hand (`--all` scans the whole history). Hooks are not copied by `git clone`, so enable them once per clone:

```sh
git config core.hooksPath .githooks
```

If a key ever does get pushed, treat it as compromised: rotate it (see [Key rotation](#key-rotation)) rather than just deleting the commit. The rotation protects running nodes only once 6 blocks follow it, so cut those blocks promptly.

## Limitations

- **Personal data is permanent.** Every signature embeds the signer's certificate, with their name and, on Croatian cards, their OIB. Blocks are public and immutable, which sits badly with GDPR erasure rights. Get legal advice before running this with real users; storing certificates off-chain would need a new block format.
- **Not tested with a real eID card, real OCSP responder or a real HRIDCA-issued certificate.** The CAdES verifier is tested against signatures from the browser-side signer, and the CA chain code against a test hierarchy, but the full path with a live Croatian card has not been run. Expect to adjust something (for example certificate extensions that Go's X.509 verifier treats strictly).
- **Block `time` is whatever the signer's clock says.** It is checked only against the parent and a 5-minute future bound. From the `block-timestamps` height, [a timestamp](#block-timestamps) must be within 5 minutes of it, but fork choice does not use timestamps.
- **Weak finality.** Running nodes limit reorganisations (see [Fork choice](#fork-choice)), but nothing proves to a new node which of two branches came first, and blocks have no minimum spacing.
- **Key separation is up to you.** The majority rule means nothing if one machine holds a majority of the keys, as the PoC deployment does.
- **The `chain` field is checked at submission, not in blocks,** like OCSP: an authority that bypasses the API can still include a record without it.
- **OCSP is only checked at submission** by the first node. Other nodes verify the stored response offline and do not re-query.
- **Trust anchors are fixed by the genesis.** Changing them means a new chain.
- **Only replacement rotations.** The authority count stays constant; adding or removing authorities is not implemented.
- **Peer discovery is minimal.** Nodes learn peers from the ones they already have (see [Peers and peer exchange](#peers-and-peer-exchange)), but there is no bootstrap list or DNS discovery: a new node needs at least one peer address to start from.
- **Whole chain in memory.** Fine for a PoC.
- **No access control, and rate limiting only in nginx.** The pending pool is capped at 5000 payloads, but one card can fill it.

## License

eidchain is free software, licensed under the **GNU General Public License, version 3** (see [`LICENSE`](LICENSE)). It uses `golang.org/x/crypto` (BSD 3-clause), which is compatible. The embedded Croatian eID CA certificates are public documents published by the issuing authority (AKD).

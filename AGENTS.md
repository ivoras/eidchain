# Agent guidelines

## Clarity

- Why is more important than how. If unclear, interview the user. When writing documentation and comments, put emphasys on whys and the bare functional minimum in hows.

## Compatibility

- Unless the user explicitly asks for it, backwards compatibility does not matter. Breaking changes are fine, including to the block format, consensus rules, APIs, the CLI and on-disk data. No migrations or compatibility shims are needed.
- The PoC blockchain is not important and can be purged. Do not limit a design to keep its existing blocks valid, or preserve its genesis.

## Git

- Never create a new branch unless explicitly asked to. Work on the current branch, including when it is `main`.

## Keeping private keys out of git

Authority private keys (`data/keys/*.key`) and all chain data live in `data/`, which is git-ignored. Three layers stop a key from being published by accident:

1. **`.gitignore`** excludes `data/`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*.pk8`, `id_*` and `.env`.
2. **`.githooks/pre-commit`** refuses a commit that adds a PEM/PGP private key block, a key-like file name, or anything under `data/` (even with `git add -f`).
3. **`.githooks/pre-push`** re-checks every commit about to be pushed, so a leak committed with `--no-verify` or buried in history is still caught.

Both hooks run `scripts/check-no-private-keys.sh`, which you can also run by hand (`--all` scans the whole history). Hooks are not copied by `git clone`, so enable them once per clone:

```sh
git config core.hooksPath .githooks
```

If a key ever does get pushed, treat it as compromised: rotate it (see [Key rotation](README.md#key-rotation)) rather than just deleting the commit. The rotation protects running nodes only once 6 blocks follow it, so cut those blocks promptly.

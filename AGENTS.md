# Agent guidelines

## Clarity

- Why is more important than how. If unclear, interview the user. When writing documentation and comments, put emphasys on whys and the bare functional minimum in hows.

## Compatibility

- Unless the user explicitly asks for it, backwards compatibility does not matter. Breaking changes are fine, including to the block format, consensus rules, APIs, the CLI and on-disk data. No migrations or compatibility shims are needed.
- The PoC blockchain is not important and can be purged. Do not limit a design to keep its existing blocks valid, or preserve its genesis.

## Git

- Never create a new branch unless explicitly asked to. Work on the current branch, including when it is `main`.

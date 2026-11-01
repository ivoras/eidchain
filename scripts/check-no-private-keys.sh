#!/bin/sh
# Refuse to let private keys into git, by file name and by content.
#
#   check-no-private-keys.sh            tracked files in the working tree
#   check-no-private-keys.sh --staged   what is about to be committed
#   check-no-private-keys.sh --range R  every commit in a git range (e.g. origin/main..HEAD)
#   check-no-private-keys.sh --all      the whole history of every ref
#
# Used by .githooks/pre-commit and .githooks/pre-push. Exit status 1 = a key was found.
set -eu
cd "$(git rev-parse --show-toplevel)"

# A PEM/PGP private key block header. (The regex does not match its own source:
# the character class cannot match the "[" that follows "BEGIN " here.)
CONTENT='-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----'
# Files that hold private keys, whatever they contain. Chain data (keys, blocks,
# pending payloads, config) lives in data/ and must never be tracked.
NAMES='(^|/)(id_(rsa|dsa|ecdsa|ed25519)(\.pem)?|[^/]*\.(key|p12|pfx|jks|pk8|keystore))$|^data/.+'
NAMES_OK='^data/\.gitignore$'

bad=0
report() { echo "REFUSED: $1" >&2; bad=1; }

# check_names takes a newline-separated list of paths as $1. The loop reads a
# here-document rather than a pipe, so it runs in this shell and "bad" is kept.
check_names() {
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    if printf '%s\n' "$p" | grep -Eq "$NAMES" && ! printf '%s\n' "$p" | grep -Eq "$NAMES_OK"; then
      report "$p looks like a private key or chain data file"
    fi
  done <<PATHS
$1
PATHS
}

mode="${1:-tree}"
case "$mode" in
  --staged)
    check_names "$(git diff --cached --name-only --diff-filter=ACMR)"
    if git diff --cached -U0 --no-color | grep -Eq "^\+.*$CONTENT"; then
      report "staged changes contain a private key block"
    fi ;;
  --range)
    range="${2:?usage: --range <git range>}"
    check_names "$(git log --name-only --format= --diff-filter=ACMR "$range" | sort -u)"
    hits="$(git log --format=%h -G"$CONTENT" "$range")"
    if [ -n "$hits" ]; then
      report "commits in $range contain a private key block: $(echo "$hits" | tr '\n' ' ')"
    fi ;;
  --all)
    check_names "$(git log --all --name-only --format= --diff-filter=ACMR | sort -u)"
    hits="$(git log --all --format=%h -G"$CONTENT")"
    if [ -n "$hits" ]; then
      report "history contains a private key block: $(echo "$hits" | tr '\n' ' ')"
    fi ;;
  *)
    check_names "$(git ls-files)"
    if git grep -I -q -E "$CONTENT" -- . 2>/dev/null; then
      report "tracked files contain a private key block: $(git grep -I -l -E "$CONTENT" -- . | tr '\n' ' ')"
    fi ;;
esac

if [ "$bad" -ne 0 ]; then
  echo "Private keys must never be committed. Remove them from the commit (and rotate the key if it was ever pushed)." >&2
  exit 1
fi

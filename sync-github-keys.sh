#!/usr/bin/env bash
#
# Mirrors GitHub's Actions OIDC signing keys into a deployed GithubOidcVerifier.
#
# GitHub rotates the keys that sign OIDC tokens. The verifier only accepts a token signed by a key
# it already knows, so registration silently starts failing whenever a rotation lands and nobody has
# mirrored the new key. This is the job that keeps the two in step.
#
# Adds every RSA key in the published JWKS that the contract does not already hold, and optionally
# revokes keys the contract still trusts that GitHub has since dropped.
#
# Required:
#   VERIFIER_ADDRESS   deployed GithubOidcVerifier
#   RPC_URL            JSON-RPC endpoint
#   PRIVATE_KEY        verifier owner key; not needed when DRY_RUN=true
#
# Optional:
#   DRY_RUN            report the plan without sending anything (default false)
#   REVOKE_STALE       revoke keys GitHub no longer publishes (default true)
#   FROM_BLOCK         first block to scan for KeyAdded when reconciling (default 0)
#   MIN_KEYS           refuse to act on a JWKS smaller than this (default 2)
#   ISSUER             OIDC issuer (default the GitHub Actions issuer)

set -euo pipefail

ISSUER="${ISSUER:-https://token.actions.githubusercontent.com}"
DRY_RUN="${DRY_RUN:-false}"
REVOKE_STALE="${REVOKE_STALE:-true}"
FROM_BLOCK="${FROM_BLOCK:-0}"
MIN_KEYS="${MIN_KEYS:-2}"

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

[[ -n "${VERIFIER_ADDRESS:-}" ]] || fail "VERIFIER_ADDRESS is not set"
[[ -n "${RPC_URL:-}" ]] || fail "RPC_URL is not set"
if [[ "$DRY_RUN" != "true" ]]; then
  [[ -n "${PRIVATE_KEY:-}" ]] || fail "PRIVATE_KEY is not set (or set DRY_RUN=true)"
fi

# --- discovery ---------------------------------------------------------------

config="$(curl -fsS --max-time 30 "${ISSUER}/.well-known/openid-configuration")" ||
  fail "could not fetch the OpenID configuration"

jwks_uri="$(printf '%s' "$config" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("jwks_uri",""))')"
[[ -n "$jwks_uri" ]] || fail "the OpenID configuration has no jwks_uri"

# The discovery document names its own key endpoint, so a tampered response could point the sync at
# an attacker's keys. Only ever follow it back to the issuer itself.
[[ "$jwks_uri" == "${ISSUER}/"* ]] || fail "jwks_uri ${jwks_uri} is outside the issuer ${ISSUER}"

jwks="$(curl -fsS --max-time 30 "$jwks_uri")" || fail "could not fetch the JWKS"

# One tab-separated line per usable key: kid, modulus, exponent.
keys="$(
  printf '%s' "$jwks" | python3 -c '
import base64, json, sys

def b64url_to_hex(value):
    padded = value + "=" * (-len(value) % 4)
    return "0x" + base64.urlsafe_b64decode(padded).hex()

document = json.load(sys.stdin)
for key in document.get("keys", []):
    if key.get("kty") != "RSA":
        continue
    kid, modulus, exponent = key.get("kid"), key.get("n"), key.get("e")
    if not (kid and modulus and exponent):
        continue
    print("\t".join([kid, b64url_to_hex(modulus), b64url_to_hex(exponent)]))
'
)" || fail "could not parse the JWKS"

published_count="$(printf '%s' "$keys" | grep -c . || true)"
[[ "$published_count" -ge "$MIN_KEYS" ]] ||
  fail "JWKS returned ${published_count} usable keys, fewer than MIN_KEYS=${MIN_KEYS}; refusing to act on a partial response"

printf 'issuer %s published %s RSA keys\n' "$ISSUER" "$published_count"
printf 'verifier %s\n\n' "$VERIFIER_ADDRESS"

# --- add or refresh ----------------------------------------------------------

send() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '    dry run, not sent\n'
    return 0
  fi
  cast send "$VERIFIER_ADDRESS" "$@" \
    --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" >/dev/null
}

added=0
refreshed=0
unchanged=0
revoked=0
published_hashes=()

while IFS=$'\t' read -r kid modulus exponent; do
  [[ -n "$kid" ]] || continue

  # The contract keys the registry by keccak256 of the kid's UTF-8 bytes.
  kid_hash="$(cast keccak "$kid")"
  published_hashes+=("$kid_hash")

  stored="$(cast call "$VERIFIER_ADDRESS" 'keyOf(bytes32)((bytes,bytes,bool))' "$kid_hash" --rpc-url "$RPC_URL")"
  stored="$(printf '%s' "$stored" | tr -d '() \n')"
  want="${modulus},${exponent},true"

  if [[ "$stored" == "$want" ]]; then
    unchanged=$((unchanged + 1))
    printf '  unchanged  %s\n' "$kid"
    continue
  fi

  if [[ "$stored" == *",true" ]]; then
    refreshed=$((refreshed + 1))
    printf '  refreshing %s\n' "$kid"
  else
    added=$((added + 1))
    printf '  adding     %s\n' "$kid"
  fi

  send 'addKey(bytes32,bytes,bytes)' "$kid_hash" "$modulus" "$exponent"
done <<<"$keys"

# --- revoke what GitHub dropped ----------------------------------------------

if [[ "$REVOKE_STALE" == "true" ]]; then
  printf '\n'

  # The registry is not enumerable, so recover every kid it has ever held from its own events.
  known="$(
    cast logs --address "$VERIFIER_ADDRESS" 'KeyAdded(bytes32)' \
      --from-block "$FROM_BLOCK" --rpc-url "$RPC_URL" --json |
      python3 -c '
import json, sys
seen = []
for log in json.load(sys.stdin):
    topic = log["topics"][1]
    if topic not in seen:
        seen.append(topic)
print("\n".join(seen))
'
  )" || fail "could not read KeyAdded logs"

  while read -r kid_hash; do
    [[ -n "$kid_hash" ]] || continue

    for published in "${published_hashes[@]}"; do
      if [[ "$published" == "$kid_hash" ]]; then
        continue 2
      fi
    done

    stored="$(cast call "$VERIFIER_ADDRESS" 'keyOf(bytes32)((bytes,bytes,bool))' "$kid_hash" --rpc-url "$RPC_URL")"
    [[ "$(printf '%s' "$stored" | tr -d '() \n')" == *",true" ]] || continue

    revoked=$((revoked + 1))
    printf '  revoking   %s\n' "$kid_hash"
    send 'revokeKey(bytes32)' "$kid_hash"
  done <<<"$known"
fi

printf '\nadded %s refreshed %s unchanged %s revoked %s\n' "$added" "$refreshed" "$unchanged" "$revoked"

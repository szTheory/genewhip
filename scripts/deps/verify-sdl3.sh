#!/usr/bin/env bash
# Re-verify the pinned SDL3 release: size, SHA-256, detached signature and notice.
# Signer keys are fetched from SDL's signing-keys page into an ignored cache (SDL3_KEY_CACHE
# overrides the path) and pinned by SHA-256 plus fingerprint; none are committed.
# Prints "sdl3 verify: PASS" or "BLOCKED: <reason>". Needs network, curl, gpg, gpgv, tar.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RECORD=${SDL3_RECORD:-$ROOT/packaging/dependencies/sdl3.json}
KEYS=${SDL3_KEY_CACHE:-$ROOT/build/deps/sdl3-release-keys.asc}
KEYS_URL=https://www.libsdl.org/signing-keys.php
NOTICE=$ROOT/packaging/notices/SDL3-LICENSE.txt
blocked() { printf 'BLOCKED: %s\n' "$1"; exit 1; }
for tool in curl gpg gpgv tar shasum python3; do
  command -v "$tool" >/dev/null 2>&1 || blocked "$tool unavailable"
done
[ -f "$RECORD" ] && [ -f "$NOTICE" ] || blocked 'record or notice copy missing'
field() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))[sys.argv[2]]; print(v if not isinstance(v,list) else " ".join(v))' "$RECORD" "$1"; }
URL=$(field url); SIG_URL=$(field signature_url); SHA=$(field sha256); BYTES=$(field bytes)
SIG_SHA=$(field signature_sha256); SIGNERS=$(field signers); KEY_SHA=$(field signer_keys_sha256); LICENSE_SHA=$(field license_file_sha256)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
export GNUPGHOME=$TMP/gnupg; mkdir -m 700 "$GNUPGHOME"
curl -fsSL --retry 2 -o "$TMP/sdl.tar.gz" "$URL" || blocked 'tarball download failed'
curl -fsSL --retry 2 -o "$TMP/sdl.tar.gz.sig" "$SIG_URL" || blocked 'signature download failed'
[ "$(wc -c < "$TMP/sdl.tar.gz" | tr -d ' ')" = "$BYTES" ] || blocked 'tarball byte size differs from the record'
[ "$(shasum -a 256 "$TMP/sdl.tar.gz" | cut -d' ' -f1)" = "$SHA" ] || blocked 'tarball SHA-256 differs from the record'
[ "$(shasum -a 256 "$TMP/sdl.tar.gz.sig" | cut -d' ' -f1)" = "$SIG_SHA" ] || blocked 'signature SHA-256 differs from the record'
# The signer keys are not committed. Use the cached copy only if it matches the pinned digest;
# otherwise fetch SDL's published key block (CR-stripped armored text) and fail closed on mismatch.
key_ok() { [ -f "$KEYS" ] && [ "$(shasum -a 256 "$KEYS" | cut -d' ' -f1)" = "$KEY_SHA" ]; }
if ! key_ok; then
  mkdir -p "$(dirname "$KEYS")" 2>/dev/null || blocked 'key cache directory not writable'
  curl -fsSL --retry 2 -o "$TMP/keys.html" "$KEYS_URL" || blocked 'signer keys unavailable: no cached copy matches the pin and the fetch failed'
  tr -d '\r' < "$TMP/keys.html" | sed -n '/^-----BEGIN PGP PUBLIC KEY BLOCK-----$/,/^-----END PGP PUBLIC KEY BLOCK-----$/p' > "$TMP/keys.asc"
  [ "$(shasum -a 256 "$TMP/keys.asc" | cut -d' ' -f1)" = "$KEY_SHA" ] || blocked 'fetched signer key bytes differ from the pinned SHA-256'
  cp "$TMP/keys.asc" "$KEYS"
fi
gpg --batch --quiet --import "$KEYS" 2>/dev/null || blocked 'signer keys did not import'
gpg --batch --export > "$TMP/keyring.gpg" 2>/dev/null
HAVE=$(gpg --batch --with-colons --list-keys 2>/dev/null | awk -F: '/^pub:/ {p=1; next} p && /^fpr:/ {print $10; p=0}' | sort | tr '\n' ' ')
WANT=$(printf '%s\n' $SIGNERS | sort | tr '\n' ' ')
[ "$HAVE" = "$WANT" ] || blocked 'signer key fingerprints differ from the recorded signers'
STATUS=$(gpgv --status-fd 1 --keyring "$TMP/keyring.gpg" "$TMP/sdl.tar.gz.sig" "$TMP/sdl.tar.gz" 2>/dev/null) || true
if printf '%s\n' "$STATUS" | grep -Eq '^\[GNUPG:\] (EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG|NO_PUBKEY|EXPSIG)'; then
  blocked "signature status rejected: $(printf '%s\n' "$STATUS" | grep -Eo '^\[GNUPG:\] (EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG|NO_PUBKEY|EXPSIG)' | head -1 | cut -d' ' -f2)"
fi
printf '%s\n' "$STATUS" | grep -Eq '^\[GNUPG:\] GOODSIG ' || blocked 'no GOODSIG status'
OK=
for fpr in $SIGNERS; do
  # VALIDSIG <fpr> <date> <ts> ... <primary-fpr>: accept the signing or the primary fingerprint.
  if printf '%s\n' "$STATUS" | awk -v f="$fpr" '$2=="VALIDSIG" && ($3==f || $NF==f) {ok=1} END {exit !ok}'; then OK=$fpr; fi
done
[ -n "$OK" ] || blocked 'no VALIDSIG for a recorded fingerprint'
mkdir "$TMP/x"; tar -xzf "$TMP/sdl.tar.gz" -C "$TMP/x" "SDL3-$(field version)/LICENSE.txt" || blocked 'LICENSE.txt not in archive'
UP=$(shasum -a 256 "$TMP/x/SDL3-$(field version)/LICENSE.txt" | cut -d' ' -f1)
[ "$UP" = "$LICENSE_SHA" ] || blocked 'archive LICENSE.txt digest differs from the record'
[ "$(shasum -a 256 "$NOTICE" | cut -d' ' -f1)" = "$LICENSE_SHA" ] || blocked 'committed notice digest differs from the record'
cmp -s "$TMP/x/SDL3-$(field version)/LICENSE.txt" "$NOTICE" || blocked 'committed notice is not byte-identical to the archive LICENSE.txt'
echo "signed by recorded fingerprint $OK"
echo 'sdl3 verify: PASS'

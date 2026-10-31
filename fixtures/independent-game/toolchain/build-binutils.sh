#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd -P)
LOCK="$ROOT/fixtures/independent-game/toolchain.lock"
ARCHIVE=binutils-2.47.tar.bz2
BASE=https://ftp.gnu.org/gnu/binutils
ARCHIVE_SHA=3068128c75cda9f898ccb4211d360246e8e195ffcc9dfb655b23ae23a54800e8
SIGNATURE_SHA=133e31f4eedfe16cd47fa30a15ceef7a953cb8027766028d0a00d5b5a9e14a28
KEYRING_SHA=8013de59880f7a59f53b6bd207f4d2a408d67b84a82fa9cba1dbbf443428e2db
PRIMARY_FPR=3A24BC1E8FB409FA9F14371813FCEF89DD9E3C4F
SIGNING_FPR=3A24BC1E8FB409FA9F14371813FCEF89DD9E3C4F
SIG_TIME=1785086752
ANNOUNCEMENT=https://sourceware.org/pipermail/binutils/2026-July/150520.html
fail() { printf 'BLOCKED: %s\n' "$*" >&2; exit 1; }
record_apple_tools() {
  [ -x /bin/mkdir ] || fail 'Apple system mkdir unavailable at /bin/mkdir'
  [ -x /usr/bin/install ] || fail 'Apple system install unavailable at /usr/bin/install'
  COREUTILS_VERSION='not-installed; Apple system mkdir/install used'
  COREUTILS_SOURCE_SHA=not-applicable COREUTILS_FORMULA_SHA=not-applicable COREUTILS_LICENSE_SHA=not-applicable
  GMK_SHA=$(shasum -a 256 /bin/mkdir | awk '{print $1}')
  GINSTALL_SHA=$(shasum -a 256 /usr/bin/install | awk '{print $1}')
  COREUTILS_LINKS="/bin/mkdir on macOS $HOST_BUILD"
  GINSTALL_LINKS="/usr/bin/install on macOS $HOST_BUILD"
}
MODE=--record
TARGET=m68k-elf
OUTPUT=''
RECEIPT=''
CURRENT_RECEIPT=''
SELF_TEST_APPLE_TOOLS=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --record|--verify-lock|--record-current) MODE=$1; shift ;;
    --self-test-apple-tools) SELF_TEST_APPLE_TOOLS=true; shift ;;
    --target) [ -n "${2:-}" ] || fail 'missing --target'; TARGET=$2; shift 2 ;;
    --output) [ -n "${2:-}" ] || fail 'missing --output directory'; OUTPUT=$2; shift 2 ;;
    --receipt) [ -n "${2:-}" ] || fail 'missing --receipt path'; RECEIPT=$2; shift 2 ;;
    *) fail "usage: $0 [--record|--verify-lock|--record-current] [--target m68k-elf|z80-elf] [--output DIR] [--receipt FILE]" ;;
  esac
done
if [ "$SELF_TEST_APPLE_TOOLS" = true ]; then
  [ "$#" -eq 0 ] || fail '--self-test-apple-tools accepts no other arguments'
  HOST_BUILD=$(sw_vers -buildVersion)
  record_apple_tools
  [[ "$COREUTILS_LINKS" == /bin/mkdir\ on\ macOS\ * ]] || fail 'Apple mkdir receipt path mismatch'
  [[ "$GINSTALL_LINKS" == /usr/bin/install\ on\ macOS\ * ]] || fail 'Apple install receipt path mismatch'
  [[ "$GMK_SHA" =~ ^[0-9a-f]{64}$ && "$GINSTALL_SHA" =~ ^[0-9a-f]{64}$ ]] || fail 'Apple utility receipt digest malformed'
  printf 'PASS: Apple utility fallback binds /bin/mkdir and /usr/bin/install bytes\n'
  exit 0
fi
if [ "$MODE" = --record-current ]; then
  [ -n "$RECEIPT" ] || fail '--record-current requires --receipt'
  mkdir -p "$(dirname "$RECEIPT")"
  RECEIPT=$(cd "$(dirname "$RECEIPT")" && pwd -P)/$(basename "$RECEIPT")
  # A failed rebuild must never leave a receipt that can bless old bytes as
  # current-host output. A successful record is installed atomically below.
  rm -f "$RECEIPT"
fi
case "$TARGET" in m68k-elf) LOCK_KEY=assembler ;; z80-elf) LOCK_KEY=assembler_z80 ;; *) fail 'unsupported assembler target' ;; esac
if [ "$MODE" = --verify-lock ]; then CURRENT_RECEIPT="$ROOT/build/tool-cache/$TARGET-as.receipt.json"; fi
FLAGS=(--prefix=/usr/local --target="$TARGET" --disable-nls --disable-werror --disable-gdb --disable-gdbserver --disable-gprofng --disable-gold --disable-ld --disable-sim --disable-shared --disable-plugins --disable-libctf --disable-readline --disable-tui --disable-gdbtk --disable-compressed-debug-sections --without-system-zlib --without-zstd)
CONFIGURE="../binutils-2.47/configure ${FLAGS[*]}"
BUILD_COMMAND='make -j4 all-gas && make DESTDIR=<BUILD_ROOT>/stage install-gas'
SOURCE_DATE_EPOCH=1785086752

# Resolve a requested output directory before entering the temporary build tree.
if [ -n "$OUTPUT" ]; then
  mkdir -p "$OUTPUT"
  OUTPUT=$(cd "$OUTPUT" && pwd -P)
fi
for tool in curl /usr/bin/tar /usr/bin/shasum /usr/bin/file /usr/bin/otool python3 xcodebuild xcrun clang make grep; do
  command -v "$tool" >/dev/null 2>&1 || fail "required host tool unavailable: $tool"
done
GPGV=$(command -v gpgv || true)
[ -n "$GPGV" ] || fail 'gpgv unavailable; signed release verification is required'
[ "$(uname -s)" = Darwin ] || fail 'the pinned executable record requires native macOS'
[ "$(uname -m)" = arm64 ] || fail 'the pinned executable record requires native macOS arm64'

TMP=$(mktemp -d "${TMPDIR:-/tmp}/genewhip-binutils-247.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
curl -fsSL --retry 2 "$BASE/$ARCHIVE" -o "$TMP/$ARCHIVE" || fail 'official release archive download failed'
curl -fsSL --retry 2 "$BASE/$ARCHIVE.sig" -o "$TMP/$ARCHIVE.sig" || fail 'official detached signature download failed'
curl -fsSL --retry 2 https://ftp.gnu.org/gnu/gnu-keyring.gpg -o "$TMP/gnu-keyring.gpg" || fail 'official GNU keyring download failed'
ACTUAL_ARCHIVE=$(shasum -a 256 "$TMP/$ARCHIVE" | awk '{print $1}')
ACTUAL_SIGNATURE=$(shasum -a 256 "$TMP/$ARCHIVE.sig" | awk '{print $1}')
ACTUAL_KEYRING=$(shasum -a 256 "$TMP/gnu-keyring.gpg" | awk '{print $1}')
[ "$ACTUAL_ARCHIVE" = "$ARCHIVE_SHA" ] || fail "archive SHA-256 mismatch: $ACTUAL_ARCHIVE"
[ "$ACTUAL_SIGNATURE" = "$SIGNATURE_SHA" ] || fail "signature SHA-256 mismatch: $ACTUAL_SIGNATURE"
[ "$ACTUAL_KEYRING" = "$KEYRING_SHA" ] || fail "keyring SHA-256 mismatch: $ACTUAL_KEYRING"
SIGNATURE_OUTPUT=$("$GPGV" --status-fd 1 --keyring "$TMP/gnu-keyring.gpg" "$TMP/$ARCHIVE.sig" "$TMP/$ARCHIVE" 2>&1) || fail "signature verification failed: $SIGNATURE_OUTPUT"
if printf '%s\n' "$SIGNATURE_OUTPUT" | grep -E -q '\[GNUPG:\] (EXPKEYSIG|EXPSIG|KEYEXPIRED|KEYREVOKED|REVKEYSIG|BADSIG|ERRSIG|NO_PUBKEY)'; then
  fail "signature reports expired, revoked, invalid, or missing-key status: $SIGNATURE_OUTPUT"
fi
printf '%s\n' "$SIGNATURE_OUTPUT" | grep -E -q "\[GNUPG:\] GOODSIG [^ ]+" || fail 'signature verifier did not report GOODSIG'
printf '%s\n' "$SIGNATURE_OUTPUT" | grep -E -q "\[GNUPG:\] VALIDSIG $SIGNING_FPR $([ "$SIG_TIME" = 1785086752 ] && printf '2026-07-26') $SIG_TIME " || fail 'signature signer or timestamp differs from the pinned identity'
PRIMARY=$(printf '%s\n' "$SIGNATURE_OUTPUT" | awk '/\[GNUPG:\] VALIDSIG / {print $NF; exit}')
[ "$PRIMARY" = "$PRIMARY_FPR" ] || fail "unexpected primary signer fingerprint: ${PRIMARY:-missing}"

/usr/bin/tar -xjf "$TMP/$ARCHIVE" -C "$TMP" || fail 'verified archive extraction failed'
python3 - "$TMP/binutils-2.47" > "$TMP/source-tree.sha256" <<'PY'
import hashlib, pathlib, sys
root = pathlib.Path(sys.argv[1])
h = hashlib.sha256()
for path in sorted(p for p in root.rglob('*') if p.is_file()):
    rel = path.relative_to(root).as_posix().encode()
    h.update(len(rel).to_bytes(8, 'big')); h.update(rel)
    h.update(bytes.fromhex(hashlib.sha256(path.read_bytes()).hexdigest()))
print(h.hexdigest())
PY

SOURCE_TREE=$(cat "$TMP/source-tree.sha256")
COMPILE_FLAGS="-O2 -g0 -ffile-prefix-map=$TMP=."
LOCK_COMPILE_FLAGS='-O2 -g0 -ffile-prefix-map=<BUILD_ROOT>=.'
LICENSES=$(python3 - "$TMP/binutils-2.47" <<'PY'
import hashlib, json, pathlib, sys
root=pathlib.Path(sys.argv[1])
names=['COPYING','COPYING3','COPYING3.LIB','gas/COPYING','bfd/COPYING']
out=[]
for name in names:
 p=root/name
 if not p.is_file(): raise SystemExit('required upstream license notice missing: '+name)
 out.append({'path':name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'license':'GNU GPL-3.0-or-later; exact notice retained in upstream release source'})
print(json.dumps(out,separators=(',',':')))
PY
) || fail 'upstream license inventory incomplete'
mkdir "$TMP/build" "$TMP/stage"
cd "$TMP/build"
CFLAGS="$COMPILE_FLAGS" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" ../binutils-2.47/configure "${FLAGS[@]}" > "$TMP/configure.log" 2>&1 || { tail -n 50 "$TMP/configure.log" >&2; fail 'Binutils configure failed'; }
CFLAGS="$COMPILE_FLAGS" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make -j4 all-gas > "$TMP/build.log" 2>&1 || { tail -n 80 "$TMP/build.log" >&2; fail 'Binutils assembler build failed'; }
CFLAGS="$COMPILE_FLAGS" SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" make DESTDIR="$TMP/stage" install-gas >> "$TMP/build.log" 2>&1 || { tail -n 80 "$TMP/build.log" >&2; fail 'Binutils assembler install failed'; }
AS="$TMP/stage/usr/local/bin/$TARGET-as"
[ -x "$AS" ] || fail "source build did not produce executable $TARGET-as"
VERSION=$("$AS" --version 2>&1)
printf '%s\n' "$VERSION" | grep -E -q '^GNU assembler \(GNU Binutils\) 2\.47\.' || fail 'built assembler version mismatch'
printf '%s\n' "$VERSION" | grep -E -q "configured for a target of .$TARGET." || fail 'built assembler target mismatch'
AS_SHA=$(shasum -a 256 "$AS" | awk '{print $1}')
AS_TYPE=$(/usr/bin/file -b "$AS")
[ "$AS_TYPE" = 'Mach-O 64-bit executable arm64' ] || fail "unexpected assembler executable type: $AS_TYPE"
AS_LINKS=$(/usr/bin/otool -L "$AS" | tail -n +2 | sed -E 's/^[[:space:]]*([^ ]+).*/\1/')
printf '%s\n' "$AS_LINKS" | grep -E -v '^(/usr/lib/|/System/Library/)' && fail 'assembler has an unaccounted non-system linked image'
AS_LINKS_JSON=$(printf '%s\n' "$AS_LINKS" | python3 -c 'import json,sys; print(json.dumps([{"path":x.strip(),"identity":"Apple system image bound to recorded macOS build"} for x in sys.stdin if x.strip()],separators=(",",":")))')
HOST_OS=$(sw_vers -productVersion); HOST_BUILD=$(sw_vers -buildVersion); HOST_ARCH=$(uname -m)
XCODE=$(xcodebuild -version | tr '\n' ';'); SDK=$(xcrun --sdk macosx --show-sdk-version); SDK_BUILD=$(xcrun --sdk macosx --show-sdk-build-version)
CLANG=$(clang --version | head -n 1); MAKE=$(make --version | head -n 1)
GPGV_VERSION=$("$GPGV" --version | head -n 1); GPGV_SHA=$(shasum -a 256 "$GPGV" | awk '{print $1}')
GPGV_LINKS=$(/usr/bin/otool -L "$GPGV" | tail -n +2 | sed -E 's/^[[:space:]]*([^ ]+).*/\1/')
GPGV_LINKS_JSON=$(printf '%s\n' "$GPGV_LINKS" | python3 -c 'import json,sys; print(json.dumps([x.strip() for x in sys.stdin if x.strip()],separators=(",",":")))')
GPGV_TYPE=$(/usr/bin/file -b "$GPGV")
GPGV_INVENTORY=$(python3 - "$GPGV_LINKS_JSON" "$HOST_BUILD" <<'PY'
import hashlib, json, pathlib, re, sys
links=json.loads(sys.argv[1]); build=sys.argv[2]
licenses={'gettext':'LGPL-2.1-or-later','libgcrypt':'LGPL-2.1-or-later','libassuan':'LGPL-2.1-or-later','npth':'LGPL-3.0-or-later','libgpg-error':'LGPL-2.1-or-later'}
out=[]
for raw in links:
    p=pathlib.Path(raw)
    if raw.startswith(('/usr/lib/','/System/Library/')):
        out.append({'image':p.name,'identity':'Apple system image, macOS build '+build,'license':'Apple macOS system component'})
        continue
    resolved=p.resolve(strict=True)
    m=re.search(r'/Cellar/([^/]+)/([^/]+)/',str(resolved))
    if not m: raise SystemExit('unidentified non-system verifier dependency: '+raw)
    name,version=m.groups()
    out.append({'image':p.name,'package':name,'version':version,'sha256':hashlib.sha256(resolved.read_bytes()).hexdigest(),'license':licenses.get(name,'unknown')})
    if out[-1]['license']=='unknown': raise SystemExit('unknown verifier dependency license: '+name)
print(json.dumps(out,separators=(',',':')))
PY
) || fail 'signature verifier linked-input/license inventory incomplete'
GCC=$(command -v gcc || true); [ -n "$GCC" ] || fail 'Apple clang driver command gcc unavailable'
GCC_VERSION=$(gcc --version | head -n 1); GCC_SHA=$(shasum -a 256 "$GCC" | awk '{print $1}')
COREUTILS=$(realpath "$(command -v gmkdir)" 2>/dev/null || true)
GINSTALL=$(realpath "$(command -v ginstall)" 2>/dev/null || true)
if [ -n "$COREUTILS" ] && [ -n "$GINSTALL" ]; then
  COREUTILS_ROOT=$(printf '%s' "$COREUTILS" | sed -E 's#/bin/[^/]+$##')
  case "$COREUTILS_ROOT" in */Cellar/coreutils/*) ;; *) COREUTILS='' ;; esac
fi
if [ -n "$COREUTILS" ] && [ -n "$GINSTALL" ]; then
  COREUTILS_VERSION=${COREUTILS_ROOT##*/}
  COREUTILS_FORMULA="$COREUTILS_ROOT/.brew/coreutils.rb"
  COREUTILS_LICENSE="$COREUTILS_ROOT/COPYING"
  [ -f "$COREUTILS_FORMULA" ] && [ -f "$COREUTILS_LICENSE" ] || fail 'GNU Coreutils formula/license notices missing'
  COREUTILS_SOURCE_SHA=$(sed -nE 's/^[[:space:]]*sha256 "([0-9a-f]{64})".*/\1/p' "$COREUTILS_FORMULA" | head -n 1)
  COREUTILS_FORMULA_SHA=$(shasum -a 256 "$COREUTILS_FORMULA" | awk '{print $1}')
  COREUTILS_LICENSE_SHA=$(shasum -a 256 "$COREUTILS_LICENSE" | awk '{print $1}')
  GMK_SHA=$(shasum -a 256 "$COREUTILS" | awk '{print $1}')
  GINSTALL_SHA=$(shasum -a 256 "$GINSTALL" | awk '{print $1}')
  COREUTILS_LINKS=$(/usr/bin/otool -L "$COREUTILS" | tail -n +2 | sed -E 's/^[[:space:]]*([^ ]+).*/\1/' | tr '\n' ';')
  GINSTALL_LINKS=$(/usr/bin/otool -L "$GINSTALL" | tail -n +2 | sed -E 's/^[[:space:]]*([^ ]+).*/\1/' | tr '\n' ';')
else
  [ "$MODE" = --record-current ] || fail 'GNU Coreutils gmkdir/ginstall build inputs unavailable'
  record_apple_tools
fi
PYTHON_BIN=$(realpath "$(command -v python3)" 2>/dev/null || true)
[ -n "$PYTHON_BIN" ] || fail 'Python candidate builder unavailable'
PYTHON_MINOR=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_FORMULA_NAME="python@$PYTHON_MINOR"
PYTHON_PREFIX=$(brew --prefix "$PYTHON_FORMULA_NAME" 2>/dev/null || true)
[ -n "$PYTHON_PREFIX" ] || fail 'Python Homebrew prefix unavailable'
PYTHON_ROOT=$(realpath "$PYTHON_PREFIX" 2>/dev/null || true)
[ -n "$PYTHON_ROOT" ] || fail 'Python Homebrew installation path unavailable'
PYTHON_FORMULA="$PYTHON_ROOT/.brew/$PYTHON_FORMULA_NAME.rb"
PYTHON_LICENSE="$PYTHON_ROOT/LICENSE"
[ -f "$PYTHON_FORMULA" ] && [ -f "$PYTHON_LICENSE" ] || fail 'Python formula/license provenance unavailable'
PYTHON_VERSION=$(python3 --version)
PYTHON_SHA=$(shasum -a 256 "$PYTHON_BIN" | awk '{print $1}')
PYTHON_TYPE=$(/usr/bin/file -b "$PYTHON_BIN")
PYTHON_SOURCE_SHA=$(sed -nE 's/^[[:space:]]*sha256 "([0-9a-f]{64})".*/\1/p' "$PYTHON_FORMULA" | head -n 1)
PYTHON_SOURCE_URL=$(sed -nE 's/^[[:space:]]*url "([^"]+)".*/\1/p' "$PYTHON_FORMULA" | head -n 1)
PYTHON_FORMULA_SHA=$(shasum -a 256 "$PYTHON_FORMULA" | awk '{print $1}')
PYTHON_LICENSE_SHA=$(shasum -a 256 "$PYTHON_LICENSE" | awk '{print $1}')
PYTHON_FRAMEWORK=$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("LDLIBRARY"))')
PYTHON_FRAMEWORK_PATH=$(python3 - "$PYTHON_BIN" <<'PY'
import pathlib, subprocess, sys
for line in subprocess.check_output(['/usr/bin/otool','-L',sys.argv[1]], text=True).splitlines()[1:]:
 p=line.strip().split(' (',1)[0]
 if '/Python.framework/' in p:
  print(pathlib.Path(p).resolve(strict=True)); break
PY
)
[ -n "$PYTHON_FRAMEWORK_PATH" ] || fail 'Python framework identity unavailable from linked-image inventory'
PYTHON_FRAMEWORK_SHA=$(shasum -a 256 "$PYTHON_FRAMEWORK_PATH" | awk '{print $1}')
PYTHON_TREE_SHA=$(python3 - "$PYTHON_ROOT" <<'PY'
import hashlib,pathlib,sys
r=pathlib.Path(sys.argv[1]); h=hashlib.sha256()
# __pycache__ is regenerated whenever Python runs, so it is not part of the package identity.
for p in sorted(x for x in r.rglob('*') if x.is_file() and '__pycache__' not in x.relative_to(r).parts):
 rel=p.relative_to(r).as_posix().encode(); h.update(len(rel).to_bytes(8,'big')); h.update(rel); h.update(bytes.fromhex(hashlib.sha256(p.read_bytes()).hexdigest()))
print(h.hexdigest())
PY
)
PYTHON_LINKS=$(/usr/bin/otool -L "$PYTHON_BIN" | tail -n +2 | sed -E 's/^[[:space:]]*([^ ]+).*/\1/')
PYTHON_INVENTORY=$(python3 - "$PYTHON_LINKS" "$HOST_BUILD" "$PYTHON_ROOT" "$PYTHON_FORMULA_NAME" "$PYTHON_VERSION" <<'PY'
import hashlib,json,pathlib,sys
build=sys.argv[2]; root=pathlib.Path(sys.argv[3]); package=sys.argv[4]; version=sys.argv[5]; out=[]
for raw in sys.argv[1].splitlines():
 p=pathlib.Path(raw)
 if raw.startswith(('/usr/lib/','/System/Library/')):
  out.append({'image':p.name,'identity':'Apple system image, macOS build '+build,'license':'Apple macOS system component'})
 else:
  resolved=p.resolve(strict=True)
  out.append({'image':p.name,'package':package,'version':version.replace('Python ',''),'sha256':hashlib.sha256(resolved.read_bytes()).hexdigest(),'license':'Python-2.0'})
print(json.dumps(out,separators=(',',':')))
PY
) || fail 'Python candidate-builder linked-image inventory incomplete'

if [ -n "$OUTPUT" ]; then
  mkdir -p "$OUTPUT"
  cp "$AS" "$OUTPUT/$TARGET-as"
  chmod 755 "$OUTPUT/$TARGET-as"
  [ "$(shasum -a 256 "$OUTPUT/$TARGET-as" | awk '{print $1}')" = "$AS_SHA" ] || fail 'copied assembler identity changed'
fi

python3 - "$LOCK" "$MODE" "$ACTUAL_ARCHIVE" "$ACTUAL_SIGNATURE" "$ACTUAL_KEYRING" "$PRIMARY" "$SIGNING_FPR" "$SIG_TIME" "$ANNOUNCEMENT" "$SOURCE_TREE" "$LICENSES" "$HOST_OS" "$HOST_BUILD" "$HOST_ARCH" "$XCODE" "$SDK" "$SDK_BUILD" "$CLANG" "$MAKE" "$GPGV_VERSION" "$GPGV_SHA" "$GPGV_TYPE" "$GPGV_LINKS_JSON" "$GPGV_INVENTORY" "$GCC_VERSION" "$GCC_SHA" "$COREUTILS_VERSION" "$COREUTILS_SOURCE_SHA" "$COREUTILS_FORMULA_SHA" "$COREUTILS_LICENSE_SHA" "$GMK_SHA" "$GINSTALL_SHA" "$COREUTILS_LINKS" "$GINSTALL_LINKS" "$PYTHON_VERSION" "$PYTHON_SHA" "$PYTHON_TYPE" "$PYTHON_SOURCE_SHA" "$PYTHON_SOURCE_URL" "$PYTHON_FORMULA_SHA" "$PYTHON_LICENSE_SHA" "$PYTHON_FRAMEWORK_SHA" "$PYTHON_TREE_SHA" "$PYTHON_INVENTORY" "$AS_SHA" "$AS_TYPE" "$VERSION" "$AS_LINKS_JSON" "${FLAGS[*]}; CFLAGS=$LOCK_COMPILE_FLAGS; SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" "$BUILD_COMMAND" "$TARGET" "$LOCK_KEY" "$RECEIPT" "$CURRENT_RECEIPT" <<'PY'
import json, pathlib, sys
(path, mode, archive, sig, keyring, primary, signing, sigtime, announcement,
 tree, licenses, osver, osbuild, arch, xcode, sdk, sdkbuild, clang, make,
 gpgv, gpgvsha, gpgvtype, gpgvlinks, gpgv_inventory, gcc_version, gcc_sha,
 coreutils_version, coreutils_source, coreutils_formula, coreutils_license,
 gmkdir_sha, ginstall_sha, gmkdir_links, ginstall_links,
 python_version, python_sha, python_type, python_source, python_source_url, python_formula, python_license, python_framework_sha, python_tree, python_inventory,
 assha, astype, version, aslinks,
 flags, build, target, lock_key, receipt, current_receipt_path) = sys.argv[1:]
p=pathlib.Path(path); doc=json.loads(p.read_text()); before_mame=doc.get('mame')
host_dependency = ({'name':'Apple system directory/install utilities','identity':'/bin/mkdir and /usr/bin/install on macOS '+osbuild,'license':'Apple macOS system tools; host build only','executables':[{'name':'mkdir','sha256':gmkdir_sha,'linked_images':[gmkdir_links]},{'name':'install','sha256':ginstall_sha,'linked_images':[ginstall_links]}]} if coreutils_version.startswith('not-installed') else {'name':'GNU Coreutils install tools','version':coreutils_version,'source_archive_sha256':coreutils_source,'formula_sha256':coreutils_formula,'license':'GPL-3.0-or-later','license_notice_sha256':coreutils_license,'executables':[{'name':'gmkdir','sha256':gmkdir_sha,'linked_images':[x for x in gmkdir_links.split(';') if x]},{'name':'ginstall','sha256':ginstall_sha,'linked_images':[x for x in ginstall_links.split(';') if x]}]})
new={
 'name':'GNU Binutils assembler','version':'2.47','source_url':'https://ftp.gnu.org/gnu/binutils/binutils-2.47.tar.bz2',
 'source_revision':'binutils-2.47 official release archive; extracted source tree SHA-256 '+tree,
 'source_archive_sha256':archive,
 'signature':{'url':'https://ftp.gnu.org/gnu/binutils/binutils-2.47.tar.bz2.sig','sha256':sig,'keyring_url':'https://ftp.gnu.org/gnu/gnu-keyring.gpg','keyring_sha256':keyring,'primary_fingerprint':primary,'signing_fingerprint':signing,'timestamp_unix':int(sigtime),'outcome':'GOODSIG and VALIDSIG; no expired, revoked, bad-signature, or missing-key status','release_announcement':announcement},
 'license':'GNU GPL-3.0-or-later for GNU assembler; upstream exact notices retained in source archive and identified below; no Binutils source or executable redistributed',
 'upstream_license_notices':json.loads(licenses),
 'host':{'os':'macOS '+osver,'os_build':osbuild,'architecture':arch,'xcode':xcode.strip(';'),'sdk_version':sdk,'sdk_build':sdkbuild,'compiler':clang,'make':make},
 'flags':['target='+target,'configure='+flags,'build='+build],
 'build_dependencies':[{'name':'Apple Xcode and macOS SDK','identity':xcode.replace(';','; ')+', macOS SDK '+sdk+' ('+sdkbuild+')','license':'Apple proprietary host tools; not redistributed'}, {'name':'Apple clang driver','command':'gcc','identity':gcc_version,'sha256':gcc_sha,'license':'Apple Xcode toolchain; host compiler only'}, {'name':'Apple GNU Make','identity':make,'license':'Apple command-line developer tools; host build only'}, host_dependency, {'name':'GNU Binutils release verifier gpgv','identity':gpgv,'sha256':gpgvsha,'file_type':gpgvtype,'license':'GnuPG GPL-3.0-or-later; verification only, not linked into assembler','linked_images':json.loads(gpgv_inventory)}],
 'candidate_builder':{'name':'Python candidate builder and identity recorder','version':python_version,'file_type':python_type,'sha256':python_sha,'source_url':python_source_url,'source_archive_sha256':python_source,'formula_sha256':python_formula,'license':'Python-2.0','license_notice_sha256':python_license,'framework_sha256':python_framework_sha,'package_tree_sha256':python_tree,'linked_images':json.loads(python_inventory)},
 'inputs':['official GNU Binutils 2.47 archive SHA-256 '+archive,'detached signature SHA-256 '+sig,'official GNU keyring SHA-256 '+keyring,'extracted source tree SHA-256 '+tree,'No assembler-linked non-system libraries; linked images: '+', '.join(x['path'] for x in json.loads(aslinks))],
 'executable':{'name':target+'-as','version_output':version,'target':target,'file_type':astype,'sha256':assha,'linked_images':json.loads(aslinks)},
 'disposition':'source-built from official archive; no Homebrew Binutils bottle used'
}
if before_mame is None: raise SystemExit('BLOCKED: MAME lock record missing')
if mode=='--record-current':
 if not receipt: raise SystemExit('BLOCKED: current-host receipt path missing')
 payload={'schema':'genewhip-current-host-toolchain-v1','receipt_basis':'fresh source build; separate from immutable historical toolchain.lock','historical_lock_sha256':__import__('hashlib').sha256(p.read_bytes()).hexdigest(),'target':target,'record':new}
 target_path=pathlib.Path(receipt)
 temporary=target_path.with_name(target_path.name+'.tmp')
 temporary.write_text(json.dumps(payload,indent=2)+'\n')
 temporary.replace(target_path)
 print('RECORDED: current-host '+target+' toolchain receipt; historical toolchain.lock unchanged')
 raise SystemExit(0)
if mode=='--verify-lock' and doc.get(lock_key) != new:
 current_path=pathlib.Path(current_receipt_path) if current_receipt_path else None
 if current_path and current_path.is_file() and new['executable']['sha256']==doc.get(lock_key,{}).get('executable',{}).get('sha256'):
  current=json.loads(current_path.read_text())
  expected_lock=__import__('hashlib').sha256(p.read_bytes()).hexdigest()
  if (current.get('schema')=='genewhip-current-host-toolchain-v1' and
      current.get('receipt_basis')=='fresh source build; separate from immutable historical toolchain.lock' and
      current.get('historical_lock_sha256')==expected_lock and current.get('target')==target and
      current.get('record')==new):
   print('PASS: exact historical assembler executable reproduced; separate current-host receipt validates host drift; toolchain.lock unchanged')
   raise SystemExit(0)
 print('BLOCKED: rebuilt assembler identity differs from toolchain.lock',file=sys.stderr)
 existing=doc.get(lock_key,{})
 for key in sorted(set(existing)|set(new)):
  if existing.get(key)!=new.get(key): print('identity mismatch '+key+': locked='+json.dumps(existing.get(key),sort_keys=True)+' actual='+json.dumps(new.get(key),sort_keys=True),file=sys.stderr)
 raise SystemExit(1)
if mode=='--record': doc[lock_key]=new; p.write_text(json.dumps(doc,indent=2)+'\n'); print('RECORDED: source-built GNU Binutils 2.47 '+target+' assembler identity')
else: print('PASS: verified source-built GNU Binutils 2.47 identity matches toolchain.lock')
PY

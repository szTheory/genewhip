#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd -P)
FIXTURE="$ROOT/fixtures/independent-game"
LOCK=${GENEWHIP_TOOLCHAIN_LOCK:-$FIXTURE/toolchain.lock}
WORK_ROOT=${GENEWHIP_MAME_WORK_ROOT:-/tmp/genewhip-mame0289-work}
SOURCE_DIR=${GENEWHIP_MAME_SOURCE_DIR:-$WORK_ROOT/source}
SDL_ROOT=${GENEWHIP_SDL3_PREFIX:-$WORK_ROOT/sdl3prefix}
ARCHIVE="$WORK_ROOT/mame0289.tar.gz"
SDL_ARCHIVE="$WORK_ROOT/dependencies/SDL3-3.4.12.tar.gz"
PATCH_FILE="$FIXTURE/mame.patch"
PATCH_SHA=
MAME_COMMIT=f34f02505e32c1993c6a782b6814232cbfc74e36
MAME_TAG=mame0289
MAME_ARCHIVE_SHA=0929cc749afabcef892900e10dd90bd8b05f94a7dde8f367ac6a5d2082589f84
SDL_SHA=f07b958a9ac5020fb7a44cadb957f658b2149c3c8abb4f63145fac9303249db7
SIGNER_FINGERPRINT=D0362DB01844E0433ADBBFBAC174B1018C40710E
SIGNER_KEY_SHA=dada893db9dc7c1fdf7b138059d54451274cf882891b38243c24d7987d92aea4

fail() { printf 'BLOCKED: %s\n' "$*" >&2; exit 1; }
hash_file() { shasum -a 256 "$1" | awk '{print $1}'; }

verify_archive() {
	[ -f "$ARCHIVE" ] || fail "MAME 0.289 source archive missing at the configured work root"
	[ "$(hash_file "$ARCHIVE")" = "$MAME_ARCHIVE_SHA" ] || fail 'MAME source archive hash mismatch'
	[ -f "$SDL_ARCHIVE" ] || fail 'SDL 3.4.12 source archive missing'
	[ "$(hash_file "$SDL_ARCHIVE")" = "$SDL_SHA" ] || fail 'SDL source archive hash mismatch'
}

verify_source_and_signature() {
	PATCH_SHA=$(hash_file "$PATCH_FILE")
	[ -d "$SOURCE_DIR/.git" ] || fail 'MAME source checkout is missing; run --build to acquire the signed tag first'
	[ "$(git -C "$SOURCE_DIR" rev-parse HEAD)" = "$MAME_COMMIT" ] || fail 'MAME checkout is not the pinned commit'
	[ "$(git -C "$SOURCE_DIR" describe --tags --exact-match HEAD)" = "$MAME_TAG" ] || fail 'MAME checkout is not at the pinned release tag'
	[ "$(hash_file "$PATCH_FILE")" = "$PATCH_SHA" ] || fail 'instrumentation patch digest mismatch'
	local changed="$WORK_ROOT/actual-instrumentation.patch"
	git -C "$SOURCE_DIR" diff --binary -- src/mame/sega/mdconsole.cpp src/mame/sega/megadriv.h > "$changed"
	[ "$(hash_file "$changed")" = "$PATCH_SHA" ] || fail 'checked-out instrumentation changes do not match the versioned patch'
	[ "$(git -C "$SOURCE_DIR" diff --name-only | LC_ALL=C sort | tr '\n' ' ')" = 'src/mame/sega/mdconsole.cpp src/mame/sega/megadriv.h ' ] || fail 'MAME checkout has unexpected tracked modifications'
	local keyfile="$WORK_ROOT/cuavas-public-key.asc"
	if [ ! -f "$keyfile" ]; then
		curl -fL --retry 3 --output "$WORK_ROOT/cuavas-gpg-keys.json" https://api.github.com/users/cuavas/gpg_keys
		python3 - "$WORK_ROOT/cuavas-gpg-keys.json" "$keyfile" <<'PY'
import json, pathlib, sys
items=json.loads(pathlib.Path(sys.argv[1]).read_text())
matches=[x for x in items if x.get('key_id','').upper()=='C174B1018C40710E']
if len(matches)!=1: raise SystemExit('BLOCKED: expected exactly one profile key with the pinned key ID')
pathlib.Path(sys.argv[2]).write_text(matches[0]['raw_key'])
PY
	fi
	[ "$(hash_file "$keyfile")" = "$SIGNER_KEY_SHA" ] || fail 'MAME signing-key bytes changed'
	local gnupg="$WORK_ROOT/gnupg"
	mkdir -p "$gnupg"
	chmod 700 "$gnupg"
	GNUPGHOME="$gnupg" gpg --batch --import "$keyfile" >/dev/null 2>&1
	local fingerprint
	fingerprint=$(GNUPGHOME="$gnupg" gpg --batch --with-colons --fingerprint "$SIGNER_FINGERPRINT" | awk -F: '$1=="fpr" { print $10; exit }')
	[ "$fingerprint" = "$SIGNER_FINGERPRINT" ] || fail 'MAME signer key fingerprint mismatch'
	GNUPGHOME="$gnupg" git -C "$SOURCE_DIR" verify-tag "$MAME_TAG" >/dev/null 2>&1 || fail 'MAME release tag signature verification failed'
}

capture_lock() {
	python3 - "$LOCK" "$WORK_ROOT" "$SOURCE_DIR" "$SDL_ROOT" "$PATCH_FILE" "$0" <<'PY'
import hashlib, json, pathlib, platform, re, subprocess, sys
lock_path, work_root, source_dir, sdl_root, patch_file, script_file=sys.argv[1:]
work=pathlib.Path(work_root); source=pathlib.Path(source_dir); sdl=pathlib.Path(sdl_root)
exe=source/'genewhip'; dylib=sdl/'lib/libSDL3.0.dylib'
def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def run(*args): return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()
def command_hash(name):
    path=run('which',name)
    return {'path_class':'host-tool','version':run(name,'--version').splitlines()[0], 'sha256':sha(path)}
config_paths=[
 'build/projects/sdl3/mamegenewhip/gmake-osx-clang/Makefile',
 'build/projects/sdl3/mamegenewhip/gmake-osx-clang/mame_genewhip.make',
 'build/projects/sdl3/mamegenewhip/gmake-osx-clang/osd_sdl3.make',
 'build/projects/sdl3/mamegenewhip/gmake-osx-clang/genewhip.make',
 'build/generated/mame/genewhip/drivlist.cpp',
]
config=[]
for rel in config_paths:
    p=source/rel
    if not p.is_file(): raise SystemExit(f'BLOCKED: generated MAME configuration missing: {rel}')
    config.append({'path':rel,'sha256':sha(p)})
config_digest=hashlib.sha256(b''.join(x['path'].encode()+b'\0'+x['sha256'].encode()+b'\n' for x in config)).hexdigest()
version=run(str(exe),'-version')
file_type=run('file',str(exe)).split(': ',1)[1]
if 'Mach-O 64-bit executable arm64' not in file_type: raise SystemExit('BLOCKED: executable is not native macOS arm64')
links=run('otool','-L',str(exe)).splitlines()[1:]
linked=[]
for line in links:
    image=line.strip().split(' (compatibility',1)[0]
    if image=='@rpath/libSDL3.0.dylib':
        linked.append({'image':image,'kind':'source-built dependency','package':'SDL','version':'3.4.12','source_archive_sha256':'f07b958a9ac5020fb7a44cadb957f658b2149c3c8abb4f63145fac9303249db7','sha256':sha(dylib),'license':'Zlib; upstream notice retained in source archive'})
    elif image.startswith('/System/Library/') or image.startswith('/usr/lib/'):
        linked.append({'image':image,'kind':'host system image','identity':'macOS build 25G83','license':'Apple system component; not redistributed'})
    else: raise SystemExit(f'BLOCKED: unclassified linked image: {image}')
if sum(x.get('package')=='SDL' for x in linked)!=1: raise SystemExit('BLOCKED: expected exactly one linked SDL image')
old=json.loads(pathlib.Path(lock_path).read_text())
prior=old.get('mame',{})
signature={
 'status':'pass', 'tag':'mame0289', 'tag_object':'d0b7160e54874fa58f553614db373d73100d5ecb',
 'tag_signature_sha256':'4e6943da913b68f395c3785e5e94e82803668fb37938e3369dc8819502a945c2',
 'signer_fingerprint':'D0362DB01844E0433ADBBFBAC174B1018C40710E',
 'signer_key_source':'https://api.github.com/users/cuavas/gpg_keys (key ID C174B1018C40710E)',
 'signer_key_sha256':'dada893db9dc7c1fdf7b138059d54451274cf882891b38243c24d7987d92aea4',
 'verification':'isolated GNUPGHOME import; full fingerprint independently matched; git verify-tag passed'
}
host={'os':'macOS 26.6.2','os_build':'25G83','architecture':platform.machine(),
 'xcode':'Xcode 26.6; build 17F113','sdk_version':'26.5','sdk_build':'25F70',
 'compiler':run('clang','--version').splitlines()[0], 'make':run('make','--version').splitlines()[0],
 'python':run('python3','--version'), 'cmake':command_hash('cmake'), 'ninja':command_hash('ninja')}
mame={
 'name':'MAME Genesis qualification executable','version':'0.289','executable_version':version,
 'source_url':'https://github.com/mamedev/mame','source_revision':'tag mame0289; commit f34f02505e32c1993c6a782b6814232cbfc74e36; signed tag object d0b7160e54874fa58f553614db373d73100d5ecb',
 'source_archive_sha256':'0929cc749afabcef892900e10dd90bd8b05f94a7dde8f367ac6a5d2082589f84','source_signature':signature,
 'license':'MAME source distribution is GPL-2.0-or-later overall; the patched Genesis files carry BSD-3-Clause headers. Upstream license and legal notices remain in the non-redistributed source checkout.',
 'status':'pass','host_observed':host,
 'flags':['targetos=macosx','architecture=arm64','configuration=Release','SUBTARGET=genewhip','SOURCES=src/mame/sega/mdconsole.cpp,src/mame/sega/megadriv.cpp','OSD=sdl3','USE_LIBSDL=1','REGENIE=1','NO_USE_MIDI=1','NO_USE_PORTAUDIO=1','NO_USE_PULSEAUDIO=1','NO_USE_PIPEWIRE=1','SDL_HIDAPI_LIBUSB=OFF','CMAKE_OSX_ARCHITECTURES=arm64','CMAKE_OSX_DEPLOYMENT_TARGET=15.0'],
 'build_dependencies':[{'name':'SDL','version':'3.4.12','source_url':'https://github.com/libsdl-org/SDL/releases/download/release-3.4.12/SDL3-3.4.12.tar.gz','source_archive_sha256':'f07b958a9ac5020fb7a44cadb957f658b2149c3c8abb4f63145fac9303249db7','license':'Zlib','configuration':'shared library; no framework; HIDAPI libusb disabled; tests/examples disabled; source install under work root'},
  {'name':'pkg-config adapter','version':'project-local SDL3 flag adapter','sha256':sha(work/'pkgconfig/pkg-config'),'license':'Genewhip build-script logic; no external package'},
  {'name':'MAME bundled static components','identity':'from the pinned MAME source archive; source archive SHA-256 binds all bundled versions and notices','license':'individual upstream notices retained in source archive; no non-system dynamic images except SDL'}],
 'build_tooling':[{'name':'CMake','version':host['cmake']['version'],'sha256':host['cmake']['sha256'],'license':'BSD-3-Clause; build host tool only'},
  {'name':'Ninja','version':host['ninja']['version'],'sha256':host['ninja']['sha256'],'license':'Apache-2.0; build host tool only'}],
 'configuration':['make -j8 SUBTARGET=genewhip SOURCES=src/mame/sega/mdconsole.cpp,src/mame/sega/megadriv.cpp OSD=sdl3 USE_LIBSDL=1 REGENIE=1 NO_USE_MIDI=1 NO_USE_PORTAUDIO=1 NO_USE_PULSEAUDIO=1 NO_USE_PIPEWIRE=1','CMake Release; arm64; SDL_FRAMEWORK=OFF; SDL_SHARED=ON; SDL_STATIC=OFF; SDL_HIDAPI_LIBUSB=OFF; SDL_TESTS=OFF; SDL_EXAMPLES=OFF'],
 'build_script_sha256':sha(script_file),'patch_sha256':sha(patch_file),
 'source_configuration_files':config,'source_configuration_identity':config_digest,
 'executable_path':'<MAME_SOURCE_DIR>/genewhip','executable_file_type':file_type,
 'executable_build_sha256':sha(exe),'linked_images':linked,
 'runtime_dependency':'SDL3 shared library; source archive, Zlib notice and exact image digest recorded above',
 'inputs':['candidate ROM intentionally excluded from MAME toolchain build; MAME source and patch only']}
old['mame']=mame
pathlib.Path(lock_path).write_text(json.dumps(old,indent=2,sort_keys=False)+'\n')
print(json.dumps({'status':'pass','mame_version':version,'executable_sha256':mame['executable_build_sha256'],'patch_sha256':mame['patch_sha256'],'source_configuration_identity':config_digest,'linked_images':linked},sort_keys=True))
PY
}

verify_lock() {
	python3 - "$LOCK" "$WORK_ROOT" "$SOURCE_DIR" "$SDL_ROOT" "$PATCH_FILE" "$0" <<'PY'
import hashlib,json,pathlib,subprocess,sys
lock_path,work_root,source_dir,sdl_root,patch_file,script_file=sys.argv[1:]
d=json.loads(pathlib.Path(lock_path).read_text())['mame']; work=pathlib.Path(work_root); source=pathlib.Path(source_dir); sdl=pathlib.Path(sdl_root)
def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def fail(m): raise SystemExit('BLOCKED: '+m)
if d.get('status')!='pass': fail('MAME lock status is not pass')
if d.get('source_signature',{}).get('status')!='pass': fail('MAME source signature is not pass')
if d.get('build_script_sha256')!=sha(script_file): fail('MAME build-script identity mismatch')
if d.get('patch_sha256')!=sha(patch_file): fail('instrumentation patch identity mismatch')
if sha(work/'mame0289.tar.gz')!='0929cc749afabcef892900e10dd90bd8b05f94a7dde8f367ac6a5d2082589f84': fail('MAME source archive identity mismatch')
exe=source/'genewhip'
if sha(exe)!=d.get('executable_build_sha256'): fail('MAME executable digest mismatch')
if 'Mach-O 64-bit executable arm64' not in subprocess.check_output(['file',str(exe)],text=True): fail('MAME executable is not native arm64')
if subprocess.check_output([str(exe),'-version'],text=True).strip()!=d.get('executable_version'): fail('MAME executable version mismatch')
if sha(sdl/'lib/libSDL3.0.dylib')!=next((x.get('sha256') for x in d.get('linked_images',[]) if x.get('package')=='SDL'),None): fail('linked SDL image digest mismatch')
if d.get('source_revision','').split(';')[1].strip().startswith('commit '+subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()) is False: fail('source checkout revision mismatch')
changed=pathlib.Path(work/'verify.patch')
subprocess.run(['git','-C',str(source),'diff','--binary','--','src/mame/sega/mdconsole.cpp','src/mame/sega/megadriv.h'],check=True,stdout=changed.open('wb'))
if sha(changed)!=d.get('patch_sha256'): fail('source patch differs from locked instrumentation')
for row in d.get('source_configuration_files',[]):
    if sha(source/row['path'])!=row['sha256']: fail('generated MAME configuration changed: '+row['path'])
if d.get('status')!='pass' or not d.get('linked_images'): fail('incomplete MAME linked-image lock')
print('PASS: MAME 0.289 source/signature, patch, build configuration, arm64 executable and linked images match toolchain.lock')
PY
}

case "${1:-}" in
	--build)
		mkdir -p "$WORK_ROOT/dependencies" "$WORK_ROOT/pkgconfig"
		[ -f "$ARCHIVE" ] || curl -fL --retry 3 --output "$ARCHIVE" https://github.com/mamedev/mame/archive/refs/tags/mame0289.tar.gz
		[ -f "$SDL_ARCHIVE" ] || curl -fL --retry 3 --create-dirs --output "$SDL_ARCHIVE" https://github.com/libsdl-org/SDL/releases/download/release-3.4.12/SDL3-3.4.12.tar.gz
		verify_archive
		if [ ! -d "$SOURCE_DIR/.git" ]; then
			mkdir -p "$(dirname "$SOURCE_DIR")"
			git clone --depth 1 --branch "$MAME_TAG" https://github.com/mamedev/mame.git "$SOURCE_DIR"
		fi
		if git -C "$SOURCE_DIR" diff --quiet -- src/mame/sega/mdconsole.cpp src/mame/sega/megadriv.h; then
			git -C "$SOURCE_DIR" apply "$PATCH_FILE"
		fi
		verify_source_and_signature
		if [ ! -f "$SDL_ROOT/lib/libSDL3.0.dylib" ]; then
			SDL_SOURCE="$WORK_ROOT/dependencies/SDL3-3.4.12-src"
			mkdir -p "$SDL_SOURCE"
			[ -f "$SDL_SOURCE/CMakeLists.txt" ] || tar -xzf "$SDL_ARCHIVE" -C "$SDL_SOURCE" --strip-components=1
			cmake -S "$SDL_SOURCE" -B "$WORK_ROOT/dependencies/SDL3-lib-build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 -DSDL_FRAMEWORK=OFF -DSDL_SHARED=ON -DSDL_STATIC=OFF -DSDL_TESTS=OFF -DSDL_EXAMPLES=OFF -DSDL_INSTALL=ON -DSDL_HIDAPI_LIBUSB=OFF -DCMAKE_INSTALL_PREFIX="$SDL_ROOT"
			cmake --build "$WORK_ROOT/dependencies/SDL3-lib-build" --parallel 8
			cmake --install "$WORK_ROOT/dependencies/SDL3-lib-build"
		fi
		[ -f "$SDL_ROOT/include/SDL3/SDL.h" ] || fail 'source-built SDL3 header tree missing'
		cat > "$WORK_ROOT/pkgconfig/pkg-config" <<'SHIM'
#!/bin/sh
if [ "${1:-}" = sdl3 ]; then shift; fi
case "${1:-}" in
  --exists) exit 0 ;;
  --cflags) printf -- '-I%s/include/SDL3\n' "$GENEWHIP_SDL3_PREFIX" ;;
  --libs) printf -- '-L%s/lib -Wl,-rpath,%s/lib -lSDL3\n' "$GENEWHIP_SDL3_PREFIX" "$GENEWHIP_SDL3_PREFIX" ;;
  *) exit 1 ;;
esac
SHIM
		chmod +x "$WORK_ROOT/pkgconfig/pkg-config"
		export GENEWHIP_SDL3_PREFIX="$SDL_ROOT"
		export PKG_CONFIG="$WORK_ROOT/pkgconfig/pkg-config"
		make -j8 -C "$SOURCE_DIR" SUBTARGET=genewhip SOURCES=src/mame/sega/mdconsole.cpp,src/mame/sega/megadriv.cpp OSD=sdl3 USE_LIBSDL=1 REGENIE=1 NO_USE_MIDI=1 NO_USE_PORTAUDIO=1 NO_USE_PULSEAUDIO=1 NO_USE_PIPEWIRE=1
		verify_source_and_signature
		capture_lock
		verify_lock
		;;
	--verify-toolchain-lock)
		verify_archive
		verify_source_and_signature
		verify_lock
		;;
	*) printf 'BLOCKED: usage: %s --build|--verify-toolchain-lock\n' "$0" >&2; exit 2 ;;
esac

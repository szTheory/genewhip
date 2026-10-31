#!/bin/sh
# Supervisor-authored, offline RECURSION94 Linux-equivalent tool bootstrap.
# Inputs are exact-archive-SHA-verified by the caller before container launch.
set -eu
TOOLS=/work/src/.toolcache
mkdir -p "$TOOLS/bin" "$TOOLS/src" "$TOOLS/lib" "$TOOLS/identity"
exec >"$TOOLS/identity/setup.log" 2>&1
printf '%s  %s\n' \
  c84b2de1cbb87831795fe64a85c5d9a7002a766e3a7c30b0a2d7d5e99d878f49 /work/src/inputs/vasm2_0f.tar.gz \
  0203a01199b16660027fbe04b0a87dc5aff299401b5e3e49bff8468a3801cc54 /work/src/inputs/sjasmplus-1.23.1-src.tar.xz \
  9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 /work/src/inputs/zlib-1.3.1.tar.gz \
  15d9c623abfd2165fe816ea1fb385d6ed8cf3c664661ab357f1782e3036a6dac /work/src/inputs/Python-3.12.10.tgz \
  | sha256sum -c -
tar -xzf /work/src/inputs/vasm2_0f.tar.gz -C "$TOOLS/src"
tar -xJf /work/src/inputs/sjasmplus-1.23.1-src.tar.xz -C "$TOOLS/src"
tar -xzf /work/src/inputs/zlib-1.3.1.tar.gz -C "$TOOLS/src"
tar -xzf /work/src/inputs/Python-3.12.10.tgz -C "$TOOLS/src"
VAS="$TOOLS/src/vasm"
set --
for item in vasm.c atom.c expr.c symtab.c symbol.c error.c parse.c reloc.c hugeint.c cond.c listing.c source.c supp.c dwarf.c osdep.c output_test.c output_elf.c output_bin.c output_vobj.c output_hunk.c output_aout.c output_tos.c output_xfile.c output_srec.c output_cdef.c output_ihex.c output_o65.c output_gst.c output_woz.c output_pap.c output_hans.c output_coff.c output_aof.c cpus/m68k/cpu.c syntax/mot/syntax.c; do set -- "$@" "$VAS/$item"; done
gcc -O2 -std=c90 -I"$VAS" -I"$VAS/cpus/m68k" -I"$VAS/syntax/mot" \
  -DOUTAOF -DOUTAOUT -DOUTBIN -DOUTCOFF -DOUTELF -DOUTGST -DOUTHANS \
  -DOUTHUNK -DOUTIHEX -DOUTO65 -DOUTPAP -DOUTSREC -DOUTTOS -DOUTVOBJ \
  -DOUTWOZ -DOUTXFIL "$@" -lm -o "$TOOLS/bin/vasmm68k_mot.exe"
"$TOOLS/bin/vasmm68k_mot.exe" -v 2>&1 | grep -F 'vasm 2.0f'
cd "$TOOLS/src/sjasmplus-1.23.1"
make -j4 USE_LUA=0
cp sjasmplus "$TOOLS/bin/sjasmplus.exe"
"$TOOLS/bin/sjasmplus.exe" --version 2>&1 | grep -F '1.23.1'
cd "$TOOLS/src/zlib-1.3.1"
./configure --prefix="$TOOLS"
make -j4
# CPython's Makefile.pre.in defaults COMPILEALL_OPTS=-j0. Override that
# exact install-time bytecode parallelism with the policy's four-job ceiling.
make install
cd "$TOOLS/src/Python-3.12.10"
CPPFLAGS="-I$TOOLS/include" CFLAGS="-O2 -g0" \
  LDFLAGS="-L$TOOLS/lib -Wl,-rpath,$TOOLS/lib" \
  ./configure --prefix="$TOOLS/python" --with-ensurepip=no --disable-test-modules
make -j4
make -j1 install COMPILEALL_OPTS=-j4
PYTHONHOME="$TOOLS/python" "$TOOLS/python/bin/python3.12" -c \
  'import sys, zlib; assert sys.version_info[:3] == (3, 12, 10); assert zlib.ZLIB_VERSION == "1.3.1"'
cp -L "$TOOLS/lib/libz.so.1" "$TOOLS/lib/libz.so.1.real"
rm -f "$TOOLS/lib/libz.so" "$TOOLS/lib/libz.so.1"
mv "$TOOLS/lib/libz.so.1.real" "$TOOLS/lib/libz.so.1"
# Unused CPython install aliases and build-directory links are not part of the
# required runtime. Remove them before the strict regular-file exporter runs.
find "$TOOLS" -type l -delete
test -f "$TOOLS/bin/vasmm68k_mot.exe"
test -f "$TOOLS/bin/sjasmplus.exe"
test -f "$TOOLS/lib/libz.so.1"
test -f "$TOOLS/python/bin/python3.12"
sha256sum "$TOOLS/bin/vasmm68k_mot.exe" "$TOOLS/bin/sjasmplus.exe" \
  "$TOOLS/python/bin/python3.12" "$TOOLS/lib/libz.so.1" \
  > "$TOOLS/identity/native-tools.sha256"
rm -rf "$TOOLS/src"

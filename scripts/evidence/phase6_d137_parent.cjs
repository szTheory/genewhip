#!/usr/bin/env node
'use strict';

// D137's owned parent. Installation access in captureManifest is DATA only.
// No Python/project module is required, compiled, or launched by preparation.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');

const PHASE = '.planning/phases/GW-06-shared-repairs-and-two-playable-routes';
const EVIDENCE = `${PHASE}/d137-43-evidence`;
const BUILD = 'build/phase6/d137-43';
const PACKAGES = ['collections', 'ctypes', 'encodings', 'importlib', 'json', 're', 'urllib'];
const EXTENSIONS = ['_typing', 'math', 'select', 'fcntl', '_datetime', '_decimal', '_hashlib', '_json', '_struct', '_random', '_sha512', '_bisect', 'binascii', 'zlib', '_socket', 'array', '_ctypes', '_posixsubprocess', '_bz2', '_lzma', 'unicodedata', '_sha1', '_sha256', '_sha3', '_md5'];
const BUILTINS = 'sys builtins _imp _io _thread _warnings _weakref _abc _codecs _collections _functools _operator _sre _stat _string atexit errno gc itertools marshal posix time _locale _signal'.split(' ');
const FROZEN = '_frozen_importlib _frozen_importlib_external zipimport abc codecs io os _collections_abc stat genericpath posixpath ntpath importlib.util importlib.machinery importlib._bootstrap importlib._bootstrap_external'.split(' ');
const LIMITS = { source_files: 512, source_bytes: 32 * 1024 ** 2, extension_files: 25, extension_bytes: 128 * 1024 ** 2, identity_files: 3, identity_bytes: 16 * 1024 ** 2, entries: 768, directories: 32, total_bytes: 176 * 1024 ** 2, rows: 1536, manifest_bytes: 512 * 1024 };
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const now = () => process.hrtime.bigint();
const readJSON = p => JSON.parse(fs.readFileSync(p, 'utf8'));
function fail(code) { const e = new Error(code); e.code = code; throw e; }
function ensureDir(p) { fs.mkdirSync(p, { recursive: true, mode: 0o700 }); const s = fs.lstatSync(p); if (!s.isDirectory() || s.isSymbolicLink()) fail('OUTPUT_DIRECTORY'); }
function create(p, bytes) { const fd = fs.openSync(p, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600); try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); } }
function assertSame(a, b) { if (a.dev !== b.dev || a.ino !== b.ino || a.size !== b.size || a.mode !== b.mode || a.nlink !== b.nlink) fail('DATA_IDENTITY_CHANGED'); }
function verifySelection(root) {
  assert.equal(root, EVIDENCE);
  const selection = readJSON(`${root}/selection.json`);
  assert.equal(selection.schema, 'd137-route-selection-v1');
  assert.equal(selection.status, 'SELECTED');
  assert.deepEqual(selection.scheduling.serial_plans, ['06-43', '06-44', '06-45', '06-46']);
  for (const [p, h] of Object.entries(selection.checked_artifacts)) assert.equal(sha(fs.readFileSync(p)), h, p);
  const entry = readJSON(`${root}/entry.json`);
  assert.equal(sha(fs.readFileSync(`${root}/selection.json`)), entry.selection_sha256);
  assert.equal(entry.event, 'SOURCE_OWNER_DISPATCH');
  const elapsed = Number(now() - BigInt(entry.monotonic_ns)) / 1e9;
  if (elapsed < 0 || elapsed + entry.complete_remaining_forecast_seconds > entry.cap_seconds) fail('COMPLETE_REMAINING_FIT');
  assert.equal(sha(fs.readFileSync('evidence/phase6-repairs.json')), '18fd6dbc2f892e4aa5c4c1847adf3b272e6cc71e31f91093d8a6fe1dd6281e5a');
  return { selection, entry, elapsed };
}
function captureManifest(root, batch) {
  verifySelection(root);
  // One initial revision, five finite data batches. No hidden retry or enumeration.
  assert(Number.isInteger(batch) && batch >= 1 && batch <= 5);
  const retained = readJSON(`${PHASE}/d136-38-evidence/runtime.json`).candidate.private_locator;
  const keg = '/opt/homebrew/Cellar/python@3.11/3.11.7_1';
  const framework = `${keg}/Frameworks/Python.framework/Versions/3.11`;
  assert.equal(retained.keg, keg); assert.equal(retained.framework_root, framework);
  assert.equal(retained.executable, `${framework}/bin/python3.11`);
  const stdlib = `${framework}/lib/python3.11`;
  ensureDir(BUILD); ensureDir(`${BUILD}/capture`);
  const statePath = `${BUILD}/capture/batch-${batch}.json`;
  if (fs.existsSync(statePath)) fail('DATA_BATCH_ALREADY_ATTEMPTED');
  let state = { schema: 'd137-data-capture-v1', revision: 0, rows: [], directories: [], rejected: [], counts: Object.fromEntries(Object.keys(LIMITS).map(k => [k, 0])), first_monotonic_ns: now().toString(), status: 'CAPTURING', batches: [] };
  if (batch > 1) { state = readJSON(`${BUILD}/capture/batch-${batch - 1}.json`); assert.equal(state.status, 'BATCH_ACCEPTED'); }
  const started = now(); const fds = [];
  const charge = (key, n = 1) => { if (state.counts[key] + n > LIMITS[key]) fail(`DATA_BOUND_${key}`); state.counts[key] += n; };
  function timeGate() { if (Number(now() - started) / 1e9 > 55 || Number(now() - BigInt(state.first_monotonic_ns)) / 1e9 > 300) fail('DATA_PREPARATION_TIME_BOUND'); }
  const checkedDirs = new Map();
  function directory(p) {
    timeGate();
    if (checkedDirs.has(p)) return checkedDirs.get(p);
    const parent = path.dirname(p); if (parent !== p) directory(parent);
    const before = fs.lstatSync(p); if (!before.isDirectory() || before.isSymbolicLink()) fail('DATA_DIRECTORY_SYMLINK_OR_TYPE');
    const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_DIRECTORY);
    fds.push(fd); assertSame(before, fs.fstatSync(fd)); checkedDirs.set(p, { fd, before }); return checkedDirs.get(p);
  }
  function read(p, kind, id, module, pin) {
    timeGate(); directory(path.dirname(p));
    charge(`${kind}_files`);
    let before; try { before = fs.lstatSync(p); } catch (e) { if (e.code === 'ENOENT' && kind === 'extension') { state.rows.push({ id, module, kind, status: 'ABSENT_DENIED' }); return; } throw e; }
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) fail('DATA_LEAF_LINK_OR_TYPE');
    const max = kind === 'source' ? 2 * 1024 ** 2 : 16 * 1024 ** 2;
    if (before.size > max) fail('DATA_PER_FILE_BOUND'); charge(`${kind}_bytes`, before.size); charge('total_bytes', before.size);
    const fd = fs.openSync(p, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    let bytes; try { assertSame(before, fs.fstatSync(fd)); bytes = fs.readFileSync(fd); assertSame(before, fs.fstatSync(fd)); assertSame(before, fs.lstatSync(p)); } finally { fs.closeSync(fd); }
    if (bytes.length !== before.size) fail('DATA_SIZE_CHANGED');
    const digest = sha(bytes); if (pin && digest !== pin) fail('DATA_PIN_MISMATCH');
    if (state.rows.some(r => r.id === id || (module && r.module === module))) fail('DATA_DUPLICATE_ROW');
    const blob = `${BUILD}/capture/${digest}.blob`; if (!fs.existsSync(blob)) create(blob, bytes);
    state.rows.push({ id, module: module || null, package_parent: module ? module.split('.').slice(0, -1).join('.') || null : null, package: kind === 'source' && p.endsWith('/__init__.py'), kind, status: 'PRESENT_PIN', size: bytes.length, sha256: digest, identity: { device: before.dev, inode: before.ino, mode: before.mode, nlink: before.nlink }, captured_blob: blob });
    timeGate();
  }
  function enumerate(relative, depth, recursive) {
    timeGate(); const p = relative ? `${stdlib}/${relative}` : stdlib; const d = directory(p);
    if (recursive) { charge('directories'); state.directories.push(relative); }
    const names = fs.readdirSync(p).sort(); assertSame(d.before, fs.fstatSync(d.fd)); assertSame(d.before, fs.lstatSync(p));
    for (const name of names) {
      timeGate(); charge('entries');
      const rel = relative ? `${relative}/${name}` : name;
      if (/^[A-Za-z_][A-Za-z0-9_]*\.py$/.test(name)) { const mod = rel.replace(/\.py$/, '').replace(/\/__init__$/, '').replaceAll('/', '.'); read(`${stdlib}/${rel}`, 'source', `runtime:python311/lib/${rel}`, mod); }
      else if (recursive && /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && !['__pycache__', 'tests', 'test'].includes(name)) {
        const st = fs.lstatSync(`${stdlib}/${rel}`);
        if (st.isSymbolicLink()) fail('DATA_PACKAGE_SYMLINK');
        if (st.isDirectory()) { if (depth >= 4) fail('DATA_PACKAGE_DEPTH'); if (!fs.existsSync(`${stdlib}/${rel}/__init__.py`)) { state.rejected.push({ id: rel, reason: 'namespace-directory' }); continue; } enumerate(rel, depth + 1, true); }
        else state.rejected.push({ id: rel, reason: 'non-source-member' });
      } else state.rejected.push({ id: rel, reason: 'excluded-entry' });
    }
  }
  let error = null;
  try {
    if (batch === 1) {
      read(`${framework}/bin/python3.11`, 'identity', 'runtime:python311/bin/python3.11', null, '2f678d02a9f146ad8b1a48d21002e6a809678ccba66f0ec4eb7c8a901e802ab1');
      read(`${framework}/Python`, 'identity', 'runtime:python311/Python', null, '4900254f0823a95f206bbcff4b7694178b4bfd465c6cbbab3941704087ddaafe');
      read(`${keg}/INSTALL_RECEIPT.json`, 'identity', 'runtime:python311/INSTALL_RECEIPT.json', null, '45e18d93ecde7edda128e925775aaec9a52ebadeb66fe596ed829afca722c859');
      enumerate('', 0, false);
    } else if (batch === 2) { for (const p of PACKAGES.slice(0, 3)) enumerate(p, 1, true); }
    else if (batch === 3) { for (const p of PACKAGES.slice(3)) enumerate(p, 1, true); }
    else if (batch === 4) { for (const name of EXTENSIONS) read(`${stdlib}/lib-dynload/${name}.cpython-311-darwin.so`, 'extension', `runtime:python311/lib/lib-dynload/${name}.cpython-311-darwin.so`, name); }
    else {
      for (const [kind, names] of [['builtin_candidate', BUILTINS], ['frozen_candidate', FROZEN]]) for (const module of names) state.rows.push({ id: `runtime:python311/${kind}/${module}`, module, kind, status: 'DECLARED_UNPROVEN' });
    }
    state.counts.rows = state.rows.length; if (state.rows.length > LIMITS.rows) fail('DATA_BOUND_rows');
    state.status = 'BATCH_ACCEPTED'; timeGate();
  } catch (e) { error = e; state.status = 'HALTED'; state.failure = { code: e.code || 'DATA_CAPTURE_FAILURE', batch }; }
  finally { for (const fd of fds.reverse()) fs.closeSync(fd); }
  state.batches.push({ batch, at: new Date().toISOString(), elapsed_seconds: Number(now() - started) / 1e9, status: state.status });
  const bytes = JSON.stringify(state, null, 2) + '\n'; if (Buffer.byteLength(bytes) > LIMITS.manifest_bytes) fail('DATA_MANIFEST_BYTE_BOUND');
  create(statePath, bytes);
  if (batch === 5 || error) create(`${root}/runtime-manifest.json`, bytes);
  process.stdout.write(JSON.stringify({ batch, status: state.status, counts: state.counts, failure: state.failure || null }) + '\n');
  if (error) throw error;
  return state;
}

function runLane() { fail('SUBJECT_LANE_NOT_REVIEWED'); }
function checkRetained(root, name) { verifySelection(root); if (name === 'selection') return; fail('RETAINED_REVIEW_NOT_AVAILABLE'); }
function main(argv) {
  const value = flag => { const i = argv.indexOf(flag); return i < 0 ? null : argv[i + 1]; };
  const root = value('--evidence-root') || EVIDENCE;
  if (argv.includes('--prepare-data')) return captureManifest(root, Number(value('--batch')));
  if (argv.includes('--check')) return checkRetained(root, value('--check'));
  if (argv.includes('--lane')) return runLane();
  fail('EXPLICIT_PARENT_MODE_REQUIRED');
}
if (require.main === module) { try { main(process.argv.slice(2)); } catch (e) { process.stderr.write(`D137_PARENT_FAILURE:${/^[A-Z0-9_]+$/.test(e.code || '') ? e.code : 'FIXED_FAILURE'}\n`); process.exitCode = 1; } }
module.exports = { main, captureManifest, runLane, checkRetained };

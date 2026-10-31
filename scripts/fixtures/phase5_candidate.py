#!/usr/bin/env python3
"""Bounded, digest-pinned Phase 5 source/material and build supervisor."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "evidence"))
import phase5_records as records  # noqa: E402

DEFAULT_TEST_IMAGE = "alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b"
CONTAINER_USER = "65532:65532"
WORKSPACE = pathlib.Path("/work")
RECURSION_SETUP_RECIPE = "scripts/fixtures/phase5_recursion_setup.sh"
RECURSION_SETUP_RECIPE_SHA256 = "6e7e8f92c638aa4926213de5abd483e9d60c94f27a5760d3e04678c15707f4df"
RECURSION_SETUP_REQUIRED_OUTPUTS = (
    ".toolcache/bin/vasmm68k_mot.exe",
    ".toolcache/bin/sjasmplus.exe",
    ".toolcache/lib/libz.so.1",
    ".toolcache/python/bin/python3.12",
    ".toolcache/python/lib/python3.12/encodings/__init__.py",
    ".toolcache/python/lib/python3.12/lib-dynload/zlib.cpython-312-x86_64-linux-musl.so",
)
RECURSION_SETUP_LOG_OUTPUT = ".toolcache/identity/setup.log"


def _recursion_setup_wrapper(expected_script_sha256, *, workdir="/work/src",
                             enforce_address_limit=True):
    """Build a selective exporter that reports bounded setup logs on failure."""
    paths = " ".join(shlex.quote(path) for path in (
        ".toolcache/bin/vasmm68k_mot.exe", ".toolcache/bin/sjasmplus.exe",
        ".toolcache/lib/libz.so.1", ".toolcache/python/bin/python3.12",
        ".toolcache/python/lib/python3.12", ".toolcache/identity/native-tools.sha256",
        RECURSION_SETUP_LOG_OUTPUT))
    limit = "ulimit -v 8388608; " if enforce_address_limit else ""
    root = shlex.quote(workdir)
    return (f"set -eu; {limit}mkdir -p {root}; "
            f"tar -xf - -C {root}; cd {root}; "
            f"test \"$(sha256sum .phase5-setup.sh | cut -d ' ' -f1)\" = {expected_script_sha256}; "
            f"if /bin/sh .phase5-setup.sh; then tar -cf - {paths}; "
            f"else status=$?; if [ -f {RECURSION_SETUP_LOG_OUTPUT} ]; then "
            f"tail -c 262144 {RECURSION_SETUP_LOG_OUTPUT} >&2 || :; fi; "
            f"exit \"$status\"; fi")
RECURSION_SETUP_INPUTS = {
    "inputs/vasm2_0f.tar.gz": ("c84b2de1cbb87831795fe64a85c5d9a7002a766e3a7c30b0a2d7d5e99d878f49",
        "phase5-inputs/vasm2_0f.tar.gz"),
    "inputs/sjasmplus-1.23.1-src.tar.xz": ("0203a01199b16660027fbe04b0a87dc5aff299401b5e3e49bff8468a3801cc54",
        "phase5-inputs/sjasmplus-1.23.1-src.tar.xz"),
    "inputs/zlib-1.3.1.tar.gz": ("9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23",
        "phase5-inputs/zlib-1.3.1.tar.gz"),
    "inputs/Python-3.12.10.tgz": ("15d9c623abfd2165fe816ea1fb385d6ed8cf3c664661ab357f1782e3036a6dac",
        "phase5-inputs/Python-3.12.10.tgz"),
}


def _fresh_screening_fixture(screening):
    """Detach harmless tests from real title counters in the working ledger."""
    counters = {name: 0 for name in records.COUNTER_LIMITS}
    for candidate in screening["candidates"]:
        candidate["identity_history"] = []
        candidate["counters"] = dict(counters)
        candidate["state"] = "unattempted"
        candidate["outcome"] = "unknown"
    return records.validate_screening(screening)


class GateError(RuntimeError):
    pass


def _json(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def _atomic_json(path, document):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _confined(root, relative):
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise GateError("archive/material path is not a safe relative path")
    pure = pathlib.PurePosixPath(relative)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise GateError("archive/material path escapes its workspace")
    result = pathlib.Path(root).joinpath(*pure.parts)
    if not result.resolve(strict=False).is_relative_to(pathlib.Path(root).resolve()):
        raise GateError("archive/material path escapes its workspace")
    return result


def safe_extract(archive_path, destination, *, max_entries=20_000,
                 max_unpacked=1_073_741_824):
    """Extract regular files and confined links only, enforcing declared archive caps."""
    destination = pathlib.Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    total = 0
    count = 0
    with tarfile.open(archive_path, "r:*") as archive:
        for member in archive:
            count += 1
            if count > max_entries:
                raise GateError("source archive entry cap exceeded")
            target = _confined(destination, member.name)
            if member.issym() or member.islnk():
                link = pathlib.PurePosixPath(member.linkname)
                if link.is_absolute():
                    raise GateError("absolute archive link is forbidden")
                link_target = _confined(target.parent, str(link))
                if not link_target.resolve(strict=False).is_relative_to(destination):
                    raise GateError("archive link escapes its workspace")
                raise GateError("archive links are not admitted; materialize reviewed files explicitly")
            if not member.isfile() and not member.isdir():
                raise GateError("archive contains a special file")
            if member.isfile():
                total += member.size
                if total > max_unpacked:
                    raise GateError("source archive unpacked-byte cap exceeded")
                stream = archive.extractfile(member)
                if stream is None:
                    raise GateError("archive member could not be read")
                target.parent.mkdir(parents=True, exist_ok=True)
                remaining = member.size
                with target.open("xb") as output:
                    while remaining:
                        chunk = stream.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise GateError("truncated archive member")
                        output.write(chunk)
                        remaining -= len(chunk)
                target.chmod(member.mode & 0o755)
            else:
                target.mkdir(parents=True, exist_ok=True)
    return {"entries": count, "unpacked_bytes": total}


def _docker_endpoint(*, deadline=None):
    docker = shutil.which("docker")
    if docker is None:
        raise GateError("Docker CLI is unavailable")
    result = subprocess.run([docker, "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
                            text=True, capture_output=True,
                            timeout=deadline.timeout_seconds(5) if deadline else 5, check=False)
    endpoint = result.stdout.strip()
    if result.returncode or not endpoint.startswith("unix://"):
        raise GateError("Docker endpoint is unavailable or is not a local Unix socket")
    return docker, endpoint


def _docker_env(endpoint):
    # A fresh empty config prevents the controller CLI from consulting credential helpers.
    config = tempfile.mkdtemp(prefix="phase5-docker-config-")
    return ({"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": tempfile.gettempdir(),
             "TMPDIR": tempfile.gettempdir(), "LC_ALL": "C", "DOCKER_HOST": endpoint,
             "DOCKER_CONFIG": config}, config)


def _image_digest(docker, image, env, *, deadline=None):
    if not isinstance(image, str) or re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", image) is None:
        raise GateError("container image must be an exact repository@sha256 digest")
    inspected = subprocess.run([docker, "image", "inspect", image, "--format", "{{.Id}}"],
                               env=env, text=True, capture_output=True,
                               timeout=deadline.timeout_seconds(10) if deadline else 10, check=False)
    if inspected.returncode or re.fullmatch(r"sha256:[0-9a-f]{64}\s*", inspected.stdout) is None:
        raise GateError("pinned build image is not already present locally; no implicit pull is allowed")
    return inspected.stdout.strip()


def _verify_image_materials(image, image_id, materials, *, endpoint, policy=None, deadline=None):
    image_materials = [item for item in materials if item.get("origin", "workspace") == "image"]
    if not image_materials:
        return
    commands = []
    for item in image_materials:
        path = pathlib.PurePosixPath(item["path"])
        if (not path.is_absolute() or ".." in path.parts or not item.get("sha256")
                or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None):
            raise GateError("pinned toolchain image material has an invalid path or hash")
        quoted = shlex.quote(str(path))
        commands.append(f"test -f {quoted} || exit 41; actual=$(sha256sum {quoted}) || exit 42; "
                        f"actual=${{actual%% *}}; test \"$actual\" = {item['sha256']} || exit 43")
    script = "; ".join(commands) + "; echo PHASE5_IMAGE_MATERIALS_OK"
    docker, _ = _docker_endpoint(deadline=deadline)
    name = "phase5-image-inputs-" + uuid.uuid4().hex[:12]
    if policy is not None:
        command = _current_container_args(docker, name, policy)
        script = 'ulimit -v 8388608 || exit 49; ' + script
    else:
        command = _container_args(docker, name, work_size=16 * 1024 * 1024,
                                  memory="256m", cpus=1, tmpfs_size=1024 * 1024)
    command.extend(["--entrypoint", "/bin/sh", image, "-c", script])
    result = bounded_run(command, endpoint=endpoint, timeout_seconds=deadline.timeout_seconds(30) if deadline else 30,
                         stdout_cap=65536, stderr_cap=65536, container_name=name, deadline=deadline)
    if (result["returncode"] or result["stop_reason"]
            or b"PHASE5_IMAGE_MATERIALS_OK" not in result["stdout"]):
        raise GateError(f"reviewed toolchain image {image_id} material hashes did not verify")


def _container_args(docker, name, *, work_size=8_589_934_592,
                    pids=4, memory="8g", cpus=4, tmpfs_size=1_073_741_824,
                    address_space_bytes=8_589_934_592, remove=True, build_environment=None,
                    work_mount_mode='noexec'):
    build_environment = build_environment or {"PATH": "/usr/local/bin:/usr/bin:/bin"}
    args = [docker, "run", "--name", name, "--network", "none", "--read-only",
            "--user", CONTAINER_USER, "--pids-limit", str(pids), "--memory", memory,
            "--memory-swap", memory,
            "--cpus", str(cpus), "--cap-drop", "ALL", "--security-opt",
            "no-new-privileges", "--ulimit", "nofile=256:256",
            "--tmpfs", f"/work:rw,nosuid,nodev,{work_mount_mode},size={work_size},uid=65532,gid=65532,mode=0700",
            "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size={tmpfs_size},uid=65532,gid=65532,mode=0700",
            "--env", f"PATH={build_environment['PATH']}", "--env", "HOME=/work/home",
            "--env", "TMPDIR=/tmp", "--env", "LC_ALL=C"]
    for key, value in sorted(build_environment.items()):
        if key == "PATH":
            continue
        args.extend(["--env", f"{key}={value}"])
    if remove:
        args.append("--rm")
    return args


def bounded_run(argv, *, endpoint, timeout_seconds, stdout_cap, stderr_cap,
                container_name=None, workspace=None, workspace_cap=8_589_934_592, deadline=None):
    """Run only a Docker-contained command, stream-cap output, and reap on every stop."""
    docker, _ = _docker_endpoint(deadline=deadline)
    env, config = _docker_env(endpoint)
    started = time.monotonic()
    if deadline is not None:
        timeout_seconds = deadline.timeout_seconds(timeout_seconds)
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, start_new_session=True,
                               bufsize=0, close_fds=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    caps = {"stdout": stdout_cap, "stderr": stderr_cap}
    reason = None

    def stop_container():
        stopped = False
        if container_name:
            stopped = subprocess.run([docker, "kill", container_name], env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     timeout=3, check=False).returncode == 0
        if not stopped:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    process.terminate()
                except PermissionError:
                    pass

    try:
        while selector.get_map() or process.poll() is None:
            if time.monotonic() - started > timeout_seconds:
                reason = "time-cap"
                stop_container()
                break
            if workspace is not None and _tree_size(workspace, workspace_cap + 1) > workspace_cap:
                reason = "workspace-cap"
                stop_container()
                break
            for key, _ in selector.select(timeout=0.05):
                block = os.read(key.fileobj.fileno(), 64 * 1024)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                target = captured[key.data]
                target.extend(block)
                if len(target) > caps[key.data]:
                    reason = key.data + "-cap"
                    stop_container()
                    break
            if reason:
                break
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            stop_container()
            process.wait(timeout=5)
    finally:
        selector.close()
        shutil.rmtree(config, ignore_errors=True)
    return {"returncode": process.returncode, "stdout": bytes(captured["stdout"]),
            "stderr": bytes(captured["stderr"]), "elapsed_seconds": time.monotonic() - started,
            "stop_reason": reason}


def _tree_size(path, stop_after=None):
    total = 0
    root = pathlib.Path(path)
    if not root.exists():
        return 0
    for item in root.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
                if stop_after is not None and total >= stop_after:
                    return total
        except OSError:
            continue
    return total


def _quarantine_usage(root=None, *, stop_after=None):
    quarantine = pathlib.Path(root) if root is not None else ROOT / "local-fixtures" / "phase5"
    return _tree_size(quarantine, stop_after)


def _ensure_quarantine_capacity(limits, *, additional_bytes=0, root=None):
    cap = limits["total_quarantine_bytes"]
    if (not isinstance(additional_bytes, int) or isinstance(additional_bytes, bool)
            or additional_bytes < 0):
        raise GateError("quarantine reservation must be a nonnegative byte count")
    usage = _quarantine_usage(root, stop_after=cap + 1)
    if usage + additional_bytes > cap:
        raise GateError("whole phase5 quarantine would exceed its frozen aggregate disk cap")
    return usage


def _workspace_identity(path):
    path = pathlib.Path(path).resolve()
    entries = []
    for item in sorted(path.rglob("*")):
        if item.is_symlink():
            raise GateError("candidate workspace contains a symlink")
        if item.is_file():
            relative = item.relative_to(path).as_posix()
            entries.append({"path": relative, "mode": item.stat().st_mode & 0o755,
                            "sha256": hashlib.sha256(item.read_bytes()).hexdigest()})
    return hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _docker_capability_probe():
    docker, endpoint = _docker_endpoint()
    env, config = _docker_env(endpoint)
    try:
        image_id = _image_digest(docker, DEFAULT_TEST_IMAGE, env)
        info = subprocess.run([docker, "info", "--format", "{{.ServerVersion}}|{{.OSType}}"],
                              env=env, text=True, capture_output=True, timeout=10, check=False)
        if info.returncode or not info.stdout.strip().endswith("|linux"):
            raise GateError("Docker daemon is not a usable Linux isolation host")
        outside = pathlib.Path(tempfile.mkdtemp(prefix="phase5-outside-")) / "sentinel"
        outside.write_text("host-only-sentinel", encoding="ascii")
        env["GENEWHIP_SECRET_SENTINEL"] = "host-controller-only"
        name = "phase5-probe-" + uuid.uuid4().hex[:16]
        script = (
            "test \"$(id -u)\" = 65532 || exit 31; "
            "test ! -e \"$HOST_SENTINEL\" || exit 32; "
            "env | grep -q '^GENEWHIP_SECRET_SENTINEL=' && exit 33; "
            "test \"$(cat /sys/fs/cgroup/pids.max)\" = 4 || exit 34; "
            "test \"$(cat /sys/fs/cgroup/memory.max)\" = 67108864 || exit 35; "
            "test \"$(cat /sys/fs/cgroup/memory.swap.max)\" = 0 || exit 38; "
            "ulimit -v 65536 || exit 39; test \"$(ulimit -v)\" = 65536 || exit 40; "
            "busybox wget -T 1 -O /dev/null http://192.0.2.1/ >/dev/null 2>&1 && exit 36; "
            "dd if=/dev/zero of=/tmp/fill bs=1024 count=2048 2>/dev/null && exit 37; "
            "echo ENFORCEMENT_PROBE_OK"
        )
        command = _container_args(docker, name, work_size=16 * 1024 * 1024,
                                  memory="64m", cpus=1, tmpfs_size=1024 * 1024)
        command.extend(["--memory-swap", "64m", "--env", f"HOST_SENTINEL={outside}",
                        "--env", "HOME=/tmp/home", "--env", "TMPDIR=/tmp", "--env",
                        "LC_ALL=C", DEFAULT_TEST_IMAGE, "/bin/sh", "-c", script])
        probe = bounded_run(command, endpoint=endpoint, timeout_seconds=10, stdout_cap=65536,
                            stderr_cap=65536, container_name=name)
        shutil.rmtree(outside.parent, ignore_errors=True)
        output = probe["stdout"].decode("utf-8", "replace")
        if probe["returncode"] != 0 or probe["stop_reason"] or "ENFORCEMENT_PROBE_OK" not in output:
            raise GateError("Docker enforcement probe failed: " + probe["stderr"].decode("utf-8", "replace")[-1000:])
        return {"status": "enforced", "endpoint_kind": "local-unix", "image": DEFAULT_TEST_IMAGE,
                "image_id": image_id, "daemon": info.stdout.strip(),
                "checks": ["host-sentinel-unmounted", "environment-allowlist", "network-none",
                           "nonroot-uid", "pids-task-limit", "memory-limit", "memory-swap-limit",
                           "address-space-limit", "tmpfs-disk-limit"]}
    finally:
        shutil.rmtree(config, ignore_errors=True)


def _workspace_tar(workspace, archive_path):
    workspace = pathlib.Path(workspace).resolve()
    with tarfile.open(archive_path, "w") as archive:
        for item in sorted(workspace.rglob("*")):
            rel = item.relative_to(workspace).as_posix()
            _confined(pathlib.Path("/tmp/phase5-tar-check"), rel)
            if item.is_symlink():
                raise GateError("candidate workspace symlinks are not permitted in build input")
            if item.is_file():
                archive.add(item, arcname=rel, recursive=False)
            elif item.is_dir():
                archive.add(item, arcname=rel, recursive=False)


def _container_build(image, workspace, output_relative, *, limits, endpoint, invocation,
                     recipe_path="build.sh", recipe_args=(), build_environment=None,
                     current_config=None):
    docker, _ = _docker_endpoint()
    env, config = _docker_env(endpoint)
    container = "phase5-build-" + uuid.uuid4().hex[:16]
    archive_path = None
    tank_map = current_config is not None and current_config.get('title_id') == 'tank-battle'
    map_cap = limits['stdout_bytes_per_process'] if tank_map else 0
    try:
        image_id = _image_digest(docker, image, env)
        workspace = pathlib.Path(workspace).resolve()
        quarantine = (ROOT / "local-fixtures" / "phase5").resolve()
        if not workspace.is_dir() or not workspace.is_relative_to(quarantine):
            raise GateError("build workspace must be inside ignored local-fixtures/phase5 quarantine")
        _ensure_quarantine_capacity(limits)
        if not pathlib.PurePosixPath(output_relative).parts or any(
                part in (".", "..") for part in pathlib.PurePosixPath(output_relative).parts):
            raise GateError("build output path is invalid")
        output_path = _confined(workspace, output_relative)
        workspace_bytes = _tree_size(workspace, limits["active_workspace_bytes_per_title"] + 1)
        if workspace_bytes > limits["active_workspace_bytes_per_title"]:
            raise GateError("candidate workspace exceeds the declared disk cap before transfer")
        archive_entries = sum(1 for item in workspace.rglob("*") if item.is_file())
        reserve = (workspace_bytes + archive_entries * 1024 + limits["rom_bytes"] + map_cap
                   + limits["stderr_bytes_per_process"])
        _ensure_quarantine_capacity(limits, additional_bytes=reserve)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        archive_path = workspace.parent / ("input-" + invocation + ".tar")
        _workspace_tar(workspace, archive_path)
        archive_bytes = archive_path.stat().st_size
        if archive_bytes > limits["source_archive_unpacked_bytes"]:
            raise GateError("candidate source bundle exceeds the declared transfer cap")
        _ensure_quarantine_capacity(limits)
        if current_config is not None:
            command = _current_container_args(docker, container, records.amended_policy(),
                                              work_mount_mode=current_config['work_mount_mode'],
                                              native_tools=current_config['native_tools'],
                                              build_environment=build_environment)
        else:
            command = _container_args(docker, container, work_size=limits["active_workspace_bytes_per_title"],
                                  pids=limits["build_processes"],
                                  memory=str(limits["address_space_bytes_per_process"]),
                                  address_space_bytes=limits["address_space_bytes_per_process"],
                                  cpus=limits["build_processes"],
                                      build_environment=build_environment)
        quoted_output = shlex.quote(output_relative)
        if (not isinstance(recipe_path, str) or not recipe_path or
                pathlib.PurePosixPath(recipe_path).is_absolute() or
                any(part in (".", "..") for part in pathlib.PurePosixPath(recipe_path).parts)):
            raise GateError("build recipe path must be confined and relative")
        if not isinstance(recipe_args, list) or any(not isinstance(arg, str) for arg in recipe_args):
            raise GateError("build recipe arguments must be a string array")
        recipe = "./" + recipe_path
        command_line = " ".join(shlex.quote(part) for part in [recipe, *recipe_args])
        address_space_kib = limits["address_space_bytes_per_process"] // 1024
        native_checks = ''
        if current_config is not None:
            for tool in current_config['native_tools']:
                relative = tool['executable'].removeprefix('/work/src/')
                native_checks += (f"test \"$(sha256sum {shlex.quote(relative)} | cut -d ' ' -f1)\" = "
                                  f"{shlex.quote(tool['executable_sha256'])} || exit 48; ")
        wrapper = (f"ulimit -v {address_space_kib} || exit 49; "
                   "mkdir -p /work/src && tar -xf - -C /work/src && cd /work/src && "
                   + native_checks + "/bin/sh " + command_line + " >&2; status=$?; [ \"$status\" = 0 ] || exit \"$status\"; "
                   "tar -cf - -C /work/src " + quoted_output + (' out/link.map' if tank_map else ''))
        command.extend(["--interactive", "--workdir", "/work", "--entrypoint", "/bin/sh",
                        image, "-c", wrapper])
        with archive_path.open("rb") as archive_input:
            process = subprocess.Popen(command, stdin=archive_input, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=env, start_new_session=True, bufsize=0)
            result = _monitor_docker_process(process, endpoint=endpoint, container=container,
                                             workspace=workspace, limits=limits,
                                             stdout_cap=limits["rom_bytes"] + map_cap + 1024 * 1024)
        if result["returncode"] != 0 or result["stop_reason"]:
            return {**result, "image_id": image_id, "input_archive_bytes": archive_bytes,
                    "output": None}
        transfer = result.pop('stdout')
        map_output = {}
        if tank_map:
            data, link_map = _tar_tank_outputs(transfer, output_relative, limits['rom_bytes'], map_cap)
            map_path = _confined(workspace, 'out/link.map')
            _ensure_quarantine_capacity(limits, additional_bytes=len(data) + len(link_map))
            if _tree_size(workspace, limits['active_workspace_bytes_per_title'] + 1) + len(data) + len(link_map) > limits['active_workspace_bytes_per_title']:
                raise GateError('Tank ROM/map exceed the workspace cap')
            map_path.parent.mkdir(parents=True, exist_ok=True)
            map_path.write_bytes(link_map)
            map_output = {'link_map': {'path': str(map_path), 'bytes': len(link_map),
                                       'sha256': hashlib.sha256(link_map).hexdigest()}}
        else:
            data = _tar_single_file(transfer, pathlib.PurePosixPath(output_relative).name, limits['rom_bytes'])
            _ensure_quarantine_capacity(limits, additional_bytes=len(data))
        output_path.write_bytes(data)
        _ensure_quarantine_capacity(limits)
        return {**result, **map_output, "image_id": image_id, "input_archive_bytes": archive_bytes,
                "output": {"path": str(output_path), "bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest()}}
    finally:
        if archive_path is not None:
            archive_path.unlink(missing_ok=True)
        subprocess.run([docker, "rm", "-f", container], env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=5, check=False)
        shutil.rmtree(config, ignore_errors=True)


def _counted_recursion_setup(image, workspace, *, limits, endpoint, deadline,
                             setup_script, expected_script_sha256):
    """Run the reviewed RECURSION Linux tool bootstrap in its own counted container.

    This is deliberately separate from ROM invocations: it has the title's single
    setup deadline, and returns only a tar of declared tool outputs.  The caller
    verifies each extracted executable hash before it can enter a build config.
    """
    if hashlib.sha256(setup_script).hexdigest() != expected_script_sha256:
        raise GateError("RECURSION setup recipe identity mismatch")
    docker, _ = _docker_endpoint(deadline=deadline)
    env, docker_config = _docker_env(endpoint)
    name = "phase5-recursion-setup-" + uuid.uuid4().hex[:12]
    workspace = pathlib.Path(workspace).resolve()
    quarantine = (ROOT / "local-fixtures" / "phase5").resolve()
    if not workspace.is_dir() or not workspace.is_relative_to(quarantine):
        raise GateError("RECURSION setup workspace must remain in ignored local quarantine")
    archive_path = workspace.parent / "recursion-setup-input.tar"
    script_path = workspace / ".phase5-setup.sh"
    try:
        image_id = _image_digest(docker, image, env, deadline=deadline)
        if deadline.remaining_us() <= 0:
            raise GateError("RECURSION setup deadline expired before container launch")
        if script_path.exists():
            raise GateError("setup workspace already contains a bootstrap recipe")
        _ensure_quarantine_capacity(limits)
        script_path.write_bytes(setup_script)
        _workspace_tar(workspace, archive_path)
        if archive_path.stat().st_size > limits["source_archive_compressed_bytes"]:
            raise GateError("RECURSION setup input exceeds declared archive cap")
        command = _container_args(
            docker, name, work_size=records.amended_policy()["work_mount_bytes"],
            pids=64, memory="8589934592", cpus=4, tmpfs_size=1_073_741_824,
            address_space_bytes=8_589_934_592,
            build_environment={"PATH": "/usr/bin:/bin", "HOME": "/work/home",
                               "TMPDIR": "/tmp", "LC_ALL": "C"},
            work_mount_mode="exec")
        wrapper = _recursion_setup_wrapper(expected_script_sha256)
        command.extend(["--interactive", "--workdir", "/work", "--entrypoint", "/bin/sh",
                        image, "-c", wrapper])
        with archive_path.open("rb") as source_tar:
            process = subprocess.Popen(command, stdin=source_tar, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=env, start_new_session=True,
                                       bufsize=0)
            result = _monitor_docker_process(process, endpoint=endpoint, container=name,
                                             workspace=workspace, limits=limits,
                                             stdout_cap=256 * 1024 * 1024,
                                             deadline=deadline)
        retained = workspace.parent / 'recursion-setup-raw'
        retained.mkdir(parents=True, exist_ok=True)
        (retained / 'stdout.tar').write_bytes(result['stdout'])
        (retained / 'stderr.bin').write_bytes(result['stderr'])
        _atomic_json(retained / 'result.json', {
            'returncode': result['returncode'], 'stop_reason': result['stop_reason'],
            'elapsed_seconds': result['elapsed_seconds'],
            'stdout_bytes': result['stdout_bytes'], 'stdout_sha256': result['stdout_sha256'],
            'stderr_bytes': result['stderr_bytes'], 'stderr_sha256': result['stderr_sha256'],
            'image_id': image_id, 'setup_recipe_sha256': expected_script_sha256,
        })
        if result["returncode"] != 0 or result["stop_reason"]:
            raise GateError("counted RECURSION tool setup failed inside the bounded container")
        return {"image_id": image_id, "elapsed_us": deadline.elapsed_us(),
                "output_tar": result["stdout"], "stderr": result["stderr"],
                "setup_recipe_sha256": expected_script_sha256}
    finally:
        script_path.unlink(missing_ok=True)
        archive_path.unlink(missing_ok=True)
        shutil.rmtree(docker_config, ignore_errors=True)


def _extract_recursion_setup_outputs(data, destination):
    """Accept only the regular runtime and native outputs declared for setup."""
    destination = pathlib.Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    observed = {}
    allowed_files = (*RECURSION_SETUP_REQUIRED_OUTPUTS,
                     ".toolcache/identity/native-tools.sha256", RECURSION_SETUP_LOG_OUTPUT)
    python_root = ".toolcache/python/lib/python3.12"
    allowed_dirs = {
        ".toolcache", ".toolcache/bin", ".toolcache/lib", ".toolcache/identity",
        ".toolcache/python", ".toolcache/python/bin", ".toolcache/python/lib",
        python_root,
    }
    with tarfile.open(fileobj=__import__("io").BytesIO(data), mode="r:") as archive:
        for member in archive:
            path = pathlib.PurePosixPath(member.name)
            if (path.is_absolute() or any(part in ("", ".", "..") for part in path.parts)
                    or not path.parts or path.parts[0] != ".toolcache"):
                raise GateError("setup output escaped the declared tool-output directory")
            canonical_name = path.as_posix()
            expected_name = member.name.rstrip("/") if member.isdir() else member.name
            if canonical_name != expected_name:
                raise GateError("setup output member path is not canonical")
            allowed = (member.name in allowed_files or member.name == python_root
                       or member.name.startswith(python_root + "/"))
            if member.isdir():
                directory = member.name.rstrip("/")
                if (directory not in allowed_dirs
                        and not directory.startswith(python_root + "/")):
                    raise GateError("setup output contains an undeclared directory")
                continue
            if not allowed or not member.isfile() or member.name in observed:
                raise GateError("setup output contains a special or duplicate archive member")
            target = destination.joinpath(*path.parts)
            if not target.resolve().is_relative_to(destination):
                raise GateError("setup output path escapes quarantine")
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise GateError("setup output archive member is unreadable")
            content = stream.read(member.size + 1)
            if len(content) != member.size:
                raise GateError("setup output file is empty or truncated")
            if member.name in (*RECURSION_SETUP_REQUIRED_OUTPUTS,
                               ".toolcache/identity/native-tools.sha256",
                               RECURSION_SETUP_LOG_OUTPUT) and not content:
                raise GateError("required setup output file is empty")
            target.write_bytes(content)
            target.chmod(member.mode & 0o755)
            observed[member.name] = {"bytes": len(content),
                                     "sha256": hashlib.sha256(content).hexdigest()}
    missing = (set(RECURSION_SETUP_REQUIRED_OUTPUTS) | {RECURSION_SETUP_LOG_OUTPUT}) - set(observed)
    if missing:
        raise GateError("setup stage omitted required tool outputs: " + ", ".join(sorted(missing)))
    return observed


def _monitor_docker_process(process, *, endpoint, container, workspace, limits, stdout_cap=None,
                            deadline=None):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    caps = {"stdout": stdout_cap or limits["stdout_bytes_per_process"],
            "stderr": limits["stderr_bytes_per_process"]}
    start = time.monotonic()
    reason = None
    docker, _ = _docker_endpoint()
    env, config = _docker_env(endpoint)
    try:
        while selector.get_map() or process.poll() is None:
            if (deadline is not None and deadline.remaining_us() <= 0) or (
                    time.monotonic() - start > limits["build_invocation_seconds"]):
                reason = "time-cap"
            elif _tree_size(workspace, limits["active_workspace_bytes_per_title"] + 1) > limits["active_workspace_bytes_per_title"]:
                reason = "workspace-cap"
            if reason:
                stopped = subprocess.run([docker, "kill", container], env=env,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         timeout=3, check=False).returncode == 0
                if not stopped:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        try:
                            process.terminate()
                        except PermissionError:
                            pass
                break
            for key, _ in selector.select(timeout=0.05):
                block = os.read(key.fileobj.fileno(), 64 * 1024)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                captured[key.data].extend(block)
                if len(captured[key.data]) > caps[key.data]:
                    reason = key.data + "-cap"
                    break
            if reason:
                stopped = subprocess.run([docker, "kill", container], env=env,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         timeout=3, check=False).returncode == 0
                if not stopped:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        try:
                            process.terminate()
                        except PermissionError:
                            pass
                break
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except PermissionError:
                pass
            process.wait(timeout=5)
    finally:
        selector.close()
        shutil.rmtree(config, ignore_errors=True)
    return {"returncode": process.returncode, "stdout": bytes(captured["stdout"]),
            "stderr": bytes(captured["stderr"]),
            "stdout_bytes": len(captured["stdout"]),
            "stderr_bytes": len(captured["stderr"]), "stdout_sha256": hashlib.sha256(captured["stdout"]).hexdigest(),
            "stderr_sha256": hashlib.sha256(captured["stderr"]).hexdigest(),
            "elapsed_seconds": time.monotonic() - start, "stop_reason": reason}


def _tar_single_file(data, expected_name, byte_cap):
    if len(data) > byte_cap + 1024 * 1024:
        raise GateError("candidate output transfer exceeds ROM size plus tar header cap")
    with tarfile.open(fileobj=__import__("io").BytesIO(data), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) != 1 or not members[0].isfile() or pathlib.PurePosixPath(members[0].name).name != expected_name:
            raise GateError("candidate output transfer did not contain exactly the named regular file")
        if members[0].size <= 0 or members[0].size > byte_cap:
            raise GateError("candidate ROM is empty or exceeds its declared size cap")
        stream = archive.extractfile(members[0])
        output = stream.read(byte_cap + 1) if stream else b""
        if len(output) != members[0].size:
            raise GateError("candidate ROM transfer was truncated")
        return output


def _tar_tank_outputs(data, output_relative, rom_cap, map_cap):
    """Tank's unchanged recipe emits exactly these two bounded regular outputs."""
    expected = {output_relative: rom_cap, 'out/link.map': map_cap}
    output_name = pathlib.PurePosixPath(output_relative)
    if (output_name.is_absolute() or '..' in output_name.parts
            or output_name.as_posix() != output_relative):
        raise GateError('Tank ROM path must be confined and exact')
    if len(expected) != 2 or len(data) > rom_cap + map_cap + 1024 * 1024:
        raise GateError('Tank ROM/map transfer exceeds its aggregate cap')
    outputs = {}
    try:
        with tarfile.open(fileobj=__import__('io').BytesIO(data), mode='r:') as archive:
            # Iterate rather than loading an unbounded member inventory.
            for member in archive:
                if (member.name not in expected or member.name in outputs
                        or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)):
                    raise GateError('Tank transfer requires exactly the named regular ROM and linker map')
                if member.size <= 0 or member.size > expected[member.name]:
                    raise GateError('Tank ROM/map is empty or exceeds its size cap')
                stream = archive.extractfile(member)
                raw = stream.read(expected[member.name] + 1) if stream else b''
                if len(raw) != member.size:
                    raise GateError('Tank ROM/map transfer is truncated')
                outputs[member.name] = raw
            if len(data[archive.offset:]) < 1024 or any(data[archive.offset:]):
                raise GateError('Tank ROM/map transfer has trailing data')
    except tarfile.TarError as exc:
        raise GateError('Tank ROM/map transfer is invalid or truncated') from exc
    if set(outputs) != set(expected):
        raise GateError('Tank transfer requires both the ROM and linker map')
    return outputs[output_relative], outputs['out/link.map']


def _verify_tank_link_map(build):
    link_map = build.get('link_map')
    if not isinstance(link_map, dict):
        raise GateError('Tank build receipt requires a linker map')
    path = _confined(ROOT, link_map.get('quarantine_path'))
    if (not path.resolve().is_relative_to((ROOT / 'local-fixtures/phase5').resolve())
            or path.is_symlink() or not path.is_file()
            or path.parts[-2:] != ('out', 'link.map')):
        raise GateError('Tank linker map must be a confined regular out/link.map')
    size = path.stat().st_size
    if not 0 < size <= records.SCREENING_LIMITS['stdout_bytes_per_process']:
        raise GateError('Tank linker map is empty or exceeds its size cap')
    with path.open('rb') as stream:
        raw = stream.read(records.SCREENING_LIMITS['stdout_bytes_per_process'] + 1)
    if len(raw) != link_map.get('bytes_count') or hashlib.sha256(raw).hexdigest() != link_map.get('sha256'):
        raise GateError('Tank linker map identity mismatch')
    return link_map


def inspect_materials(candidate):
    return records.inspect_materials(candidate)


def build_pair(image, workspaces, output_relative, *, limits, endpoint, title_id,
               screening_path, identity, screen_already_started=False,
               recipe_path="build.sh", recipe_args=None, log_directory=None,
               build_environment=None, current_config=None):
    if len(workspaces) != 2:
        raise GateError("repeatability requires exactly two clean candidate workspaces")
    log_dir = (pathlib.Path(log_directory) if log_directory is not None else
               ROOT / "local-fixtures" / "phase5" / "logs" / title_id).resolve()
    screening = _json(screening_path)
    if any(_workspace_identity(workspace) != _workspace_identity(workspaces[0]) for workspace in workspaces[1:]):
        raise GateError("clean build workspaces do not contain identical pinned inputs")
    if not screen_already_started:
        screening = records.append_attempt(screening, title_id, "screen_started", identity)
        _atomic_json(screening_path, screening)
    receipts = []
    for ordinal, workspace in enumerate(workspaces, start=1):
        current = _json(screening_path)
        candidate_record = next(item for item in current["candidates"] if item["id"] == title_id)
        invocation_ordinal = candidate_record["counters"]["rom_build_invocations"] + 1
        if invocation_ordinal > limits["rom_build_invocations_per_title"]:
            raise GateError("candidate ROM build invocation cap exceeded")
        workspace = pathlib.Path(workspace)
        workspace_size = _tree_size(workspace,
                                    limits["active_workspace_bytes_per_title"] + 1)
        entries = sum(1 for item in workspace.rglob("*") if item.is_file())
        reservation = (workspace_size + entries * 1024 + limits["rom_bytes"]
                       + (limits['stdout_bytes_per_process'] if current_config is not None
                          and current_config.get('title_id') == 'tank-battle' else 0)
                       + limits["stderr_bytes_per_process"])
        _ensure_quarantine_capacity(limits, additional_bytes=reservation)
        current_identity = {**identity, "clean_build_ordinal": ordinal,
                            "title_invocation_ordinal": invocation_ordinal}
        screening = records.append_attempt(screening, title_id, "rom_build_invocation", current_identity)
        _atomic_json(screening_path, screening)
        result = _container_build(image, workspace, output_relative, limits=limits,
                                  endpoint=endpoint, invocation=f"{title_id}-{invocation_ordinal}",
                                  recipe_path=recipe_path, recipe_args=recipe_args or [],
                                  build_environment=build_environment, current_config=current_config)
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"build-{invocation_ordinal}.stderr"
        stderr_bytes = result.get("stderr", b"")
        _ensure_quarantine_capacity(limits, additional_bytes=(
            len(stderr_bytes) if isinstance(stderr_bytes, bytes) else 0))
        log_path.write_bytes(stderr_bytes if isinstance(stderr_bytes, bytes) else b"")
        if result.get("returncode") or result.get("stop_reason") or not result.get("output"):
            raise GateError(f"clean build {ordinal} failed: {result.get('stop_reason') or result.get('returncode')}; "
                            f"container stderr {stderr_bytes.decode('utf-8', 'replace')[-500:]}")
        quarantine = (ROOT / "local-fixtures" / "phase5").resolve()
        raw_path = pathlib.Path(result["output"]["path"]).resolve()
        if not raw_path.is_relative_to(quarantine):
            raise GateError("raw build output escaped the ignored local quarantine")
        receipts.append({"ordinal": ordinal, "invocation": invocation_ordinal,
                         "quarantine_path": raw_path.relative_to(ROOT).as_posix(),
                         "log_path": log_path.relative_to(ROOT).as_posix(),
                         "bytes": pathlib.Path(result["output"]["path"]).read_bytes(),
                         "sha256": result["output"]["sha256"], "bytes_count": result["output"]["bytes"],
                         "image_id": result["image_id"]})
        if current_config is not None and current_config.get('title_id') == 'tank-battle':
            link_map = result.get('link_map', {})
            map_path = pathlib.Path(link_map.get('path', '')).resolve()
            if not map_path.is_relative_to(quarantine):
                raise GateError('Tank linker map escaped quarantine')
            receipts[-1]['link_map'] = {'quarantine_path': map_path.relative_to(ROOT).as_posix(),
                                        'sha256': link_map.get('sha256'),
                                        'bytes_count': link_map.get('bytes')}
            _verify_tank_link_map(receipts[-1])
    comparison = records.compare_build_outputs(receipts)
    return {"builds": [{k: v for k, v in receipt.items() if k != "bytes"} for receipt in receipts],
            "comparison": comparison}


def _verify_eligibility(path):
    doc = _json(path)
    if pathlib.Path(path).name == 'phase5-eligibility-v2.json' and doc.get('schema') != records.ELIGIBILITY_V2:
        raise GateError('current eligibility path requires v2 ancestry')
    records.validate_current_eligibility(doc, pathlib.Path(path).resolve().parents[1])
    candidates = doc.get("candidates")
    if not isinstance(candidates, list) or [x.get("title_id") for x in candidates] != list(records.SCREENING_IDS):
        raise GateError("eligibility record must retain all five frozen titles in order")
    for candidate in candidates:
        material_review = inspect_materials(candidate)
        check = records.validate_eligibility(candidate)
        if candidate.get("decision") == "eligible" and (not check or not material_review["eligible"]):
            raise GateError(f"unresolved material was marked eligible: {candidate['title_id']}")
        for field in ("source_terms", "asset_terms", "font_music_terms", "runtime_terms",
                      "generated_rom_terms", "retained_notices", "pinned_inputs", "lineage_evidence"):
            if field not in candidate.get("review", {}):
                raise GateError(f"material review silently omitted {field} for {candidate['title_id']}")
    print(json.dumps({"schema": doc["schema"], "candidates": len(candidates),
                      "eligible": sum(c.get("decision") == "eligible" for c in candidates),
                      "unknown_or_rejected": sum(c.get("decision") != "eligible" for c in candidates)},
                     sort_keys=True))
    return True


def _verify_slot(slot, stage, eligibility_path):
    """Verify a promoted local slot directly, without manifest admission or execution."""
    eligibility = _json(eligibility_path)
    records.validate_current_eligibility(eligibility)
    slot_id = f"phase5-{slot}"
    entry = next((item for item in eligibility["candidates"]
                  if item.get("slot_id") == slot_id), None)
    if entry is None:
        raise GateError(f"{slot_id} has no promoted eligibility payload")
    if entry.get("decision") != "eligible" or not inspect_materials(entry)["eligible"]:
        raise GateError(f"{slot_id} material eligibility is unresolved")
    promotion = entry.get("promotion")
    if not isinstance(promotion, dict):
        raise GateError(f"{slot_id} promotion identities are missing")
    required = ("source_tree_sha256", "build_lock_sha256", "notices_sha256",
                "build_receipt_sha256") + (("rom_sha256",) if stage == 'complete' else ())
    for key in required:
        if not isinstance(promotion.get(key), str) or re.fullmatch(r"[0-9a-f]{64}", promotion[key]) is None:
            raise GateError(f"{slot_id} promotion identity is invalid: {key}")
    for key in ("source_tree_identity", "build_lock", "notices") + (("rom",) if stage == 'complete' else ()):
        relative = promotion.get(key)
        path = _confined(ROOT, relative)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != promotion[
                {"source_tree_identity": "source_tree_sha256", "build_lock": "build_lock_sha256",
                 "notices": "notices_sha256", "rom": "rom_sha256"}[key]]:
            raise GateError(f"{slot_id} promoted {key} is absent or hash-mismatched")
    if stage == "complete":
        route = entry.get("route_evidence")
        if not isinstance(route, dict) or route.get("canonical_rom_sha256") != promotion["rom_sha256"]:
            raise GateError(f"{slot_id} canonical ROM is not bound to frozen route evidence")
        if not route.get("frozen_route_sha256") or not route.get("reference_pair_sha256"):
            raise GateError(f"{slot_id} complete-stage route/reference identity is missing")
    print(json.dumps({"slot": slot_id, "stage": stage, "status": "verified",
                      "manifest_admission": "not_required", "execution": "not_performed"}, sort_keys=True))


def _documentary(ledger_path, eligibility_path):
    ledger = _json(ledger_path)
    if pathlib.Path(ledger_path).name == 'candidate-screening-v2.json' and ledger.get('schema') != records.SCREENING_V2:
        raise GateError('current ledger path requires v2 ancestry')
    records.validate_screening(ledger)
    eligibility = _json(eligibility_path)
    records.validate_current_eligibility(eligibility)
    if len(eligibility.get("candidates", [])) != len(records.SCREENING_IDS):
        raise GateError("documentary evidence must retain all five frozen leads")
    screened = {item["id"]: item for item in ledger["candidates"]}
    for item in eligibility.get("candidates", []):
        frozen = screened.get(item.get("title_id"))
        if (frozen is None or frozen.get("repository") != item.get("repository")
                or frozen.get("source_revision") != item.get("source_revision")
                or frozen.get("lineage_id") != item.get("lineage_id")):
            raise GateError("documentary source identity differs from the frozen screening ledger")
        review = item.get("review", {})
        if not isinstance(review.get("source_evidence"), list) or not review["source_evidence"]:
            raise GateError(f"source evidence links are missing for {item['title_id']}")
        material_review = inspect_materials(item)
        if item.get("decision") == "eligible" and not material_review["eligible"]:
            raise GateError(f"rights/material gate rejected incomplete eligibility: {item['title_id']}")
        if item.get("decision") != "eligible" and not item.get("unverified_categories"):
            raise GateError(f"unknown material categories were not preserved for {item['title_id']}")
    _verify_eligibility(eligibility_path)
    print("Documentary inventory validated; reviewed-source dispositions remain bound to evidence.")


def _repeatable_build_reported(item):
    # Later reference dispositions must not erase the earlier build stage.
    # This is selection metadata; _verify_build_pair still checks actual bytes.
    repeatable = item.get('post_build_checks', {}).get('repeatable_build')
    return (repeatable is True or (repeatable is None
            and item.get('state') == 'build-screened' and item.get('outcome') == 'pass'))


def _select_next_candidate(ledger, eligibility):
    ledger_by_id = {item["id"]: item for item in ledger["candidates"]}
    eligibility_by_id = {item["title_id"]: item for item in eligibility["candidates"]}
    viable = [title_id for title_id in records.SCREENING_IDS
              if _repeatable_build_reported(ledger_by_id[title_id])]
    viable_lineages = {eligibility_by_id[title_id].get("lineage_id") for title_id in viable
                       if eligibility_by_id[title_id].get("lineage_id")}
    if len(viable_lineages) >= 2:
        return None, "two distinct source lineages have repeatable build receipts"
    if ledger.get('schema') == records.SCREENING_V2:
        continuation = records.setup_continuation_state(ledger)
        if continuation['state'] in ('failed', 'in-flight'):
            return None, 'Tank shared-toolchain continuation failed/interrupted; no unchanged-toolchain reserve retry'
        tank = ledger_by_id['tank-battle']
        if 'tank-battle' not in viable:
            if (continuation['state'] == 'completed'
                    and records.validate_eligibility(eligibility_by_id['tank-battle'])
                    and tank['counters']['rom_build_invocations'] == 0):
                return 'tank-battle', 'reuse already charged Tank screen and completed continuation'
            return None, 'Tank continuation/material/repeatable-build gate is not qualified'
        candidate = eligibility_by_id['recursion94']
        recursion = ledger_by_id['recursion94']
        correction_retry = (
            recursion.get('state') == 'build-setup-blocked'
            and recursion.get('outcome') == 'infrastructure-error'
            and recursion['counters']['full_screens'] == 1
            and recursion['counters']['build_environment_corrections'] == 1
            and recursion['counters']['rom_build_invocations'] == 0
            and _recursion_d114_retry_available(ledger, recursion))
        if (records.validate_eligibility(candidate)
                and (recursion['counters']['full_screens'] == 0 or correction_retry)):
            return 'recursion94', 'conditional independent lineage after viable Tank builds'
        # The other documented fallbacks remain blocked until an explicit
        # title-specific disposition establishes a different supported path.
        return None, 'preferred independent lineage lacks exact rights/tool/build eligibility'

    def available(title_id):
        candidate = eligibility_by_id[title_id]
        frozen = ledger_by_id[title_id]
        return (records.validate_eligibility(candidate)
                and frozen["counters"]["full_screens"] == 0
                and frozen.get("state") == "unattempted")

    for title_id in records.SCREENING_IDS:
        frozen = ledger_by_id[title_id]
        candidate = eligibility_by_id[title_id]
        has_pending_screen = (frozen["counters"]["full_screens"] == 1
                              and frozen["counters"]["rom_build_invocations"] == 0
                              and frozen.get("state") == "unattempted"
                              and frozen.get("outcome") == "unknown"
                              and records.validate_eligibility(candidate)
                              and not any(event.get("event") in
                                          ("build_setup_completed", "build_setup_failed")
                                          for event in frozen["identity_history"]))
        if has_pending_screen:
            return title_id, "resume already-accounted pending setup"

    for title_id in records.SCREENING_IDS[:2]:
        if available(title_id):
            return title_id, "next documentary-eligible primary"

    missing_primaries = [title_id for title_id in records.SCREENING_IDS[:2]
                         if title_id not in viable]
    if not missing_primaries:
        return None, "all primary lineages have repeatable build receipts"
    missing_tank = "tank-battle" in missing_primaries
    if missing_tank and available("space-shooter"):
        return "space-shooter", "documented same-lineage replacement for unavailable Tank Battle"
    for title_id in records.SCREENING_IDS[3:]:
        candidate = eligibility_by_id[title_id]
        if (available(title_id)
                and candidate.get("lineage_id") not in viable_lineages):
            return title_id, "distinct-lineage reserve for unavailable primary"
    return None, "no eligible primary or permitted reserve remains"


RECURSION_PRELAUNCH_METADATA_FAILURE = hashlib.sha256(
    b'pinned toolchain image material has an invalid path or hash').hexdigest()


def _recursion_setup_correction_event(candidate):
    """Return the one permitted, exact prelaunch metadata correction event."""
    history = candidate.get('identity_history', [])
    failures = [event for event in history if event.get('event') == 'build_setup_failed']
    corrections = [event for event in history if event.get('event') == 'build_environment_correction']
    if (len(failures) == 2 and len(corrections) == 1
            and failures[-1].get('sha256') == _json(ROOT / RECURSION_SETUP_AUTHORIZATION).get(
                'prior_recursion_event_sha256')):
        failures = failures[:1]
    if (len(failures) != 1 or len(corrections) != 1
            or failures[0].get('details', {}).get('failure_sha256') != RECURSION_PRELAUNCH_METADATA_FAILURE
            or corrections[0].get('details', {}).get('failure_event_sha256') != failures[0].get('sha256')
            or corrections[0].get('details', {}).get('correction') != 'image-material-sha256-transcription'):
        return None
    return corrections[0]


def _recursion_d114_retry_available(ledger, candidate):
    if (candidate.get('state') != 'build-setup-blocked'
            or candidate.get('outcome') != 'infrastructure-error'
            or (ROOT / RECURSION_SETUP_ATTEMPT).exists()):
        return False
    try:
        _recursion_setup_authorization_bindings(ledger)
    except (GateError, OSError, ValueError):
        return False
    return _recursion_setup_correction_event(candidate) is not None


RECURSION_SETUP_AUTHORIZATION = 'evidence/phase5-recursion-setup-authorization.json'
RECURSION_SETUP_ATTEMPT = 'evidence/phase5-recursion-setup-attempt.json'
RECURSION_SETUP_REMAINING_US = 1573190865
RECURSION_SETUP_AUTHORIZATION_SHA256 = 'b2d90b1c28346353bfde121be39e0bb3a80e5d4ea1e689a372e1fefd0a04a587'


def _recursion_setup_authorization_bindings(ledger):
    authorization_path = ROOT / RECURSION_SETUP_AUTHORIZATION
    failed_path = ROOT / 'evidence/phase5-recursion-setup-failure.json'
    proposal_path = ROOT / '.planning/phases/GW-05-candidate-admission-and-baseline/05-10-CONTINUATION.md'
    authorization = _json(authorization_path)
    if hashlib.sha256(authorization_path.read_bytes()).hexdigest() != RECURSION_SETUP_AUTHORIZATION_SHA256:
        raise GateError('D-114 authorization record bytes changed')
    row = next(item for item in ledger['candidates'] if item['id'] == 'recursion94')
    history = row.get('identity_history', [])
    failures = [event for event in history if event.get('event') == 'build_setup_failed']
    corrections = [event for event in history if event.get('event') == 'build_environment_correction']
    if (len(failures) != 2 or len(corrections) != 1
            or failures[0].get('details', {}).get('failure_sha256') != RECURSION_PRELAUNCH_METADATA_FAILURE
            or corrections[0].get('details', {}).get('failure_event_sha256') != failures[0].get('sha256')
            or corrections[0].get('details', {}).get('correction') != 'image-material-sha256-transcription'):
        raise GateError('D-114 requires the exact previously consumed RECURSION setup correction')
    if (not row['identity_history']
            or row['identity_history'][-1].get('sha256') != authorization.get('prior_recursion_event_sha256')):
        raise GateError('D-114 prior RECURSION event binding changed')
    expected = {
        'schema': 'genewhip-phase5-recursion-setup-authorization-v1',
        'title_id': 'recursion94', 'setup_attempts_authorized': 1,
        'additional_corrections_authorized': 0,
        'prior_setup_elapsed_us': 226809135,
        'remaining_setup_budget_us': RECURSION_SETUP_REMAINING_US,
        'cumulative_setup_ceiling_us': 1800000000,
        'prior_counters': {'full_screens': 1, 'build_environment_corrections': 1,
                           'route_authoring_corrections': 0, 'reference_harness_corrections': 0,
                           'rom_build_invocations': 0},
        'proposal_sha256': hashlib.sha256(proposal_path.read_bytes()).hexdigest(),
        'prior_ledger_sha256': hashlib.sha256((ROOT / 'fixtures/candidate-screening-v2.json').read_bytes()).hexdigest(),
        'prior_recursion_event_sha256': authorization['prior_recursion_event_sha256'],
        'failed_setup_record_sha256': hashlib.sha256(failed_path.read_bytes()).hexdigest(),
    }
    for key, value in expected.items():
        if authorization.get(key) != value:
            raise GateError('D-114 authorization binding changed: ' + key)
    if row['counters'] != authorization['prior_counters']:
        raise GateError('D-114 prior screening counters changed')
    return authorization, hashlib.sha256(authorization_path.read_bytes()).hexdigest(), corrections[0]['sha256']


def _consume_recursion_setup_authorization(ledger, config, eligibility_path):
    authorization, authorization_sha256, correction_sha256 = _recursion_setup_authorization_bindings(ledger)
    path = ROOT / RECURSION_SETUP_ATTEMPT
    ledger_sha = hashlib.sha256((ROOT / 'fixtures/candidate-screening-v2.json').read_bytes()).hexdigest()
    event = {'kind': 'started', 'ordinal': 1, 'authorization_sha256': authorization_sha256,
             'prior_ledger_sha256': ledger_sha, 'correction_event_sha256': correction_sha256,
             'failed_setup_record_sha256': authorization['failed_setup_record_sha256'],
             'config_sha256': records.identity_digest(config),
             'eligibility_sha256': hashlib.sha256(pathlib.Path(eligibility_path).read_bytes()).hexdigest(),
             'remaining_setup_budget_us': RECURSION_SETUP_REMAINING_US}
    event['sha256'] = records.identity_digest(event)
    document = {'schema': 'genewhip-phase5-recursion-setup-attempt-v1',
                'authorization_sha256': authorization_sha256, 'events': [event]}
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('x', encoding='utf-8') as stream:
            json.dump(document, stream, indent=2, ensure_ascii=False)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise GateError('D-114 authorization has already been consumed or interrupted') from exc
    return document


def _finish_recursion_setup_authorization(document, *, success, elapsed_us, reason=None):
    if (document.get('schema') != 'genewhip-phase5-recursion-setup-attempt-v1'
            or len(document.get('events', [])) != 1
            or document['events'][0].get('kind') != 'started'):
        raise GateError('D-114 attempt receipt is not in its one-use in-flight state')
    started = document['events'][0]
    terminal = {'kind': 'completed' if success else 'failed', 'ordinal': 2,
                'previous_sha256': started['sha256'], 'authorization_sha256': document['authorization_sha256'],
                'elapsed_us': max(0, int(elapsed_us)),
                'success': bool(success)}
    if reason:
        terminal['reason_sha256'] = hashlib.sha256(reason.encode()).hexdigest()
    terminal['sha256'] = records.identity_digest(terminal)
    document['events'].append(terminal)
    _atomic_json(ROOT / RECURSION_SETUP_ATTEMPT, document)


def _record_recursion_setup_correction(ledger_path, eligibility_path, config_path):
    """Record only the authorized repair for the observed prelaunch image-hash typo."""
    ledger, eligibility, _, _ = _current_prerequisites(ledger_path, eligibility_path,
                                                        ROOT / 'fixtures/phase5-policy-v2.json')
    config, _ = _validate_build_config(config_path, 'recursion94')
    candidate = next(item for item in eligibility['candidates'] if item['title_id'] == 'recursion94')
    row = next(item for item in ledger['candidates'] if item['id'] == 'recursion94')
    failures = [event for event in row['identity_history'] if event.get('event') == 'build_setup_failed']
    if (row.get('state') != 'build-setup-blocked' or row.get('outcome') != 'infrastructure-error'
            or row['counters']['full_screens'] != 1 or row['counters']['rom_build_invocations'] != 0
            or row['counters']['build_environment_corrections'] != 0 or len(failures) != 1
            or failures[0].get('details', {}).get('failure_sha256') != RECURSION_PRELAUNCH_METADATA_FAILURE
            or any(event.get('event') in ('build_setup_completed', 'build_pair_completed', 'build_pair_failed')
                   for event in row['identity_history'])
            or not records.validate_eligibility(candidate) or not inspect_materials(candidate)['eligible']):
        raise GateError('RECURSION setup correction is outside the one exact prelaunch metadata failure')
    identity = {'operation': 'correct-reviewed-image-material-identity',
                'title_id': 'recursion94', 'failed_event_sha256': failures[0]['sha256'],
                'config_sha256': records.identity_digest(config),
                'eligibility_sha256': hashlib.sha256(pathlib.Path(eligibility_path).read_bytes()).hexdigest(),
                'corrected_material': '/bin/busybox',
                'corrected_sha256': next(item['sha256'] for item in candidate['materials']
                                         if item.get('origin') == 'image' and item['path'] == '/bin/busybox')}
    ledger = records.append_attempt(ledger, 'recursion94', 'build_environment_correction', identity,
                                    details={'failure_event_sha256': failures[0]['sha256'],
                                             'correction': 'image-material-sha256-transcription',
                                             'candidate_setup_launched': False, 'rom_builds': 0})
    row = next(item for item in ledger['candidates'] if item['id'] == 'recursion94')
    row.update(state='unattempted', outcome='unknown',
               reason='One authorized prelaunch image-material hash correction recorded; setup retry not yet run')
    records.validate_screening(ledger)
    _atomic_json(ledger_path, ledger)
    print(json.dumps({'status': 'corrected', 'title_id': 'recursion94',
                      'build_environment_corrections': row['counters']['build_environment_corrections'],
                      'rom_build_invocations': row['counters']['rom_build_invocations']}, sort_keys=True))


def _validate_build_config(path, expected_title):
    config_path = pathlib.Path(path).resolve()
    quarantine = (ROOT / "local-fixtures" / "phase5").resolve()
    if not config_path.is_relative_to(quarantine):
        raise GateError("build configuration must be kept in ignored local-fixtures/phase5")
    config = _json(config_path)
    current = config.get('schema') == 'genewhip-phase5-build-config-v2'
    if not current and config.get("schema") != "genewhip-phase5-build-config-v1":
        raise GateError("unknown candidate build configuration schema")
    if config.get("title_id") != expected_title:
        raise GateError(f"selected title is {expected_title}; build configuration names {config.get('title_id')}")
    if not isinstance(config.get("build_image"), str) or re.fullmatch(
            r"[^@\s]+@sha256:[0-9a-f]{64}", config["build_image"]) is None:
        raise GateError("candidate build image must be pinned by repository and sha256 digest")
    workspaces = config.get("workspaces")
    if not isinstance(workspaces, list) or len(workspaces) != 2:
        raise GateError("build configuration requires exactly two clean workspaces")
    resolved = []
    for relative in workspaces:
        workspace = _confined(ROOT, relative).resolve()
        if not workspace.is_relative_to(quarantine) or not workspace.is_dir():
            raise GateError("each clean build workspace must exist inside local quarantine")
        resolved.append(workspace)
    output_relative = config.get("output_relative")
    output_path = pathlib.PurePosixPath(output_relative or "")
    if (not output_relative or output_path.is_absolute()
            or any(part in (".", "..") for part in output_path.parts)):
        raise GateError("build output must be a confined relative path")
    recipe = config.get("build_recipe")
    if not isinstance(recipe, dict) or set(recipe) != {"path", "args"}:
        raise GateError("build_recipe must declare exactly a relative path and string arguments")
    if (not isinstance(recipe["path"], str) or not recipe["path"]
            or pathlib.PurePosixPath(recipe["path"]).is_absolute()
            or any(part in (".", "..") for part in pathlib.PurePosixPath(recipe["path"]).parts)
            or not isinstance(recipe["args"], list)
            or any(not isinstance(arg, str) for arg in recipe["args"])):
        raise GateError("build recipe path or arguments are invalid")
    build_environment = config.get("build_environment")
    if not isinstance(build_environment, dict) or not isinstance(build_environment.get("PATH"), str):
        raise GateError("build configuration must declare the exact in-image tool PATH")
    for key, value in build_environment.items():
        if (not re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
                or key in {"HOME", "TMPDIR", "LC_ALL", "LD_PRELOAD", "BASH_ENV", "ENV"}
                or not isinstance(value, str)
                or "\x00" in value or "\n" in value):
            raise GateError("build environment contains a reserved name or non-constant value")
    path_entries = build_environment["PATH"].split(":")
    if any(not part.startswith("/") or ".." in pathlib.PurePosixPath(part).parts
           for part in path_entries):
        raise GateError("tool PATH entries must be absolute image paths without traversal")
    required = {"schema", "title_id", "source_revision", "build_image", "workspaces",
                "output_relative", "build_recipe", "build_environment"}
    extra = {'policy_sha256', 'migration_sha256', 'linux_tasks_per_container', 'cpus_per_container',
             'concurrent_build_jobs', 'work_mount_mode', 'native_tools', 'job_policy',
             'recipe_sha256', 'makefiles', 'initialization_probe', 'initialization_tool_sha256',
             'preparation_receipts', 'setup_outputs', 'recursion_setup',
             'setup_receipt_sha256'} if current else set()
    if not required.issubset(config) or set(config) - required - {"setup_receipt"} - extra:
        raise GateError("build configuration contains unknown or missing fields")
    if 'recursion_setup' in config:
        setup = config['recursion_setup']
        if (expected_title != 'recursion94' or not isinstance(setup, dict)
                or set(setup) != {'workspace'}):
            raise GateError('RECURSION setup declaration has an unsupported shape')
        setup_workspace = _confined(ROOT, setup['workspace']).resolve()
        if (not setup_workspace.is_relative_to(quarantine)
                or setup_workspace in resolved or not setup_workspace.parent.is_relative_to(quarantine)):
            raise GateError('RECURSION setup workspace must be a separate ignored quarantine directory')
    if expected_title == 'recursion94' and 'recursion_setup' not in config:
        raise GateError('RECURSION build config requires its one counted setup stage')
    if current:
        _validate_current_config(config, resolved)
        if config.get('native_tools'):
            receipt_path = ROOT / 'evidence/phase5-recursion-setup.json'
            receipt = _json(receipt_path)
            if (hashlib.sha256(receipt_path.read_bytes()).hexdigest() != config.get('setup_receipt_sha256')
                    or receipt.get('schema') != 'genewhip-phase5-recursion-setup-v1'
                    or receipt.get('title_id') != expected_title or receipt.get('status') != 'pass'
                    or receipt.get('setup_outputs') != config.get('setup_outputs')):
                raise GateError('RECURSION native tools lack their exact successful counted setup receipt')
    return config, resolved


def _verify_build_inputs(workspaces, candidate, config):
    expected = {item["path"]: item for item in candidate["materials"]
                if item.get("origin", "workspace") == "workspace"}
    if config.get("source_revision") != candidate.get("source_revision"):
        raise GateError("build configuration source revision differs from reviewed eligibility")
    if config.get("build_image") != candidate.get("build_image"):
        raise GateError("build image differs from the reviewed eligibility image pin")
    revisions = candidate.get('material_source_revisions')
    source_pins = lambda value: (isinstance(value, str) and (
        re.fullmatch(r'[0-9a-f]{40}', value) is not None
        or re.fullmatch(r'sha256:[0-9a-f]{64}', value) is not None))
    if (not isinstance(revisions, list) or not revisions
            or any(not source_pins(revision) for revision in revisions)
            or len(set(revisions)) != len(revisions)
            or candidate.get('source_revision') not in revisions
            or candidate.get('toolchain_source_revision') not in revisions):
        raise GateError('material inventory requires exact reviewed game revision and toolchain source/archive pins')
    for item in candidate['materials']:
        if (item.get('origin', 'workspace') not in ('workspace', 'image')
                or item.get('source_revision') not in revisions):
            raise GateError('material inventory source revision is not reviewed')
    identities = []
    recipe_path = config["build_recipe"]["path"]
    setup_outputs = config.get('setup_outputs', {})
    if not isinstance(setup_outputs, dict):
        raise GateError('counted setup output inventory must be an object')
    for workspace in workspaces:
        actual = {}
        for item in sorted(workspace.rglob("*")):
            if item.is_symlink():
                raise GateError("candidate workspace contains a symlink")
            if item.is_file():
                actual[item.relative_to(workspace).as_posix()] = hashlib.sha256(item.read_bytes()).hexdigest()
        for relative, digest in setup_outputs.items():
            generated = _confined(workspace, relative)
            if (re.fullmatch(r'[0-9a-f]{64}', str(digest)) is None
                    or not generated.is_file()
                    or hashlib.sha256(generated.read_bytes()).hexdigest() != digest):
                raise GateError('counted setup output is missing or has a changed hash')
        reviewed_inputs = {path: digest for path, digest in actual.items()
                           if path not in setup_outputs}
        if reviewed_inputs != {path: item["sha256"] for path, item in expected.items()}:
            raise GateError("workspace bytes differ from the exhaustive reviewed material inventory")
        if recipe_path not in actual:
            raise GateError("declared build recipe is absent from reviewed inputs")
        if _tree_size(workspace, records.SCREENING_LIMITS["active_workspace_bytes_per_title"] + 1) > records.SCREENING_LIMITS["active_workspace_bytes_per_title"]:
            raise GateError("candidate workspace exceeds its frozen disk cap")
        if (workspace / config["output_relative"]).exists():
            raise GateError("clean build workspace already contains the requested output")
        identities.append(_workspace_identity(workspace))
    if identities[0] != identities[1]:
        raise GateError("the two clean workspaces do not have identical reviewed input identities")
    return identities[0]


def _screen_setup_identity(ledger, candidate, config, config_path):
    identity = {"operation": "reviewed-toolchain-setup", "title_id": candidate["title_id"],
                "image": config["build_image"], "source_revision": candidate["source_revision"]}
    frozen = next(item for item in ledger["candidates"] if item["id"] == candidate["title_id"])
    prior_screens = [event for event in frozen["identity_history"]
                     if event.get("event") == "screen_started"]
    receipt_ref = config.get("setup_receipt")
    if prior_screens:
        if len(prior_screens) != 1 or not isinstance(receipt_ref, dict):
            raise GateError("resume requires the exact setup receipt for the already-consumed screen")
        relative = receipt_ref.get("path")
        receipt_path = _confined(ROOT, relative)
        quarantine = (ROOT / "local-fixtures" / "phase5").resolve()
        if not receipt_path.resolve().is_relative_to(quarantine):
            raise GateError("setup receipt must stay in local quarantine")
        raw = receipt_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != receipt_ref.get("sha256"):
            raise GateError("setup receipt hash does not match the build configuration")
        prior_identity = json.loads(raw)
        expected_keys = {"operation", "title_id", "image", "source_revision", "started"}
        if set(prior_identity) != expected_keys or prior_identity.get("operation") != identity["operation"]:
            raise GateError("setup receipt has unexpected fields")
        for key in ("title_id", "image", "source_revision"):
            if prior_identity.get(key) != identity[key]:
                raise GateError(f"setup receipt {key} differs from frozen candidate/configuration")
        if records.identity_digest(prior_identity) != prior_screens[0]["identity_sha256"]:
            raise GateError("setup receipt identity does not match the consumed screen event")
        return prior_identity, False
    started = {**identity, "started": datetime.now(timezone.utc).isoformat()}
    receipt_path = pathlib.Path(config_path).resolve().parent / "setup-start.json"
    _atomic_json(receipt_path, started)
    return started, True


def _screen_next(ledger_path, eligibility_path, build_config_path):
    _documentary(ledger_path, eligibility_path)
    ledger = _json(ledger_path)
    eligibility = _json(eligibility_path)
    if ledger.get('schema') == records.SCREENING_V2:
        return _screen_current(ledger_path, eligibility_path, build_config_path)
    print(json.dumps({'status': 'blocked', 'reason': 'historical v1 screening is read-only; current executions require v2'}))
    return False


def _self_test():
    capability = _docker_capability_probe()
    docker, endpoint = _docker_endpoint()
    limits = records.SCREENING_LIMITS
    test_root = ROOT / "local-fixtures" / "phase5" / ("self-test-" + uuid.uuid4().hex[:12])
    test_root.mkdir(parents=True, exist_ok=False)
    try:
        source = "#!/bin/sh\nmkdir -p out\nprintf 'phase5-harmless-source-output\\n' > out/rom.bin\n"
        workspaces = []
        for ordinal in (1, 2):
            workspace = test_root / f"clean-{ordinal}"
            workspace.mkdir()
            build = workspace / "build.sh"
            build.write_text(source, encoding="ascii")
            build.chmod(0o755)
            workspaces.append(workspace)
        ledger_path = test_root / "screening.json"
        _atomic_json(ledger_path, _fresh_screening_fixture(
            _json(ROOT / "fixtures" / "candidate-screening.json")))
        build_receipt = build_pair(DEFAULT_TEST_IMAGE, workspaces, "out/rom.bin", limits=limits,
                                   endpoint=endpoint, title_id="tank-battle", screening_path=ledger_path,
                                   identity={"source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                                             "toolchain_sha256": hashlib.sha256(DEFAULT_TEST_IMAGE.encode()).hexdigest()})
        if build_receipt["comparison"]["status"] != "byte-identical" or len(build_receipt["builds"]) != 2:
            raise GateError("harmless source did not produce two isolated raw identities and an equality receipt")
        current = _json(ledger_path)
        tank = next(item for item in current["candidates"] if item["id"] == "tank-battle")
        if tank["counters"]["rom_build_invocations"] != 2 or tank["counters"]["full_screens"] != 1:
            raise GateError("screen/build counters did not persist for both isolated identities")
    finally:
        shutil.rmtree(test_root, ignore_errors=True)
    name = "phase5-pids-" + uuid.uuid4().hex[:16]
    command = _container_args(docker, name, work_size=16 * 1024 * 1024,
                              memory="64m", cpus=1, tmpfs_size=1024 * 1024)
    command.extend(["--memory-swap", "64m", "--entrypoint", "/bin/sh",
                    DEFAULT_TEST_IMAGE, "-c", "for i in 1 2 3 4 5 6; do /bin/sleep 1 & done; wait"])
    pids = bounded_run(command, endpoint=endpoint, timeout_seconds=5, stdout_cap=4096,
                       stderr_cap=4096, container_name=name)
    if pids["returncode"] != 2 or b"can't fork" not in pids["stderr"]:
        raise GateError("process-count cap did not reject the harmless excess-child probe")
    name = "phase5-as-limit-" + uuid.uuid4().hex[:16]
    command = _container_args(docker, name, work_size=16 * 1024 * 1024,
                              pids=16, memory="64m", cpus=1, tmpfs_size=1024 * 1024,
                              address_space_bytes=32 * 1024 * 1024)
    command.extend(["--entrypoint", "/bin/sh", DEFAULT_TEST_IMAGE, "-c",
                    "ulimit -v 32768 || exit 30; busybox awk 'BEGIN { value=sprintf(\"%100000000s\", \"x\"); print \"AS_LIMIT_NOT_ENFORCED\" }'"])
    as_limit = bounded_run(command, endpoint=endpoint, timeout_seconds=10, stdout_cap=4096,
                           stderr_cap=4096, container_name=name)
    if (as_limit["returncode"] == 0 or as_limit["stop_reason"]
            or b"AS_LIMIT_NOT_ENFORCED" in as_limit["stdout"]):
        raise GateError("harmless virtual-address allocation exceeded its enforced process limit")
    name = "phase5-output-" + uuid.uuid4().hex[:16]
    command = _container_args(docker, name, work_size=16 * 1024 * 1024,
                              memory="64m", cpus=1, tmpfs_size=1024 * 1024)
    command.extend(["--memory-swap", "64m"])
    command.extend(["--entrypoint", "/bin/sh", DEFAULT_TEST_IMAGE, "-c", "yes output"])
    over = bounded_run(command, endpoint=endpoint, timeout_seconds=10, stdout_cap=4096,
                       stderr_cap=4096, container_name=name)
    if over["stop_reason"] != "stdout-cap":
        raise GateError("streaming stdout cap did not terminate the harmless runaway child")
    name = "phase5-timeout-" + uuid.uuid4().hex[:16]
    command = _container_args(docker, name, work_size=16 * 1024 * 1024,
                              memory="64m", cpus=1, tmpfs_size=1024 * 1024)
    command.extend(["--memory-swap", "64m"])
    command.extend(["--entrypoint", "/bin/sh", DEFAULT_TEST_IMAGE, "-c", "sleep 30"])
    timed = bounded_run(command, endpoint=endpoint, timeout_seconds=0.5, stdout_cap=4096,
                        stderr_cap=4096, container_name=name)
    if timed["stop_reason"] != "time-cap":
        raise GateError("wall-clock cap did not terminate the harmless sleeping child")
    env, config = _docker_env(endpoint)
    try:
        inspect = subprocess.run([docker, "inspect", name], env=env, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=3, check=False)
        if inspect.returncode == 0:
            state = subprocess.run([docker, "inspect", "--format", "{{.State.Running}}", name],
                                   env=env, text=True, capture_output=True, timeout=3, check=False)
            if state.stdout.strip() == "true":
                raise GateError("container child survived its wall-clock cap")
            subprocess.run([docker, "rm", "-f", name], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=3, check=False)
    finally:
        shutil.rmtree(config, ignore_errors=True)
    with tempfile.TemporaryDirectory(prefix="phase5-archive-test-") as temporary:
        bad = pathlib.Path(temporary) / "bad.tar"
        with tarfile.open(bad, "w") as archive:
            import io
            item = tarfile.TarInfo("../escape")
            item.size = 1
            archive.addfile(item, io.BytesIO(b"x"))
        try:
            safe_extract(bad, pathlib.Path(temporary) / "target")
        except (GateError, tarfile.TarError):
            pass
        else:
            raise GateError("archive traversal member was accepted")
        if (pathlib.Path(temporary) / "escape").exists():
            raise GateError("archive traversal wrote outside its extraction root")
    print(json.dumps({"status": "PASS", "isolation": capability,
                      "source_to_output": build_receipt,
                      "process_cap": "excess child creation refused", "output_cap": over["stop_reason"],
                      "time_cap": timed["stop_reason"], "archive_traversal": "rejected"}, sort_keys=True))



class SetupDeadline:
    """One monotonic deadline shared by all child operations, never per child."""
    def __init__(self, remaining_us, *, now_ns=time.monotonic_ns):
        if not records.within_limit(remaining_us, 1800000000):
            raise GateError('setup deadline budget is invalid')
        self.now_ns = now_ns
        self.started_ns = now_ns()
        self.budget_us = remaining_us

    def elapsed_us(self):
        elapsed = self.now_ns() - self.started_ns
        if elapsed < 0:
            raise GateError('monotonic setup deadline clock moved backwards')
        return (elapsed + 999) // 1000

    def remaining_us(self):
        return max(0, self.budget_us - self.elapsed_us())

    def timeout_seconds(self, ceiling):
        left = self.remaining_us()
        if left <= 0:
            raise GateError('cumulative setup deadline exhausted')
        return min(ceiling, left / 1000000)


def _validate_native_tools(tools, mode):
    if mode not in ('noexec', 'exec') or not isinstance(tools, list):
        raise GateError('native executable mount declaration is invalid')
    if mode == 'exec' and not tools:
        raise GateError('exec /work requires declared native tools')
    if mode == 'noexec' and tools:
        raise GateError('native tools cannot execute on declared noexec /work')
    seen = set()
    for tool in tools:
        if not isinstance(tool, dict) or set(tool) != {'executable', 'executable_sha256', 'inputs', 'command'}:
            raise GateError('native tool must bind exact input/output/path/command identities')
        path, inputs, command = tool['executable'], tool['inputs'], tool['command']
        if (not isinstance(path, str) or not path.startswith('/work/src/')
                or '..' in pathlib.PurePosixPath(path).parts or path in seen
                or re.fullmatch('[0-9a-f]{64}', str(tool['executable_sha256'])) is None
                or not isinstance(inputs, dict) or not inputs
                or not isinstance(command, list) or not command or command[0] != path
                or any(not isinstance(arg, str) or '\x00' in arg for arg in command)):
            raise GateError('native tool executable identity/path/command is invalid')
        for relative, digest in inputs.items():
            _confined(ROOT, relative)
            if re.fullmatch('[0-9a-f]{64}', str(digest)) is None:
                raise GateError('native tool input identity is invalid')
        seen.add(path)


def _validate_job_policy(job, environment):
    if (not isinstance(job, dict) or set(job) != {'scheduler', 'jobs', 'command'}
            or job.get('scheduler') != 'gnu-make'
            or not records.within_limit(job.get('jobs'), 4) or job.get('jobs') == 0):
        raise GateError('unsupported scheduler or build job count')
    expected_flag = '-j' + str(job['jobs'])
    command = job.get('command')
    if (not isinstance(command, list) or len(command) < 4
            or command[:3] != ['make', expected_flag, '-f']
            or any(not isinstance(arg, str) or re.fullmatch('[A-Za-z0-9_./-]+', arg) is None
                   for arg in command[3:])
            or any(arg.startswith('-') or '=' in arg for arg in command[3:])):
        raise GateError('build jobs require explicit bounded make -jN -f file [targets]')
    if environment.get('MAKEFLAGS', expected_flag) != expected_flag:
        raise GateError('unbounded/overridden MAKEFLAGS or inherited jobserver is forbidden')
    if any(key in environment for key in ('GNUMAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'MAKEOVERRIDES')):
        raise GateError('build jobserver/override environment is forbidden')
    return job


def _validate_recipe_commands(raw, native_tools):
    """Support a deliberately small reviewed make grammar, fail closed otherwise.

    No shell indirection, recursive make, interpreter recipes or generated
    executable paths can silently turn an exec mount into blanket permission.
    Broader upstream build systems require a reviewed flattened recipe first.
    """
    declared = [tool['command'] for tool in native_tools]
    image_tools = {'/usr/bin/m68k-elf-gcc', '/usr/bin/m68k-elf-as', '/usr/bin/m68k-elf-ld',
                   '/usr/bin/m68k-elf-objcopy', '/usr/bin/gcc', '/usr/bin/as', '/usr/bin/ld',
                   '/usr/bin/java', '/opt/jre-minimal/bin/java', '/bin/mkdir', '/bin/cp', '/bin/rm'}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.lstrip().startswith('#'):
            continue
        if any(token in line for token in ('`', '$(', '${', ';', '&', '|', '<', '>', '\\')):
            raise GateError('unsupported shell/make indirection in job/native recipe')
        if '$' in line.replace('$@', '').replace('$^', ''):
            raise GateError('unsupported make variable in job/native recipe')
        if line.startswith('\t'):
            command = shlex.split(line[1:])
            if not command:
                continue
            if command[0].startswith('/work/'):
                if command not in declared:
                    raise GateError('undeclared native executable path/command in reviewed recipe')
            elif command[0] not in image_tools:
                raise GateError('unsupported image executable/interpreter in reviewed recipe')
            if any(arg.startswith(('-fplugin', '-wrapper', '--plugin', '@')) for arg in command[1:]):
                raise GateError('undeclared native compiler plugin/wrapper/response execution')
        elif ':' not in line or '=' in line:
            raise GateError('unsupported make definition outside reviewed literal targets')


def _current_container_args(docker, name, policy, *, work_mount_mode='noexec',
                            native_tools=None, build_environment=None, remove=True):
    policy = records.effective_policy(policy)
    _validate_native_tools(native_tools or [], work_mount_mode)
    return _container_args(docker, name, work_size=policy['work_mount_bytes'],
                           pids=policy['linux_tasks_per_container'],
                           memory=str(policy['aggregate_container_memory_bytes']),
                           cpus=policy['cpus_per_container'], tmpfs_size=policy['tmp_mount_bytes'],
                           address_space_bytes=policy['address_space_bytes_per_process'],
                           build_environment=build_environment, remove=remove,
                           work_mount_mode=work_mount_mode)


ENFORCEMENT_CONTROLS = {
    'task-process-cap64', 'task-thread-cap64', 'four-jobs-fifth-queued',
    'declared-native-exec', 'work-noexec', 'tmp-noexec', 'timeout-descendants',
    'output-descendants', 'uid-gid', 'network-none', 'read-only-root',
    'capabilities-nnp', 'host-unmounted', 'secret-env-absent', 'cpu-quota4',
    'memory8g-swap0', 'address-space8g', 'smaller-memory-rejection',
    'smaller-as-rejection', 'workspace-disk', 'output-cap', 'archive-cap',
    'policy-config-negative-controls',
}


ENFORCEMENT_IDENTITY_FILES = (
    'scripts/fixtures/phase5_candidate.py', 'tools/evidence/phase5_records.py',
    'tests/evidence/phase5_build_contract.py', 'tests/evidence/phase5_admission_contract.py',
    'tests/evidence/fixtures/phase5_sandbox_probe.c', 'fixtures/phase5-policy-v2.json',
    'evidence/phase5-policy-migration.json',
)


def _enforcement_identities():
    return {f: hashlib.sha256((ROOT / f).read_bytes()).hexdigest() for f in ENFORCEMENT_IDENTITY_FILES}


def _verify_enforcement_document(document, *, producer_identities=None):
    if (document.get('schema') != 'genewhip-phase5-enforcement-v2'
            or document.get('status') != 'pass'
            or document.get('policy_sha256') != records.identity_digest(records.amended_policy())
            or document.get('identities') != (producer_identities if producer_identities is not None
                                               else _enforcement_identities())):
        raise GateError('enforcement receipt missing, failed or stale for current code/policy')
    controls = document.get('controls', {})
    if set(controls) != ENFORCEMENT_CONTROLS or any(
            not isinstance(value, dict) or value.get('status') != 'pass'
            or not value.get('observations') for value in controls.values()):
        raise GateError('enforcement receipt has missing/skipped/forged required controls')
    if document.get('candidate_execution') is not False or document.get('elapsed_us', 180000001) > 180000000:
        raise GateError('enforcement receipt has invalid scope/watchdog')
    policy = records.amended_policy()
    if document.get('requested') != {k: policy[k] for k in (
            'linux_tasks_per_container', 'cpus_per_container', 'concurrent_build_jobs',
            'aggregate_container_memory_bytes', 'swap_bytes', 'address_space_bytes_per_process')}:
        raise GateError('enforcement requested/effective policy mismatch')
    for name, control in controls.items():
        observation = control['observations']
        if not isinstance(observation, dict):
            raise GateError('enforcement observation is not a named assertion')
        if name in ('task-process-cap64', 'task-thread-cap64'):
            valid = (observation.get('max') == observation.get('current') == 64
                     and observation.get('denied') == 11 and observation.get('created', 0) > 0
                     and observation.get('peak') in (-1, 64))
        elif name == 'four-jobs-fifth-queued':
            events = observation.get('events', [])
            valid = (observation.get('starts') == 5 and observation.get('max_active') == 4
                     and observation.get('fifth_queued') is True and len(events) == 10
                     and {e[1] for e in events if e[0] == 'start'} == set('abcde')
                     and {e[1] for e in events if e[0] == 'finish'} == set('abcde')
                     and max(e[2] for e in events) == 4
                     and any(e[0] == 'finish' for e in events[:5]))
        elif name == 'declared-native-exec':
            valid = (observation.get('binary_sha256') == document.get('probe_binary_sha256')
                     and re.fullmatch('[0-9a-f]{64}', str(document.get('probe_binary_sha256'))) is not None
                     and observation.get('sentinel') is True)
        elif name in ('work-noexec', 'tmp-noexec'):
            valid = observation == {'denied_exit': 126, 'sentinel_absent': True}
        elif name in ('timeout-descendants', 'output-descendants'):
            valid = observation == {'stop_reason': 'time-cap' if name.startswith('timeout') else 'stdout-cap',
                                    'descendant_started': True, 'running_after_stop': False}
        elif name == 'policy-config-negative-controls':
            valid = observation == {'offline_suites': 2, 'exit_codes': [0, 0]}
        elif name == 'archive-cap':
            valid = observation == {'unpacked_limit': 1, 'attempted_bytes': 2, 'denied': True}
        elif name == 'output-cap':
            valid = observation == {'stop_reason': 'stdout-cap', 'cap_bytes': 4096}
        elif name == 'workspace-disk':
            valid = observation == {'tmpfs_bytes': 1048576, 'attempted_bytes': 2097152, 'denied': True}
        elif name == 'smaller-as-rejection':
            valid = observation == {'address_space_kib': 1048576, 'allocation_denied': True}
        elif name == 'smaller-memory-rejection':
            valid = observation == {'memory_bytes': 268435456, 'oom_killed': True, 'allocation_reached': True}
        else:
            valid = (observation.get('asserted_in_production_container') is True
                     and re.fullmatch('[0-9a-f]{64}', str(observation.get('output_sha256'))) is not None)
        if not valid:
            raise GateError('enforcement named observation rejected: ' + name)
    return document


def _verify_enforcement(path):
    document = _verify_enforcement_document(_json(path))
    print(json.dumps({'status': 'verified', 'controls': len(document['controls']),
                      'policy_sha256': document['policy_sha256']}, sort_keys=True))
    return document


def enforcement_self_test():
    """Bounded local capability lane. Never initializes candidate tools or ROMs."""
    import base64
    deadline = SetupDeadline(180000000)
    policy = records.amended_policy()
    receipt = {'schema': 'genewhip-phase5-enforcement-v2', 'status': 'blocked',
               'candidate_execution': False, 'policy_sha256': records.identity_digest(policy),
               'identities': _enforcement_identities(), 'controls': {},
               'requested': {k: policy[k] for k in ('linux_tasks_per_container', 'cpus_per_container',
                            'concurrent_build_jobs', 'aggregate_container_memory_bytes', 'swap_bytes',
                            'address_space_bytes_per_process')},
               'measurement': 'pids.current is a sample; pids.peak is kernel peak only when available'}
    directory = ROOT / 'local-fixtures/phase5' / ('enforcement-' + uuid.uuid4().hex[:12])
    directory.mkdir(parents=True)
    def passed(name, observation):
        receipt['controls'][name] = {'status': 'pass', 'observations': observation}
    try:
        for test, mode in (('phase5_admission_contract.py', '--self-test'),
                           ('phase5_build_contract.py', '--policy-self-test')):
            result = subprocess.run([sys.executable, '-I', str(ROOT / 'tests/evidence' / test), mode],
                                    capture_output=True, timeout=deadline.timeout_seconds(15))
            if result.returncode:
                raise GateError('offline semantic controls failed before enforcement: ' + test)
        passed('policy-config-negative-controls', {'offline_suites': 2, 'exit_codes': [0, 0]})
        docker, endpoint = _docker_endpoint()
        env, config = _docker_env(endpoint)
        image = _json(ROOT / 'evidence/phase5-eligibility.json')['candidates'][0]['toolchain_image']
        try:
            image_id = _image_digest(docker, image, env)
            receipt.update(image=image, image_id=image_id)
        finally:
            shutil.rmtree(config, ignore_errors=True)
        compiler = 'ceb739494a2ae79f1968e8722a83ed1979f092536422478ffd7cb0882745f06a'
        receipt['compiler'] = {'path': '/usr/bin/gcc', 'sha256': compiler, 'origin': image,
                               'purpose': 'local compilation of original harmless MIT probe only'}
        source = ROOT / 'tests/evidence/fixtures/phase5_sandbox_probe.c'
        (directory / 'probe.c').write_bytes(source.read_bytes())
        (directory / 'build.sh').write_text(
            'set -eu\n' +
            'test "$(sha256sum /usr/bin/gcc | cut -d " " -f1)" = ' + compiler + '\n' +
            'exec /usr/bin/gcc -std=c17 -Wall -Wextra -Werror -pthread probe.c -o probe\n')
        limits = dict(records.SCREENING_LIMITS, build_invocation_seconds=deadline.timeout_seconds(15))
        result = _container_build(image, directory, 'probe', limits=limits, endpoint=endpoint,
                                  invocation='harmless-compile', recipe_args=[],
                                  current_config={'work_mount_mode': 'noexec', 'native_tools': []})
        if result['returncode'] or result['stop_reason'] or not result.get('output'):
            raise GateError('reviewed native compiler/pthread helper unavailable: ' +
                            result['stderr'].decode('utf-8', 'replace')[-500:])
        raw = (directory / 'probe').read_bytes()
        binary_sha = hashlib.sha256(raw).hexdigest()
        receipt['probe_binary_sha256'] = binary_sha
        encoded = base64.b64encode(raw).decode('ascii')
        transfer = ('mkdir -p /work/src; printf %s ' + shlex.quote(encoded) +
                    ' | base64 -d > /work/src/probe; chmod 700 /work/src/probe; ' +
                    'test "$(sha256sum /work/src/probe | cut -d " " -f1)" = ' + binary_sha + ' || exit 48; ')
        def probe(script, *, mode='exec', seconds=15, stdout_cap=1048576,
                  memory=None, as_kib=8388608, tmp_size=None, work_size=None):
            name = 'phase5-enforce-' + uuid.uuid4().hex[:16]
            native = [{'executable': '/work/src/probe', 'executable_sha256': binary_sha,
                       'inputs': {'probe.c': hashlib.sha256(source.read_bytes()).hexdigest()},
                       'command': ['/work/src/probe']}]
            args = _current_container_args(docker, name, policy, work_mount_mode=mode,
                                            native_tools=native if mode == 'exec' else [], remove=False)
            if memory is not None:
                args[args.index('--memory')+1] = str(memory)
                args[args.index('--memory-swap')+1] = str(memory)
            if tmp_size is not None or work_size is not None:
                for i, arg in enumerate(args):
                    if arg.startswith('/tmp:') and tmp_size is not None:
                        args[i] = arg.replace('size=1073741824', 'size=' + str(tmp_size))
                    if arg.startswith('/work:') and work_size is not None:
                        args[i] = arg.replace('size=8589934592', 'size=' + str(work_size))
            args += ['--entrypoint', '/bin/sh', image, '-c',
                     f'ulimit -v {as_kib} || exit 49; ' + transfer + script]
            result = bounded_run(args, endpoint=endpoint, timeout_seconds=deadline.timeout_seconds(seconds),
                                 stdout_cap=stdout_cap, stderr_cap=1048576, container_name=name)
            env, config = _docker_env(endpoint)
            try:
                inspected = subprocess.run([docker, 'inspect', name, '--format',
                                            '{{json .State}}'], env=env, capture_output=True,
                                           text=True, timeout=deadline.timeout_seconds(3))
                if inspected.returncode:
                    raise GateError('enforcement container state is unavailable after probe')
                state = json.loads(inspected.stdout)
                if state['Running']:
                    raise GateError('enforcement descendant/container survived controller stop')
                result['container_state'] = {'running': state['Running'], 'oom_killed': state['OOMKilled']}
            finally:
                subprocess.run([docker, 'rm', '-f', name], env=env, capture_output=True, timeout=3)
                shutil.rmtree(config, ignore_errors=True)
            return result
        def require_ok(result, marker):
            if result['returncode'] or result['stop_reason'] or marker not in result['stdout']:
                raise GateError('harmless enforcement assertion failed: ' + marker.decode() + '; ' +
                                result['stdout'].decode('utf-8', 'replace')[-300:] + '; ' +
                                result['stderr'].decode('utf-8', 'replace')[-300:])
        for kind in ('processes', 'threads'):
            result = probe('exec /work/src/probe ' + kind)
            require_ok(result, b'PRESSURE')
            text = result['stdout'].decode()
            fields = dict(re.findall(r'(created|denied|current|max|peak)=(-?[0-9]+)', text))
            values = {k: int(v) for k, v in fields.items()}
            if values.get('denied') != 11 or values.get('current') != 64 or values.get('max') != 64:
                raise GateError('actual64-task pressure did not reject cap+1 with EAGAIN')
            passed('task-' + ('process' if kind == 'processes' else 'thread') + '-cap64', values)
        jobs = probe("printf 'all: a b c d e\na b c d e:\n\t/work/src/probe job $@\n' > /work/Makefile; "
                     'cd /work; make -j4 -f Makefile')
        require_ok(jobs, b'JOB finish')
        events = re.findall(rb'JOB (start|finish) ([a-e]) active=([0-9]+)', jobs['stdout'])
        starts = [event for event in events if event[0] == b'start']
        if (len(starts) != 5 or max(int(e[2]) for e in starts) != 4
                or len(events) != 10 or not any(e[0] == b'finish' for e in events[:5])):
            raise GateError('four-job bound/fifth queued assertion failed')
        passed('four-jobs-fifth-queued', {'starts': 5, 'max_active': 4, 'fifth_queued': True,
                                         'events': [[a.decode(), b.decode(), int(c)] for a,b,c in events]})
        result = probe('/work/src/probe sentinel')
        require_ok(result, b'NATIVE_SENTINEL_OK')
        passed('declared-native-exec', {'binary_sha256': binary_sha, 'sentinel': True})
        for name, script, mode in (
                ('work-noexec', '/work/src/probe sentinel; code=$?; test "$code" = 126 && echo NOEXEC_DENIED', 'noexec'),
                ('tmp-noexec', 'cp /work/src/probe /tmp/probe; /tmp/probe sentinel; code=$?; test "$code" = 126 && echo NOEXEC_DENIED', 'exec')):
            result = probe(script, mode=mode)
            require_ok(result, b'NOEXEC_DENIED')
            if b'NATIVE_SENTINEL_OK' in result['stdout']:
                raise GateError('native noexec sentinel unexpectedly executed')
            passed(name, {'denied_exit': 126, 'sentinel_absent': True})
        for name, command, reason, seconds, cap in (
                ('timeout-descendants', 'descendant', 'time-cap', 1, 1048576),
                ('output-descendants', 'flood', 'stdout-cap', 15, 4096)):
            result = probe('exec /work/src/probe ' + command, seconds=seconds, stdout_cap=cap)
            if (result['stop_reason'] != reason or b'DESCENDANT_STARTED' not in result['stdout']
                    or result['container_state']['running']):
                raise GateError('descendant cleanup did not reach its intended ' + reason)
            passed(name, {'stop_reason': reason, 'descendant_started': True, 'running_after_stop': False})
        passed('output-cap', {'stop_reason': 'stdout-cap', 'cap_bytes': 4096})
        script = (
            'set -eu; test "$(id -u):$(id -g)" = 65532:65532; '
            'test "$(cat /sys/fs/cgroup/pids.max)" = 64; '
            'test "$(cat /sys/fs/cgroup/cpu.max)" = "400000 100000"; '
            'test "$(cat /sys/fs/cgroup/memory.max)" = 8589934592; '
            'test "$(cat /sys/fs/cgroup/memory.swap.max)" = 0; '
            'test "$(ulimit -v)" = 8388608; '
            'grep -q "CapEff:[[:space:]]*0000000000000000" /proc/self/status; '
            'grep -q "NoNewPrivs:[[:space:]]*1" /proc/self/status; '
            'test ! -e /var/run/docker.sock; test ! -e /run/host-services; '
            'test ! -e /Users; test ! -e /root/.aws; '
            '! env | grep -q "GENEWHIP_SECRET_SENTINEL"; '
            '! touch /root-write-test 2>/dev/null; '
            '! busybox wget -T 1 -O /dev/null http://192.0.2.1/ >/dev/null 2>&1; '
            'echo ISOLATION64_OK')
        result = probe(script)
        require_ok(result, b'ISOLATION64_OK')
        for name in ('uid-gid', 'network-none', 'read-only-root', 'capabilities-nnp',
                     'host-unmounted', 'secret-env-absent', 'cpu-quota4', 'memory8g-swap0', 'address-space8g'):
            passed(name, {'asserted_in_production_container': True,
                          'output_sha256': hashlib.sha256(result['stdout']).hexdigest()})
        result = probe('dd if=/dev/zero of=/work/fill bs=1048576 count=2 2>/dev/null; '
                       'code=$?; test "$code" != 0 && echo WORKSPACE_LIMIT_DENIED', work_size=1048576)
        require_ok(result, b'WORKSPACE_LIMIT_DENIED')
        passed('workspace-disk', {'tmpfs_bytes': 1048576, 'attempted_bytes': 2097152, 'denied': True})
        result = probe('/work/src/probe address-space', as_kib=1048576)
        require_ok(result, b'ALLOC_DENIED')
        if b'BEFORE_ALLOC' not in result['stdout']:
            raise GateError('AS negative never reached the allocation assertion')
        passed('smaller-as-rejection', {'address_space_kib': 1048576, 'allocation_denied': True})
        result = probe('/work/src/probe memory', memory=268435456)
        if b'BEFORE_ALLOC' not in result['stdout'] or not result['container_state']['oom_killed']:
            raise GateError('memory pressure did not prove intended aggregate OOM rejection')
        passed('smaller-memory-rejection', {'memory_bytes': 268435456, 'oom_killed': True, 'allocation_reached': True})
        # Exercise the production archive boundary, not a text-only declaration.
        archive = directory / 'empty.tar'
        with tarfile.open(archive, 'w') as stream:
            import io
            info = tarfile.TarInfo('too-large'); info.size = 2
            stream.addfile(info, io.BytesIO(b'12'))
        try:
            safe_extract(archive, directory / 'extract', max_unpacked=1)
        except GateError as exc:
            if 'unpacked-byte cap' not in str(exc):
                raise
        else:
            raise GateError('archive negative failed to reject its intended byte boundary')
        passed('archive-cap', {'unpacked_limit': 1, 'attempted_bytes': 2, 'denied': True})
        receipt.update(status='pass', elapsed_us=deadline.elapsed_us())
        _verify_enforcement_document(receipt)
    except (GateError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        receipt.update(status='blocked', elapsed_us=deadline.elapsed_us(), reason=str(exc))
    finally:
        # Only original authored helper files are removed, never candidate work.
        shutil.rmtree(directory, ignore_errors=True)
        receipt['elapsed_us'] = deadline.elapsed_us()
        _atomic_json(ROOT / 'evidence/phase5-enforcement.json', receipt)
    print(json.dumps({'status': receipt['status'], 'controls_passed': len(receipt['controls']),
                      'required_controls': len(ENFORCEMENT_CONTROLS), 'reason': receipt.get('reason'),
                      'elapsed_us': receipt['elapsed_us']}, sort_keys=True))
    return 0 if receipt['status'] == 'pass' else 2



TANK_PROBE = ['/opt/jre-minimal/bin/java', '-Xint', '-XX:+UseSerialGC', '-XX:ActiveProcessorCount=1',
              '-XX:+DisableAttachMechanism', '-XX:-UsePerfData', '-version']


def _validate_current_config(config, workspaces):
    policy = records.amended_policy()
    if (config.get('policy_sha256') != records.identity_digest(policy)
            or config.get('migration_sha256') != hashlib.sha256(
                (ROOT / 'evidence/phase5-policy-migration.json').read_bytes()).hexdigest()):
        raise GateError('build config policy/migration identity mismatch')
    for key in ('linux_tasks_per_container', 'cpus_per_container', 'concurrent_build_jobs'):
        if type(config.get(key)) is not int or config[key] != policy[key]:
            raise GateError('build config task/CPU/job policy mismatch')
    _validate_native_tools(config.get('native_tools'), config.get('work_mount_mode'))
    setup_outputs = config.get('setup_outputs', {})
    if not isinstance(setup_outputs, dict):
        raise GateError('counted setup output inventory must be an object')
    for relative, digest in setup_outputs.items():
        if (not isinstance(relative, str) or re.fullmatch(r'[0-9a-f]{64}', str(digest)) is None
                or any(_confined(workspace, relative).is_symlink()
                       or not _confined(workspace, relative).is_file()
                       or hashlib.sha256(_confined(workspace, relative).read_bytes()).hexdigest() != digest
                       for workspace in workspaces)):
            raise GateError('counted setup output does not match both clean workspaces')
    if any(tool['executable'].removeprefix('/work/src/') not in setup_outputs
           or setup_outputs[tool['executable'].removeprefix('/work/src/')] != tool['executable_sha256']
           for tool in config.get('native_tools', [])):
        raise GateError('native tools must be exact members of the counted setup output inventory')
    _validate_job_policy(config.get('job_policy'), config['build_environment'])
    if set(config['build_environment']) - {'PATH', 'MAKEFLAGS', 'GDK'}:
        raise GateError('current build environment contains undeclared loader/interpreter variables')
    if any(part.startswith(('/work', '/tmp')) for part in config['build_environment']['PATH'].split(':')):
        raise GateError('current tool PATH must contain only read-only image directories')
    if config['build_recipe']['args']:
        raise GateError('current job-bounded recipe does not accept override arguments')
    recipe_hash = config.get('recipe_sha256')
    makefiles = config.get('makefiles')
    if not isinstance(makefiles, dict) or not makefiles:
        raise GateError('job-bounded recipe requires all reviewed makefile identities')
    command = config['job_policy']['command']
    if command[3] not in makefiles:
        raise GateError('job recipe makefile is absent from reviewed job declarations')
    setup_pending = (config.get('title_id') == 'recursion94'
                    and isinstance(config.get('recursion_setup'), dict)
                    and not config.get('native_tools'))
    for workspace in workspaces:
        recipe = _confined(workspace, config['build_recipe']['path'])
        raw = recipe.read_bytes()
        if hashlib.sha256(raw).hexdigest() != recipe_hash:
            raise GateError('reviewed build recipe hash mismatch')
        expected = 'set -eu\nexec ' + shlex.join(command) + '\n'
        if raw.decode() not in (expected, '#!/bin/sh\n' + expected):
            raise GateError('unsupported job scheduler recipe; require exact reviewed exec make command')
        for relative, digest in makefiles.items():
            path = _confined(workspace, relative)
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != digest:
                raise GateError('reviewed job makefile identity mismatch')
            # Nested make can override a jobserver. Such recipes need explicit
            # review/support rather than treating CPU quota as a job bound.
            if (re.search(rb'(\$[({]MAKE[)}]|\bmake\b|--jobserver|(?:^|\s)-j(?:[0-9]+|\s|$))', raw)
                    or re.search(rb'^\s*(?:-?include|sinclude)\s', raw, re.M)):
                raise GateError('unsupported nested make/job override/include in reviewed recipe')
            if not setup_pending:
                _validate_recipe_commands(raw, config['native_tools'])
        for tool in config['native_tools']:
            for relative, digest in tool['inputs'].items():
                if hashlib.sha256(_confined(workspace, relative).read_bytes()).hexdigest() != digest:
                    raise GateError('native executable input hash mismatch')
            relative = tool['executable'].removeprefix('/work/src/')
            if hashlib.sha256(_confined(workspace, relative).read_bytes()).hexdigest() != tool['executable_sha256']:
                raise GateError('native executable output hash mismatch')
    if config.get('initialization_probe') is not None:
        if config['title_id'] != 'tank-battle' or config['initialization_probe'] != TANK_PROBE:
            raise GateError('initialization probe differs from exact historical minimized Java tool command')
        if re.fullmatch('[0-9a-f]{64}', str(config.get('initialization_tool_sha256'))) is None:
            raise GateError('initialization tool hash is missing')


def _current_prerequisites(ledger_path, eligibility_path, policy_path):
    ledger, eligibility = _json(ledger_path), _json(eligibility_path)
    policy = _json(policy_path)
    records.effective_policy(policy)
    records.validate_policy_migration(ledger, eligibility, _json(ROOT / 'evidence/phase5-policy-migration.json'))
    enforcement = _verify_enforcement(ROOT / 'evidence/phase5-enforcement.json')
    # Tests use production validators, and run before candidate-specific work.
    for test, mode in (('phase5_admission_contract.py', '--self-test'),
                       ('phase5_build_contract.py', '--policy-self-test')):
        run = subprocess.run([sys.executable, '-I', str(ROOT / 'tests/evidence' / test), mode],
                             capture_output=True, timeout=15)
        if run.returncode:
            raise GateError('current offline semantic controls failed: ' + test)
    return ledger, eligibility, policy, enforcement


def _prepare_recursion_toolchain(config, config_path, workspaces, *, endpoint, limits, deadline):
    """Compile the exact pinned Linux-equivalent tools once inside setup budget."""
    setup = config.get('recursion_setup')
    if config.get('title_id') != 'recursion94' or not isinstance(setup, dict):
        raise GateError('RECURSION build requires its exact candidate-specific setup declaration')
    recipe_path = ROOT / RECURSION_SETUP_RECIPE
    recipe = recipe_path.read_bytes()
    if hashlib.sha256(recipe).hexdigest() != RECURSION_SETUP_RECIPE_SHA256:
        raise GateError('reviewed RECURSION setup recipe bytes changed')
    setup_workspace = _confined(ROOT, setup['workspace']).resolve()
    setup_workspace.mkdir(parents=True, exist_ok=True)
    if any(setup_workspace.iterdir()):
        raise GateError('RECURSION setup workspace is not fresh; no setup replay is permitted')
    for archive_relative, (digest, candidate_path) in RECURSION_SETUP_INPUTS.items():
        source = _confined(workspaces[0], candidate_path)
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise GateError('pinned RECURSION tool source archive is missing or changed')
        destination = _confined(setup_workspace, archive_relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    run = _counted_recursion_setup(
        config['build_image'], setup_workspace, limits=limits, endpoint=endpoint,
        deadline=deadline, setup_script=recipe,
        expected_script_sha256=RECURSION_SETUP_RECIPE_SHA256)
    outputs_dir = setup_workspace.parent / 'setup-output'
    outputs = _extract_recursion_setup_outputs(run['output_tar'], outputs_dir)
    output_hashes = {path: item['sha256'] for path, item in outputs.items()}
    input_manifest = {
        'schema': 'genewhip-phase5-recursion-toolchain-inputs-v1',
        'source_revision': config['source_revision'],
        'setup_recipe': RECURSION_SETUP_RECIPE,
        'setup_recipe_sha256': RECURSION_SETUP_RECIPE_SHA256,
        'build_image': config['build_image'], 'build_image_id': run['image_id'],
        'policy_sha256': records.identity_digest(records.amended_policy()),
        'inputs': [{'path': path, 'source_revision': 'sha256:' + digest, 'sha256': digest}
                   for path, (digest, _) in sorted(RECURSION_SETUP_INPUTS.items())],
    }
    manifest_bytes = json.dumps(input_manifest, sort_keys=True, indent=2).encode() + b'\n'
    setup_outputs = dict(output_hashes)
    setup_outputs['tools/phase5-toolchain-inputs.json'] = hashlib.sha256(manifest_bytes).hexdigest()
    for workspace in workspaces:
        tool_tree = workspace / '.toolcache'
        if tool_tree.exists():
            raise GateError('clean build workspace already contains setup outputs')
        shutil.copytree(outputs_dir / '.toolcache', tool_tree)
        manifest = _confined(workspace, 'tools/phase5-toolchain-inputs.json')
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_bytes(manifest_bytes)
    inputs_hash = setup_outputs['tools/phase5-toolchain-inputs.json']
    def tool(path, command):
        digest = setup_outputs[path.removeprefix('/work/src/')]
        return {'executable': path, 'executable_sha256': digest,
                'inputs': {'tools/phase5-toolchain-inputs.json': inputs_hash},
                'command': [path, *command]}
    config['work_mount_mode'] = 'exec'
    config['setup_outputs'] = setup_outputs
    config['native_tools'] = [
        tool('/work/src/.toolcache/python/bin/python3.12',
             ['tools/build_rom.py', '--root', '/work/src', '--configuration', 'Release']),
        tool('/work/src/.toolcache/bin/vasmm68k_mot.exe', ['-v']),
        tool('/work/src/.toolcache/bin/sjasmplus.exe', ['--nologo', '--version']),
    ]
    config['setup_receipt_sha256'] = None
    receipt = {
        'schema': 'genewhip-phase5-recursion-setup-v1', 'title_id': 'recursion94',
        'status': 'pass', 'image': config['build_image'], 'image_id': run['image_id'],
        'policy_sha256': records.identity_digest(records.amended_policy()),
        'recipe': RECURSION_SETUP_RECIPE, 'recipe_sha256': RECURSION_SETUP_RECIPE_SHA256,
        'inputs': input_manifest['inputs'], 'output_tar_bytes': len(run['output_tar']),
        'output_tar_sha256': hashlib.sha256(run['output_tar']).hexdigest(),
        'stderr_bytes': len(run['stderr']), 'stderr_sha256': hashlib.sha256(run['stderr']).hexdigest(),
        'elapsed_us': run['elapsed_us'], 'setup_outputs': setup_outputs,
    }
    receipt_raw = json.dumps(receipt, sort_keys=True, indent=2).encode() + b'\n'
    receipt_path = ROOT / 'evidence/phase5-recursion-setup.json'
    _atomic_json(receipt_path, receipt)
    config['setup_receipt_sha256'] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    _atomic_json(config_path, config)
    shutil.rmtree(outputs_dir, ignore_errors=True)
    return receipt


def _continue_tank_setup(ledger_path, eligibility_path, policy_path, config_path):
    ledger, eligibility, policy, enforcement = _current_prerequisites(ledger_path, eligibility_path, policy_path)
    config, _ = _validate_build_config(config_path, 'tank-battle')
    if config.get('schema') != 'genewhip-phase5-build-config-v2' or config.get('initialization_probe') != TANK_PROBE:
        raise GateError('Tank setup requires current reviewed config and exact pinned initialization probe')
    historical = _json(ROOT / 'evidence/phase5-eligibility.json')['candidates'][0]
    current_candidate = eligibility['candidates'][0]
    if config['build_image'] != historical['toolchain_image'] or config['source_revision'] != historical['source_revision']:
        raise GateError('Tank continuation cannot change historical toolchain/title/source identity')
    _screen_setup_identity(ledger, historical, config, config_path)
    for original in ledger['candidates'][0]['identity_history'][3]['details']['probe_receipts']:
        path = ROOT / 'local-fixtures/phase5/tank-setup' / original['file']
        if hashlib.sha256(path.read_bytes()).hexdigest() != original['sha256']:
            raise GateError('exact historical failed probe receipt is unavailable/changed')
    # Every fallible prerequisite precedes one-use consumption; no candidate
    # subprocess has launched. Once consumed, ANY interruption is nonrenewable.
    preparation_us = 0
    preparation_receipts = []
    for reference in config.get('preparation_receipts', []):
        path = _confined(ROOT, reference['path'])
        if not path.resolve().is_relative_to((ROOT / 'local-fixtures/phase5/tank-battle').resolve()):
            raise GateError('preparation receipt must stay in Tank quarantine')
        if hashlib.sha256(path.read_bytes()).hexdigest() != reference['sha256']:
            raise GateError('preparation receipt identity mismatch')
        document = _json(path)
        elapsed = document.get('elapsed_seconds')
        if type(elapsed) not in (float, int) or not math.isfinite(elapsed) or elapsed < 0:
            raise GateError('preparation elapsed time is invalid')
        preparation_us += math.ceil(elapsed * 1000000)
        preparation_receipts.append(reference)
    if not records.within_limit(preparation_us, records.SETUP_REMAINING_US):
        raise GateError('preparation already exhausted cumulative setup budget')
    ledger = records.begin_setup_continuation(ledger, ledger_path=ledger_path)
    ledger = records.charge_setup_elapsed(ledger, preparation_us, ledger_path=ledger_path)
    deadline = SetupDeadline(records.SETUP_REMAINING_US - preparation_us)
    receipt = {'schema': 'genewhip-phase5-setup-continuation-v2', 'title_id': 'tank-battle',
               'policy_sha256': ledger['policy_sha256'], 'identities': _enforcement_identities(),
               'enforcement_sha256': hashlib.sha256((ROOT / 'evidence/phase5-enforcement.json').read_bytes()).hexdigest(),
               'config_sha256': records.identity_digest(config), 'probe_command': TANK_PROBE,
               'config_path': pathlib.Path(config_path).resolve().relative_to(ROOT).as_posix(),
               'preparation_receipts': preparation_receipts, 'preparation_elapsed_us': preparation_us,
               'image_materials_sha256': records.identity_digest({'materials': current_candidate['image_materials']}),
               'initialization_tool_sha256': config['initialization_tool_sha256'],
               'status': 'in-flight', 'rom_invocations': 0, 'candidate_rom_execution': False,
               'historical_anchors': records.HISTORICAL_ANCHORS}
    public_path = ROOT / 'evidence/phase5-setup-continuation.json'
    _atomic_json(public_path, receipt)
    probe_elapsed = None
    try:
        docker, endpoint = _docker_endpoint(deadline=deadline)
        env, docker_config = _docker_env(endpoint)
        try:
            receipt['build_image_id'] = _image_digest(docker, config['build_image'], env, deadline=deadline)
        finally:
            shutil.rmtree(docker_config, ignore_errors=True)
        name = 'phase5-tank-continuation-' + uuid.uuid4().hex[:12]
        args = _current_container_args(docker, name, policy, work_mount_mode=config['work_mount_mode'],
                                        native_tools=config['native_tools'], build_environment=config['build_environment'])
        tool = shlex.quote(config['initialization_probe'][0])
        script = ('ulimit -v 8388608 || exit 49; test "$(sha256sum ' + tool +
                  ' | cut -d " " -f1)" = ' + config['initialization_tool_sha256'] +
                  ' || exit 48; printf "PIDS_MAX="; cat /sys/fs/cgroup/pids.max; '
                  'printf "CPU_MAX="; cat /sys/fs/cgroup/cpu.max; '
                  'printf "MEMORY_MAX="; cat /sys/fs/cgroup/memory.max; '
                  'printf "SWAP_MAX="; cat /sys/fs/cgroup/memory.swap.max; '
                  'printf "AS_KIB="; ulimit -v; ' + shlex.join(TANK_PROBE) +
                  '; status=$?; printf "PIDS_PEAK="; cat /sys/fs/cgroup/pids.peak 2>/dev/null || echo unavailable; exit "$status"')
        args += ['--entrypoint', '/bin/sh', config['build_image'], '-c', script]
        before = deadline.elapsed_us()
        result = bounded_run(args, endpoint=endpoint, timeout_seconds=deadline.timeout_seconds(120),
                             stdout_cap=1048576, stderr_cap=1048576, container_name=name, deadline=deadline)
        probe_elapsed = deadline.elapsed_us() - before
        receipt['probe'] = {k: v for k, v in result.items() if k not in ('stdout', 'stderr')}
        for stream in ('stdout', 'stderr'):
            data = result[stream]
            path = pathlib.Path(config_path).resolve().parent / ('continuation.' + stream)
            _ensure_quarantine_capacity(records.SCREENING_LIMITS, additional_bytes=len(data))
            path.write_bytes(data)
            receipt['probe'][stream + '_sha256'] = hashlib.sha256(data).hexdigest()
            receipt['probe'][stream + '_bytes'] = len(data)
            receipt['probe'][stream + '_path'] = path.relative_to(ROOT).as_posix()
        observed = dict(re.findall(r'^(PIDS_MAX|CPU_MAX|MEMORY_MAX|SWAP_MAX|AS_KIB|PIDS_PEAK)=(.*)$',
                                   result['stdout'].decode('utf-8', 'replace'), re.M))
        receipt['effective_observations'] = observed
        receipt['task_measurement'] = 'PIDS_PEAK is the kernel peak when available; no sampled peak inferred'
        receipt['probe_elapsed_us'] = probe_elapsed
        if (result['returncode'] or result['stop_reason'] or probe_elapsed > records.PROBE_CEILING_US
                or any(observed.get(k) != v for k, v in {'PIDS_MAX': '64', 'CPU_MAX': '400000 100000',
                    'MEMORY_MAX': '8589934592', 'SWAP_MAX': '0', 'AS_KIB': '8388608'}.items())):
            raise GateError('single Tank initialization probe failed or exceeded its120-second ceiling')
        ledger = records.charge_setup_elapsed(ledger, preparation_us + deadline.elapsed_us(),
                                               probe_elapsed_us=probe_elapsed, ledger_path=ledger_path)
        # Only image metadata/hash inspection remains; no ROM or candidate
        # build recipe is permitted in the setup continuation command.
        _verify_image_materials(config['build_image'], receipt['build_image_id'], current_candidate['image_materials'],
                                endpoint=endpoint, policy=policy, deadline=deadline)
        ledger = records.charge_setup_elapsed(ledger, preparation_us + deadline.elapsed_us(), ledger_path=ledger_path)
        ledger = records.complete_setup_continuation(ledger, success=True, ledger_path=ledger_path)
        receipt['status'] = 'pass'
    except (GateError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        elapsed = preparation_us + deadline.elapsed_us()
        receipt.update(status='blocked', reason=str(exc), measured_elapsed_us=elapsed)
        # On a controller overrun retain the actual measured excess separately,
        # exhaust the finite allowance and terminally fail; never renew it.
        ledger = records.charge_setup_elapsed(ledger, min(elapsed, records.SETUP_REMAINING_US), ledger_path=ledger_path)
        ledger = records.complete_setup_continuation(ledger, success=False, ledger_path=ledger_path)
    receipt['continuation'] = records.setup_continuation_state(ledger)
    receipt['measured_elapsed_us'] = preparation_us + deadline.elapsed_us()
    _atomic_json(public_path, receipt)
    print(json.dumps({'status': receipt['status'], 'continuation': receipt['continuation'],
                      'rom_invocations': 0}, sort_keys=True))
    return receipt['status'] == 'pass'


def _bind_continuation_config(receipt, config):
    if records.identity_digest(config) != receipt.get('config_sha256'):
        raise GateError('continuation config identity changed after setup authorization')


# This is the one consumed observation, not a renewable launch authorization.
# Its original bytes identify the producer hashes; Git supplies those producer
# bytes without executing them. Missing history fails closed (including exports).
SETUP_PRODUCER_REVISION = '0e04e1c2552fe174ecb3051adf270a65b2b2c819'
SETUP_OBSERVATION_SHA256 = '12b71bbb47b3b02e6f8b96b1b9c66ca5b8b49d081d5983d6b4a6ab8fb1c96b91'


def _verify_setup_producer(receipt):
    identities = receipt['identities']
    if set(identities) != set(ENFORCEMENT_IDENTITY_FILES):
        raise GateError('historical setup producer file roster changed')
    for relative, digest in identities.items():
        try:
            result = subprocess.run(['git', 'show', SETUP_PRODUCER_REVISION + ':' + relative],
                                    cwd=ROOT, capture_output=True, timeout=10, check=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise GateError('historical setup producer bytes unavailable: ' + relative) from exc
        if hashlib.sha256(result.stdout).hexdigest() != digest:
            raise GateError('historical setup producer identity mismatch: ' + relative)


def _verify_continuation(path, ledger_path, eligibility_path, policy_path, config=None):
    """Verify the consumed observation. Launches separately require current controls."""
    ledger, eligibility, policy = _json(ledger_path), _json(eligibility_path), _json(policy_path)
    records.effective_policy(policy)
    records.validate_policy_migration(ledger, eligibility, _json(ROOT / 'evidence/phase5-policy-migration.json'))
    if hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() != SETUP_OBSERVATION_SHA256:
        raise GateError('historical setup observation bytes changed')
    receipt = _json(path)
    _verify_setup_producer(receipt)
    archive_path = ROOT / 'evidence/phase5-enforcement-setup.json'
    if hashlib.sha256(archive_path.read_bytes()).hexdigest() != receipt['enforcement_sha256']:
        raise GateError('historical setup enforcement archive changed')
    _verify_enforcement_document(_json(archive_path), producer_identities=receipt['identities'])
    if config is None:
        config_path = _confined(ROOT, receipt.get('config_path'))
        config = _json(config_path)
    _bind_continuation_config(receipt, config)
    preparation_us = 0
    if receipt['preparation_receipts'] != config.get('preparation_receipts'):
        raise GateError('historical setup preparation identity mismatch')
    for reference in receipt['preparation_receipts']:
        preparation_path = _confined(ROOT, reference['path'])
        if hashlib.sha256(preparation_path.read_bytes()).hexdigest() != reference['sha256']:
            raise GateError('historical setup preparation receipt changed')
        elapsed = _json(preparation_path).get('elapsed_seconds')
        if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
            raise GateError('historical setup preparation elapsed is invalid')
        preparation_us += math.ceil(elapsed * 1000000)
    if preparation_us != receipt['preparation_elapsed_us']:
        raise GateError('historical setup preparation charge mismatch')
    probe = receipt['probe']
    raw = {}
    for stream in ('stdout', 'stderr'):
        raw[stream] = _confined(ROOT, probe[stream + '_path']).read_bytes()
        if (len(raw[stream]) != probe[stream + '_bytes']
                or hashlib.sha256(raw[stream]).hexdigest() != probe[stream + '_sha256']):
            raise GateError('historical setup probe ' + stream + ' changed')
    observed = dict(re.findall(r'^(PIDS_MAX|CPU_MAX|MEMORY_MAX|SWAP_MAX|AS_KIB|PIDS_PEAK)=(.*)$',
                              raw['stdout'].decode('utf-8', 'replace'), re.M))
    if (probe['returncode'] != 0 or probe['stop_reason'] is not None
            or observed != receipt['effective_observations']
            or any(observed.get(k) != v for k, v in {'PIDS_MAX': '64', 'CPU_MAX': '400000 100000',
                'MEMORY_MAX': '8589934592', 'SWAP_MAX': '0', 'AS_KIB': '8388608'}.items())):
        raise GateError('historical setup probe did not establish the recorded controls')
    state = records.setup_continuation_state(ledger)
    if (receipt.get('schema') != 'genewhip-phase5-setup-continuation-v2'
            or receipt.get('status') != 'pass' or state['state'] != 'completed'
            or receipt.get('continuation') != state or receipt.get('title_id') != 'tank-battle'
            or receipt.get('historical_anchors') != records.HISTORICAL_ANCHORS
            or receipt.get('policy_sha256') != records.identity_digest(policy)
            or receipt.get('probe_command') != TANK_PROBE
            or not records.within_limit(receipt.get('probe_elapsed_us'), records.PROBE_CEILING_US)
            or not records.within_limit(receipt.get('measured_elapsed_us'), records.SETUP_REMAINING_US)
            or receipt.get('probe_elapsed_us') != state['probe_elapsed_us']
            or not state['elapsed_us'] <= receipt['measured_elapsed_us']
            or receipt.get('candidate_rom_execution') is not False
            or receipt.get('rom_invocations') != 0):
        raise GateError('continuation receipt is missing, stale, failed or not cumulative/single-use')
    print(json.dumps({'status': 'verified', 'scope': 'historical-setup-observation',
                      'producer_revision': SETUP_PRODUCER_REVISION,
                      'launch_authorized': False, 'continuation': state}, sort_keys=True))
    return receipt


def _verify_build_pair(ledger_path, eligibility_path, policy_path):
    ledger, eligibility, _, _ = _current_prerequisites(ledger_path, eligibility_path, policy_path)
    qualified = []
    for item in ledger['candidates']:
        if not _repeatable_build_reported(item):
            continue
        candidate = next(c for c in eligibility['candidates'] if c['title_id'] == item['id'])
        if not records.validate_eligibility(candidate) or not inspect_materials(candidate)['eligible']:
            raise GateError('build pair lacks exact material eligibility')
        evidence = item.get('build_evidence', {})
        path = _confined(ROOT, evidence.get('quarantine_receipt'))
        if not path.resolve().is_relative_to((ROOT / 'local-fixtures/phase5').resolve()):
            raise GateError('build pair receipt must be quarantined')
        if hashlib.sha256(path.read_bytes()).hexdigest() != evidence.get('receipt_sha256'):
            raise GateError('build pair receipt hash mismatch')
        receipt = _json(path)
        if (receipt.get('schema') != 'genewhip-phase5-build-receipt-v2'
                or receipt.get('title_id') != candidate['title_id']
                or receipt.get('source_revision') != candidate['source_revision']
                or receipt.get('policy_sha256') != ledger['policy_sha256']):
            raise GateError('build pair current policy/title/source identity mismatch')
        outputs = []
        for ordinal, build in enumerate(receipt.get('builds', []), 1):
            if build.get('ordinal') != ordinal:
                raise GateError('build pair output order changed')
            raw_path = _confined(ROOT, build.get('quarantine_path'))
            if not raw_path.resolve().is_relative_to((ROOT / 'local-fixtures/phase5').resolve()):
                raise GateError('build raw output escaped quarantine')
            raw = raw_path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != build.get('sha256') or len(raw) != build.get('bytes_count'):
                raise GateError('build raw output identity mismatch')
            if candidate['title_id'] == 'tank-battle':
                _verify_tank_link_map(build)
            outputs.append({'ordinal': ordinal, 'bytes': raw})
        comparison = records.compare_build_outputs(outputs, receipt.get('comparison', {}).get('variation'))
        if comparison != receipt.get('comparison') or comparison['status'] not in ('byte-identical', 'explained-variation'):
            raise GateError('actual ordered repeatable build comparison is not qualified')
        qualified.append(candidate)
    if len(qualified) != 2 or len({c['lineage_id'] for c in qualified}) != 2:
        raise GateError('build pair requires two distinct actual eligible repeatable-build lineages')
    print(json.dumps({'status': 'verified', 'titles': [c['title_id'] for c in qualified],
                      'reference_qualification': 'pending'}, sort_keys=True))
    return qualified


def _screen_current(ledger_path, eligibility_path, config_path):
    config_path = pathlib.Path(config_path).resolve()
    ledger, eligibility, policy, enforcement = _current_prerequisites(
        ledger_path, eligibility_path, ROOT / 'fixtures/phase5-policy-v2.json')
    selected, reason = _select_next_candidate(ledger, eligibility)
    if selected is None:
        print(json.dumps({'status': 'blocked', 'reason': reason}, sort_keys=True))
        return False
    config, workspaces = _validate_build_config(config_path, selected)
    if config['schema'] != 'genewhip-phase5-build-config-v2':
        raise GateError('current executions require v2 build config')
    candidate = next(c for c in eligibility['candidates'] if c['title_id'] == selected)
    if not inspect_materials(candidate)['eligible'] or not records.validate_eligibility(candidate):
        raise GateError('current ROM production requires exact material eligibility')
    workspace_identity = _verify_build_inputs(workspaces, candidate, config)
    identity = {'source_revision': candidate['source_revision'], 'build_config_sha256': records.identity_digest(config),
                'workspace_sha256': workspace_identity, 'build_image': config['build_image'],
                'policy_sha256': ledger['policy_sha256'], 'work_mount_mode': config['work_mount_mode'],
                'native_tools': config['native_tools'], 'job_policy': config['job_policy']}
    d114_attempt = None
    recursion_deadline = None
    d114_started_ns = None
    if selected == 'recursion94':
        d114_attempt = _consume_recursion_setup_authorization(ledger, config, eligibility_path)
        d114_started_ns = time.monotonic_ns()
        recursion_deadline = SetupDeadline(RECURSION_SETUP_REMAINING_US)
    try:
        docker, endpoint = _docker_endpoint(deadline=recursion_deadline)
        env, docker_config = _docker_env(endpoint)
        try:
            image_id = _image_digest(docker, config['build_image'], env, deadline=recursion_deadline)
        finally:
            shutil.rmtree(docker_config, ignore_errors=True)
    except (GateError, OSError, subprocess.TimeoutExpired, ValueError) as exc:
        if selected == 'recursion94':
            _finish_recursion_setup_authorization(
                d114_attempt, success=False,
                elapsed_us=(time.monotonic_ns() - d114_started_ns + 999) // 1000,
                reason=str(exc))
        raise
    correction_event = None
    if selected == 'tank-battle':
        setup = _verify_continuation(ROOT / 'evidence/phase5-setup-continuation.json', ledger_path,
                                    eligibility_path, ROOT / 'fixtures/phase5-policy-v2.json', config=config)
        if image_id != setup['build_image_id']:
            raise GateError('current Tank image differs from the observed setup image')
        # No renewed setup/probe/correction for Tank.
    else:
        prior_row = next(c for c in ledger['candidates'] if c['id'] == selected)
        correction_event = (_recursion_setup_correction_event(prior_row)
                            if selected == 'recursion94' else None)
        if correction_event is None:
            ledger = records.append_attempt(ledger, selected, 'screen_started', identity)
        else:
            # This is a continuation of the same consumed screen; the correction
            # event binds the unchanged screen to the repaired prelaunch metadata.
            identity['setup_correction_sha256'] = correction_event['sha256']
        ledger = records.append_attempt(ledger, selected, 'build_setup_started', identity)
        _atomic_json(ledger_path, ledger)
        setup_started = time.monotonic_ns()
        prior_setup_us = math.ceil(sum(event.get('elapsed_seconds', 0) for event in prior_row['identity_history']
                                       if event.get('event') in ('build_setup_completed', 'build_setup_failed'))
                                   * 1000000)
        try:
            if selected == 'recursion94':
                # Bind the exact build container tools before any source compilation.
                # Charge this inspect stage to the same nonrenewable setup clock.
                _verify_image_materials(config['build_image'], image_id, candidate['materials'],
                                        endpoint=endpoint, policy=policy, deadline=recursion_deadline)
                _prepare_recursion_toolchain(config, config_path, workspaces,
                                             endpoint=endpoint, limits=records.SCREENING_LIMITS,
                                             deadline=recursion_deadline)
                config, workspaces = _validate_build_config(config_path, selected)
                workspace_identity = _verify_build_inputs(workspaces, candidate, config)
                identity = {'source_revision': candidate['source_revision'],
                            'build_config_sha256': records.identity_digest(config),
                            'workspace_sha256': workspace_identity,
                            'build_image': config['build_image'],
                            'policy_sha256': ledger['policy_sha256'],
                            'work_mount_mode': config['work_mount_mode'],
                            'native_tools': config['native_tools'], 'job_policy': config['job_policy'],
                            'setup_receipt_sha256': config['setup_receipt_sha256']}
                if correction_event is not None:
                    identity['setup_correction_sha256'] = correction_event['sha256']
                if recursion_deadline.elapsed_us() > RECURSION_SETUP_REMAINING_US:
                    raise GateError('D-114 cumulative setup allowance exceeded')
            else:
                spent_us = math.ceil(sum(e.get('elapsed_seconds', 0) for e in next(c for c in ledger['candidates']
                                    if c['id'] == selected)['identity_history']) * 1000000)
                deadline = SetupDeadline(max(0, 1800000000 - spent_us))
                _verify_image_materials(config['build_image'], image_id, candidate['materials'], endpoint=endpoint,
                                        policy=policy, deadline=deadline)
            ledger = records.append_attempt(ledger, selected, 'build_setup_completed', identity,
                                             details={'elapsed_seconds': (recursion_deadline.elapsed_us() / 1_000_000
                                                                          if recursion_deadline else
                                                                          (time.monotonic_ns() - setup_started) / 1_000_000_000)})
            if selected == 'recursion94':
                _finish_recursion_setup_authorization(
                    d114_attempt, success=True,
                    elapsed_us=(time.monotonic_ns() - d114_started_ns + 999) // 1000)
        except (GateError, OSError, subprocess.TimeoutExpired) as exc:
            row = next(c for c in ledger['candidates'] if c['id'] == selected)
            row.update(state='build-setup-blocked', outcome='infrastructure-error', reason='Current bounded setup failed')
            ledger = records.append_attempt(ledger, selected, 'build_setup_failed', identity,
                                             details={'elapsed_seconds': (recursion_deadline.elapsed_us() / 1_000_000
                                                                          if recursion_deadline else
                                                                          (time.monotonic_ns() - setup_started) / 1_000_000_000),
                                                      'failure_sha256': hashlib.sha256(str(exc).encode()).hexdigest()})
            _atomic_json(ledger_path, ledger)
            if selected == 'recursion94':
                _finish_recursion_setup_authorization(
                    d114_attempt, success=False,
                    elapsed_us=(time.monotonic_ns() - d114_started_ns + 999) // 1000,
                    reason=str(exc))
            raise GateError('current candidate setup failed') from exc
        _atomic_json(ledger_path, ledger)
    try:
        pair = build_pair(config['build_image'], workspaces, config['output_relative'],
                          limits=records.SCREENING_LIMITS, endpoint=endpoint, title_id=selected,
                          screening_path=ledger_path, identity=identity, screen_already_started=True,
                          recipe_path=config['build_recipe']['path'], recipe_args=[],
                          build_environment=config['build_environment'],
                          current_config=config, log_directory=pathlib.Path(config_path).parent / 'logs')
    except (GateError, OSError, subprocess.TimeoutExpired) as exc:
        current = _json(ledger_path)
        current = records.append_attempt(current, selected, 'build_pair_failed', identity,
                                         details={'failure_sha256': hashlib.sha256(str(exc).encode()).hexdigest()})
        row = next(c for c in current['candidates'] if c['id'] == selected)
        row.update(state='build-blocked', outcome='fail', reason='Bounded clean build failed; no automatic correction')
        _atomic_json(ledger_path, current)
        raise
    success = pair['comparison']['status'] in ('byte-identical', 'explained-variation')
    receipt = {'schema': 'genewhip-phase5-build-receipt-v2', 'title_id': selected,
               'source_revision': candidate['source_revision'], 'source_sha256': workspace_identity,
               'build_config_sha256': records.identity_digest(config), 'build_image': config['build_image'],
               'build_image_id': image_id, 'policy_sha256': ledger['policy_sha256'],
               'enforcement_sha256': hashlib.sha256((ROOT / 'evidence/phase5-enforcement.json').read_bytes()).hexdigest(),
               'builds': pair['builds'], 'comparison': pair['comparison'],
               'work_mount_mode': config['work_mount_mode'], 'native_tools': config['native_tools'],
               'job_policy': config['job_policy']}
    raw = json.dumps(receipt, sort_keys=True, indent=2).encode() + b'\n'
    digest = hashlib.sha256(raw).hexdigest()
    path = pathlib.Path(config_path).parent / 'receipts' / (selected + '-' + digest[:16] + '.json')
    path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
    current = _json(ledger_path)
    current = records.append_attempt(current, selected, 'build_pair_completed' if success else 'build_pair_failed',
                                     {**identity, 'receipt_sha256': digest}, details={'comparison': pair['comparison']['status']})
    row = next(c for c in current['candidates'] if c['id'] == selected)
    row.update(state='build-screened' if success else 'build-blocked', outcome='pass' if success else 'fail',
               reason='Ordered clean builds compared; reference route remains pending',
               post_build_checks={'repeatable_build': success},
               build_evidence={'receipt_sha256': digest, 'quarantine_receipt': path.relative_to(ROOT).as_posix(),
                               'comparison': pair['comparison']})
    _atomic_json(ledger_path, current)
    print(json.dumps({'status': 'screened' if success else 'blocked', 'title_id': selected,
                      'receipt_sha256': digest, 'comparison': pair['comparison']['status']}, sort_keys=True))
    return success


def _policy_migration(ledger_path, eligibility_path, policy_path, *, verify=False):
    if not all((ledger_path, eligibility_path, policy_path)):
        raise GateError("policy migration requires --ledger, --eligibility and --policy")
    root = pathlib.Path(ledger_path).resolve().parents[1]
    original_ledger = root / "fixtures/candidate-screening.json"
    original_eligibility = root / "evidence/phase5-eligibility.json"
    current_ledger = root / "fixtures/candidate-screening-v2.json"
    current_eligibility = root / "evidence/phase5-eligibility-v2.json"
    receipt_path = root / "evidence/phase5-policy-migration.json"
    expected = (current_ledger, current_eligibility) if verify else (original_ledger, original_eligibility)
    if tuple(pathlib.Path(p).resolve() for p in (ledger_path, eligibility_path)) != expected:
        raise GateError("policy migration accepts only the named historical/current paths")
    policy = _json(policy_path)
    records.effective_policy(policy)
    outputs = (current_ledger, current_eligibility, receipt_path)
    if any(p.exists() for p in outputs):
        if not all(p.is_file() for p in outputs):
            raise GateError("partial policy migration outputs; refusing to overwrite/reissue")
        ledger, eligibility, receipt = map(_json, outputs)
        records.validate_policy_migration(ledger, eligibility, receipt, root)
        if records.identity_digest(policy) != ledger["policy_sha256"]:
            raise GateError("requested migration policy differs from current ancestry")
    elif verify:
        raise GateError("policy migration outputs are missing")
    else:
        ledger, eligibility, receipt = records.migrate_screening(root, policy)
        # Exclusive creation: concurrent migration cannot overwrite later state.
        for path, document in zip(outputs, (ledger, eligibility, receipt)):
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("x", encoding="utf-8") as stream:
                json.dump(document, stream, indent=2, ensure_ascii=False)
                stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
    print(json.dumps({"status": "verified", "policy_sha256": ledger["policy_sha256"],
                      "continuation": records.setup_continuation_state(ledger),
                      "candidate_execution": False, "eligibility_granted": False}, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    migration = parser.add_mutually_exclusive_group()
    migration.add_argument("--migrate-policy", action="store_true")
    migration.add_argument("--verify-policy-migration", action="store_true")
    parser.add_argument("--policy")
    parser.add_argument('--continue-tank-setup', action='store_true')
    parser.add_argument('--verify-continuation')
    parser.add_argument('--verify-build-pair', action='store_true')
    parser.add_argument('--correct-recursion-setup', action='store_true')
    parser.add_argument('--verify-enforcement')
    parser.add_argument("--documentary", action="store_true")
    parser.add_argument("--ledger")
    parser.add_argument("--eligibility")
    parser.add_argument("--screen-next", action="store_true")
    parser.add_argument("--build-config")
    parser.add_argument("--verify-eligibility")
    parser.add_argument("--verify-slot", choices=("a", "b"))
    parser.add_argument("--stage", choices=("materials", "complete"))
    args = parser.parse_args(argv)
    try:
        if args.verify_enforcement:
            _verify_enforcement(args.verify_enforcement)
        elif args.verify_continuation:
            _verify_continuation(args.verify_continuation, args.ledger, args.eligibility, args.policy)
        elif args.verify_build_pair:
            _verify_build_pair(args.ledger, args.eligibility, args.policy)
        elif args.correct_recursion_setup:
            if not all((args.ledger, args.eligibility, args.build_config)):
                raise GateError('RECURSION setup correction requires --ledger --eligibility --build-config')
            _record_recursion_setup_correction(args.ledger, args.eligibility, args.build_config)
        elif args.continue_tank_setup:
            if not all((args.ledger, args.eligibility, args.policy, args.build_config)):
                raise GateError('continuation requires --ledger --eligibility --policy --build-config')
            return 0 if _continue_tank_setup(args.ledger, args.eligibility, args.policy, args.build_config) else 3
        elif args.migrate_policy or args.verify_policy_migration:
            _policy_migration(args.ledger, args.eligibility, args.policy, verify=args.verify_policy_migration)
        elif args.self_test:
            _self_test()
        elif args.documentary:
            if not args.ledger:
                raise GateError("--documentary requires --ledger")
            _documentary(args.ledger, args.eligibility or ROOT / "evidence" / "phase5-eligibility.json")
        elif args.screen_next:
            if not args.ledger or not args.eligibility:
                raise GateError("--screen-next requires --ledger and --eligibility")
            if not _screen_next(args.ledger, args.eligibility, args.build_config):
                return 3
        elif args.verify_eligibility:
            _verify_eligibility(args.verify_eligibility)
        elif args.verify_slot:
            if args.stage is None:
                raise GateError("--verify-slot requires --stage")
            _verify_slot(args.verify_slot, args.stage,
                         args.eligibility or ROOT / "evidence" / "phase5-eligibility.json")
        else:
            parser.error("select --self-test, --documentary, --screen-next, --verify-eligibility, or --verify-slot")
        return 0
    except (GateError, OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

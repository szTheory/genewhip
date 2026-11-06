#!/usr/bin/env python3
"""Run the Linux x86_64 Libretro package tracer in a pinned Docker image."""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTAINER_CONTEXT = ROOT / "tools/containers/libretro-tracer"
DOCKERFILE = CONTAINER_CONTEXT / "Dockerfile"
BASE_IMAGE = "gcc@sha256:435c3cbc2ad1c25fbc1684c367808ff0ca2035a1bed56734a40165ab5cd7e3bd"
DEBIAN_SNAPSHOT = "20261020T213255Z"
CMAKE_VERSION = "3.31.6-2"
BUILD_TIMEOUT_SECONDS = 900
TRACER_TIMEOUT_SECONDS = 900
DOCKER_COMMAND_TIMEOUT_SECONDS = 15
TERMINATE_GRACE_SECONDS = 5
MEMORY = "2g"
MEMORY_SWAP = "2g"
CPUS = "2"
PIDS_LIMIT = "256"
TMPFS_BYTES = "2147483648"
CONTAINER_NAME_PREFIX = "genewhip-libretro-tracer-"
IMAGE_TAG_PREFIX = "genewhip-libretro-tracer:local-"
IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")


class RunnerError(RuntimeError):
    """A Docker prerequisite, command, or cleanup failed."""


class RunnerTimeout(RunnerError):
    """An owned Docker CLI command exceeded its deadline."""


def _stop_owned_process(process: subprocess.Popen[str]) -> None:
    """Stop only the Docker CLI process group started by this runner."""
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        process.wait()
    # Drain/reap after signalling so no child output pipe or process is left.
    process.communicate()


def _docker_command(docker: str, args: list[str], *, timeout: int,
                    label: str) -> subprocess.CompletedProcess[str]:
    command = [docker, *args]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
            start_new_session=(os.name == "posix"),
        )
    except OSError as error:
        raise RunnerError(f"cannot start Docker CLI for {label}: {error}") from error

    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        _stop_owned_process(process)
        raise RunnerTimeout(f"{label} exceeded its {timeout}-second deadline") from error
    except KeyboardInterrupt:
        _stop_owned_process(process)
        raise
    return subprocess.CompletedProcess(command, process.returncode, output, None)


def _require_success(result: subprocess.CompletedProcess[str], label: str) -> str:
    output = result.stdout or ""
    if result.returncode != 0:
        detail = output.strip()
        suffix = f": {detail}" if detail else ""
        raise RunnerError(f"{label} failed with status {result.returncode}{suffix}")
    return output


def _is_missing_resource(result: subprocess.CompletedProcess[str], kind: str) -> bool:
    output = result.stdout or ""
    return result.returncode != 0 and f"No such {kind}" in output


def _cleanup_owned(docker: str, container_name: str | None, image_tag: str | None) -> list[str]:
    errors: list[str] = []
    if container_name is not None:
        try:
            result = _docker_command(docker, ["container", "rm", "--force", container_name],
                                     timeout=DOCKER_COMMAND_TIMEOUT_SECONDS, label="container cleanup")
            if result.returncode != 0 and not _is_missing_resource(result, "container"):
                errors.append(f"container cleanup failed: {(result.stdout or '').strip()}")
        except (RunnerError, OSError) as error:
            errors.append(str(error))
    if image_tag is not None:
        try:
            result = _docker_command(docker, ["image", "rm", "--force", image_tag],
                                     timeout=DOCKER_COMMAND_TIMEOUT_SECONDS, label="image cleanup")
            if result.returncode != 0 and not _is_missing_resource(result, "image"):
                errors.append(f"image cleanup failed: {(result.stdout or '').strip()}")
        except (RunnerError, OSError) as error:
            errors.append(str(error))
    return errors


def _docker_path(docker_path: str | None) -> str:
    if docker_path:
        return docker_path
    found = shutil.which("docker")
    if found is None:
        raise RunnerError("Docker CLI not found; install or start Docker Desktop/Engine and retry")
    return found


def _source_sha(root: pathlib.Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"],
            text=True, capture_output=True, timeout=DOCKER_COMMAND_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise RunnerError("cannot resolve the checkout commit for the Linux tracer") from None
    source_sha = result.stdout.strip()
    if result.returncode != 0 or not SOURCE_SHA_RE.fullmatch(source_sha):
        raise RunnerError("cannot resolve the checkout commit for the Linux tracer")
    return source_sha


def run(root: pathlib.Path = ROOT, docker_path: str | None = None) -> int:
    """Build and run the tracer; return the tracer's exact exit status."""
    root = pathlib.Path(root).resolve()
    if not (root / "scripts/package_libretro.py").is_file():
        raise RunnerError("checkout root is missing scripts/package_libretro.py")
    source_sha = _source_sha(root)
    if not DOCKERFILE.is_file() or not CONTAINER_CONTEXT.is_dir():
        raise RunnerError("pinned Libretro tracer Docker build context is missing")
    if not hasattr(os, "getuid") or not hasattr(os, "getgid"):
        raise RunnerError("this runner needs host UID/GID support to select a non-root container user")
    uid, gid = os.getuid(), os.getgid()
    if uid == 0:
        raise RunnerError("refusing to run the tracer as host root; use a non-root account")

    docker = _docker_path(docker_path)
    engine = _docker_command(
        docker, ["version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"],
        timeout=DOCKER_COMMAND_TIMEOUT_SECONDS, label="Docker engine check",
    )
    engine_platform = _require_success(engine, "Docker engine check").strip()
    if not engine_platform.startswith("linux/"):
        raise RunnerError(f"Docker engine must run Linux containers; engine reports {engine_platform or 'unknown'}")

    token = uuid.uuid4().hex
    image_tag = IMAGE_TAG_PREFIX + token
    container_name = CONTAINER_NAME_PREFIX + token
    image_id: str | None = None
    cleanup_container: str | None = None
    cleanup_image: str | None = None
    primary_error: BaseException | None = None
    tracer_status: int | None = None
    cleanup_errors: list[str] = []

    try:
        with tempfile.TemporaryDirectory(prefix="genewhip-libretro-tracer-") as scratch:
            iidfile = pathlib.Path(scratch) / "image-id"
            # The tag is invocation-unique, so cleanup can remove only this
            # build's tag even if the image already has another local name.
            cleanup_image = image_tag
            build_args = [
                "build",
                "--platform=linux/amd64",
                f"--iidfile={iidfile}",
                f"--tag={image_tag}",
                f"--file={DOCKERFILE}",
                str(CONTAINER_CONTEXT),
            ]
            print("Building pinned Linux x86_64 tracer image…", flush=True)
            build_started = time.monotonic()
            build_result = _docker_command(
                docker, build_args, timeout=BUILD_TIMEOUT_SECONDS, label="tracer image build",
            )
            build_output = _require_success(build_result, "tracer image build")
            print(f"Image build completed in {time.monotonic() - build_started:.1f}s.", flush=True)
            if build_output:
                print(build_output, end="" if build_output.endswith("\n") else "\n")
            try:
                image_id = iidfile.read_text(encoding="ascii").strip()
            except OSError as error:
                raise RunnerError("Docker build succeeded without writing its image ID") from error
            if not IMAGE_ID_RE.fullmatch(image_id):
                raise RunnerError("Docker build returned an invalid image ID")

        inspect = _docker_command(
            docker, ["image", "inspect", image_id, "--format", "{{.Os}}/{{.Architecture}}"],
            timeout=DOCKER_COMMAND_TIMEOUT_SECONDS, label="tracer image inspection",
        )
        built_platform = _require_success(inspect, "tracer image inspection").strip()
        if built_platform != "linux/amd64":
            raise RunnerError(f"built tracer image must be linux/amd64; image reports {built_platform or 'unknown'}")

        mount = f"type=bind,src={root},dst=/work/source,readonly"
        tmpfs = f"/tmp:rw,exec,nosuid,nodev,size={TMPFS_BYTES},mode=1777"
        run_args = [
            "run", "--pull=never", f"--platform=linux/amd64", f"--name={container_name}", "--rm",
            "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            f"--user={uid}:{gid}", f"--cpus={CPUS}", f"--memory={MEMORY}",
            f"--memory-swap={MEMORY_SWAP}", f"--pids-limit={PIDS_LIMIT}", f"--tmpfs={tmpfs}",
            f"--mount={mount}", "--workdir=/tmp", "--env=HOME=/tmp", "--env=TMPDIR=/tmp",
            "--env=XDG_CACHE_HOME=/tmp/.cache", "--env=CMAKE_BUILD_PARALLEL_LEVEL=2",
            image_id, "python3", "-I", "/work/source/scripts/package_libretro.py",
            "--self-test", "--tracer", "--source-sha", source_sha,
        ]
        cleanup_container = container_name
        print("Running the isolated Linux x86_64 package tracer…", flush=True)
        tracer_started = time.monotonic()
        tracer = _docker_command(
            docker, run_args, timeout=TRACER_TIMEOUT_SECONDS, label="tracer run",
        )
        tracer_elapsed = time.monotonic() - tracer_started
        if tracer.stdout:
            print(tracer.stdout, end="" if tracer.stdout.endswith("\n") else "\n")
        tracer_status = tracer.returncode
        print(f"Tracer exited with status {tracer_status} in {tracer_elapsed:.1f}s.", flush=True)
    except BaseException as error:
        primary_error = error
    finally:
        cleanup_errors = _cleanup_owned(docker, cleanup_container, cleanup_image)

    if primary_error is not None:
        for cleanup_error in cleanup_errors:
            print(f"ERROR: {cleanup_error}", file=sys.stderr)
        raise primary_error
    if cleanup_errors:
        raise RunnerError("; ".join(cleanup_errors))
    if tracer_status is None:
        raise RunnerError("tracer did not produce an exit status")
    return tracer_status


def main() -> int:
    try:
        status = run()
    except KeyboardInterrupt:
        print("Interrupted; owned Docker work was stopped and cleaned up.", file=sys.stderr)
        return 130
    except RunnerError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    if status != 0:
        print(f"Tracer exited with status {status}.", file=sys.stderr)
    return status


if __name__ == "__main__":
    raise SystemExit(main())

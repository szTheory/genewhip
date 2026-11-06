#!/usr/bin/env python3
"""Daemon-free contracts for the host-clean Libretro tracer container runner."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import signal
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "scripts/ci/run_libretro_tracer_container.py"
SPEC = importlib.util.spec_from_file_location("libretro_tracer_container_runner", RUNNER_PATH)
runner = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(runner)

IMAGE_ID = "sha256:" + "a" * 64


def _completed(args, output="", status=0):
    return subprocess.CompletedProcess(args, status, output, None)


class LibretroTracerContainerContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tracer contract with spaces ")
        self.root = pathlib.Path(self.temp.name) / "checkout with spaces"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "scripts/package_libretro.py").write_text("# source fixture\n", encoding="utf-8")
        subprocess.run(["git", "init", "--quiet", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Genewhip Test"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "scripts/package_libretro.py"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "--quiet", "-m", "fixture"], check=True)
        self.source_sha = subprocess.check_output(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True,
        ).strip()
        self.fake_bin = pathlib.Path(self.temp.name) / "fake docker bin"
        self.fake_bin.mkdir()
        self.docker = self.fake_bin / "docker"
        self.log = pathlib.Path(self.temp.name) / "docker-argv.jsonl"
        self.docker.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['FAKE_DOCKER_LOG'], 'a', encoding='utf-8') as stream:\n"
            "    stream.write(json.dumps(args) + '\\n')\n"
            "if args[:2] == ['version', '--format']:\n"
            "    print('linux/arm64')\n"
            "elif args and args[0] == 'build':\n"
            "    path = next(item.split('=', 1)[1] for item in args if item.startswith('--iidfile='))\n"
            "    pathlib.Path(path).write_text('" + IMAGE_ID + "\\n', encoding='ascii')\n"
            "    print('python3 3.13.5; gcc 14.4.0; cmake 3.31.6')\n"
            "elif args[:2] == ['image', 'inspect']:\n"
            "    print('linux/amd64')\n"
            "elif args and args[0] == 'run':\n"
            "    sys.exit(int(os.environ.get('FAKE_RUN_EXIT', '0')))\n"
            "elif args[:2] in (['container', 'rm'], ['image', 'rm']):\n"
            "    pass\n"
            "else:\n"
            "    print('unexpected fake Docker command: ' + repr(args), file=sys.stderr)\n"
            "    sys.exit(64)\n",
            encoding="utf-8",
        )
        self.docker.chmod(0o755)

    def tearDown(self):
        self.temp.cleanup()

    def calls(self):
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def run_runner(self, env=None):
        with mock.patch.dict("os.environ", {"FAKE_DOCKER_LOG": str(self.log), **(env or {})}):
            return runner.run(root=self.root, docker_path=str(self.docker))

    def test_build_pins_context_and_run_isolated_image_id(self):
        self.assertEqual(self.run_runner(), 0)
        calls = self.calls()
        build = next(call for call in calls if call[0] == "build")
        self.assertEqual(build[1], "--platform=linux/amd64")
        self.assertEqual(build[-1], str(runner.CONTAINER_CONTEXT))
        self.assertEqual(build[-2], f"--file={runner.DOCKERFILE}")
        self.assertEqual(pathlib.Path(build[-1]), runner.CONTAINER_CONTEXT)
        dockerfile = runner.DOCKERFILE.read_text(encoding="utf-8")
        dockerignore = (runner.CONTAINER_CONTEXT / ".dockerignore").read_text(encoding="utf-8")
        self.assertIn(runner.BASE_IMAGE, dockerfile)
        self.assertIn(runner.DEBIAN_SNAPSHOT, dockerfile)
        self.assertIn(runner.CMAKE_VERSION, dockerfile)
        self.assertFalse(any(line.lstrip().upper().startswith(("COPY ", "ADD "))
                             for line in dockerfile.splitlines()))
        self.assertEqual(dockerignore, "*\n!Dockerfile\n!.dockerignore\n")

        inspect = next(call for call in calls if call[:2] == ["image", "inspect"])
        self.assertEqual(inspect[2], IMAGE_ID)
        run = next(call for call in calls if call[0] == "run")
        self.assertIn("--pull=never", run)
        self.assertIn("--platform=linux/amd64", run)
        self.assertIn("--network=none", run)
        self.assertIn("--read-only", run)
        self.assertIn("--cap-drop=ALL", run)
        self.assertIn("--security-opt=no-new-privileges", run)
        self.assertIn("--cpus=2", run)
        self.assertIn("--memory=2g", run)
        self.assertIn("--memory-swap=2g", run)
        self.assertIn("--pids-limit=256", run)
        self.assertIn("--tmpfs=/tmp:rw,exec,nosuid,nodev,size=2147483648,mode=1777", run)
        self.assertIn(f"--mount=type=bind,src={self.root.resolve()},dst=/work/source,readonly", run)
        self.assertTrue(any(arg.startswith("--user=") for arg in run))
        self.assertIn("--env=CMAKE_BUILD_PARALLEL_LEVEL=2", run)
        self.assertIn(IMAGE_ID, run)
        self.assertEqual(run[-7:], ["python3", "-I", "/work/source/scripts/package_libretro.py",
                                    "--self-test", "--tracer", "--source-sha", self.source_sha])
        self.assertNotIn("--library", run)
        self.assertFalse(any("docker.sock" in arg for call in calls for arg in call))
        mounts = [arg for arg in run if arg.startswith("--mount=")]
        self.assertEqual(len(mounts), 1)
        container_rm = next(call for call in calls if call[:2] == ["container", "rm"])
        image_rm = next(call for call in calls if call[:2] == ["image", "rm"])
        self.assertEqual(container_rm[-1], next(arg.split("=", 1)[1] for arg in run if arg.startswith("--name=")))
        self.assertEqual(image_rm[-1], next(arg.split("=", 1)[1] for arg in build if arg.startswith("--tag=")))

    def test_tracer_exit_status_is_propagated_after_owned_cleanup(self):
        self.assertEqual(self.run_runner({"FAKE_RUN_EXIT": "17"}), 17)
        calls = self.calls()
        self.assertTrue(any(call[:2] == ["container", "rm"] for call in calls))
        self.assertTrue(any(call[:2] == ["image", "rm"] for call in calls))

    def test_build_and_run_use_separate_deadlines(self):
        seen = []

        def command(_docker, args, *, timeout, label):
            seen.append((args, timeout, label))
            if args[0] == "build":
                iidfile = pathlib.Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--iidfile=")))
                iidfile.write_text(IMAGE_ID + "\n", encoding="ascii")
            if args[:2] == ["version", "--format"]:
                return _completed(args, "linux/arm64\n")
            if args[:2] == ["image", "inspect"]:
                return _completed(args, "linux/amd64\n")
            return _completed(args)

        with mock.patch.object(runner, "_docker_command", side_effect=command):
            self.assertEqual(runner.run(root=self.root, docker_path="docker"), 0)
        self.assertEqual(next(row[1] for row in seen if row[2] == "tracer image build"), 900)
        self.assertEqual(next(row[1] for row in seen if row[2] == "tracer run"), 900)
        self.assertTrue(all(timeout == 15 for _args, timeout, label in seen
                            if label in ("Docker engine check", "tracer image inspection",
                                         "container cleanup", "image cleanup")))

    def test_build_timeout_cleans_only_its_unique_tag(self):
        seen = []

        def command(_docker, args, *, timeout, label):
            seen.append((args, timeout, label))
            if args[:2] == ["version", "--format"]:
                return _completed(args, "linux/arm64\n")
            if args[0] == "build":
                raise runner.RunnerTimeout("tracer image build exceeded its 900-second deadline")
            return _completed(args)

        with mock.patch.object(runner, "_docker_command", side_effect=command):
            with self.assertRaisesRegex(runner.RunnerTimeout, "900-second"):
                runner.run(root=self.root, docker_path="docker")
        self.assertFalse(any(args[0] == "container" for args, _timeout, _label in seen))
        cleanup = next(args for args, _timeout, label in seen if label == "image cleanup")
        build = next(args for args, _timeout, label in seen if label == "tracer image build")
        self.assertEqual(cleanup[-1], next(arg.split("=", 1)[1] for arg in build if arg.startswith("--tag=")))

    def test_run_timeout_and_interrupt_cleanup_only_owned_container_and_tag(self):
        for failure in (runner.RunnerTimeout("tracer run exceeded its 900-second deadline"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                seen = []

                def command(_docker, args, *, timeout, label):
                    seen.append((args, timeout, label))
                    if args[:2] == ["version", "--format"]:
                        return _completed(args, "linux/arm64\n")
                    if args[0] == "build":
                        pathlib.Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--iidfile="))) \
                            .write_text(IMAGE_ID + "\n", encoding="ascii")
                    if args[:2] == ["image", "inspect"]:
                        return _completed(args, "linux/amd64\n")
                    if args[0] == "run":
                        raise failure
                    return _completed(args)

                with mock.patch.object(runner, "_docker_command", side_effect=command):
                    with self.assertRaises(type(failure)):
                        runner.run(root=self.root, docker_path="docker")
                cleanup = [args for args, _timeout, label in seen if label == "container cleanup"]
                self.assertEqual(len(cleanup), 1)
                run = next(args for args, _timeout, label in seen if label == "tracer run")
                self.assertEqual(cleanup[0][-1], next(arg.split("=", 1)[1] for arg in run if arg.startswith("--name=")))

    def test_cleanup_timeout_is_a_failure(self):
        def command(_docker, args, *, timeout, label):
            if args[:2] == ["version", "--format"]:
                return _completed(args, "linux/arm64\n")
            if args[0] == "build":
                pathlib.Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--iidfile="))) \
                    .write_text(IMAGE_ID + "\n", encoding="ascii")
            if args[:2] == ["image", "inspect"]:
                return _completed(args, "linux/amd64\n")
            if label == "container cleanup":
                raise runner.RunnerTimeout("container cleanup exceeded its 15-second deadline")
            return _completed(args)

        with mock.patch.object(runner, "_docker_command", side_effect=command):
            with self.assertRaisesRegex(runner.RunnerError, "cleanup"):
                runner.run(root=self.root, docker_path="docker")

    def test_docker_timeout_kills_only_its_process_group_and_reaps_it(self):
        process = mock.Mock(pid=43123, returncode=-signal.SIGKILL)
        process.communicate.side_effect = [subprocess.TimeoutExpired(["docker", "build"], 900), ("", None)]
        process.wait.side_effect = [subprocess.TimeoutExpired(["docker", "build"], 5), None]
        with mock.patch.object(runner.subprocess, "Popen", return_value=process) as popen, \
                mock.patch.object(runner.os, "killpg") as killpg:
            with self.assertRaises(runner.RunnerTimeout):
                runner._docker_command("docker", ["build"], timeout=900, label="tracer image build")
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertEqual(killpg.call_args_list, [
            mock.call(43123, signal.SIGTERM), mock.call(43123, signal.SIGKILL),
        ])
        self.assertEqual(process.communicate.call_count, 2)

    def test_keyboard_interrupt_stops_only_its_process_group_and_reaps_it(self):
        process = mock.Mock(pid=43124, returncode=0)
        process.communicate.side_effect = [KeyboardInterrupt(), ("", None)]
        process.wait.return_value = None
        with mock.patch.object(runner.subprocess, "Popen", return_value=process) as popen, \
                mock.patch.object(runner.os, "killpg") as killpg:
            with self.assertRaises(KeyboardInterrupt):
                runner._docker_command("docker", ["run"], timeout=900, label="tracer run")
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(killpg.call_args_list, [mock.call(43124, signal.SIGTERM)])
        self.assertEqual(process.communicate.call_count, 2)

    def test_engine_and_image_architecture_are_checked(self):
        with mock.patch.object(runner, "_docker_command", return_value=_completed([], "darwin/arm64\n")):
            with self.assertRaisesRegex(runner.RunnerError, "must run Linux"):
                runner.run(root=self.root, docker_path="docker")


if __name__ == "__main__":
    unittest.main()

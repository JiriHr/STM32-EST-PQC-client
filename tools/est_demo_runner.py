#!/usr/bin/env python3
"""
Single-entry runner for the Lamassu PQC EST STM demo.

This script intentionally orchestrates existing tools instead of replacing them:
- starts Lamassu monolithic development server
- waits for the HTTP API to become reachable
- runs the Lamassu PQC STM setup script non-interactively
- optionally runs a user-provided flash command
- starts the UART TCP proxy used by the STM firmware
"""

from __future__ import annotations

import argparse
import os
import shlex
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LAMASSU_DIR = REPO_ROOT / "dp-lamassupqc-EST" / "lamassuiot"
DEFAULT_BASE_URL = "http://127.0.0.1:8080"
DEFAULT_PROXY = REPO_ROOT / "EST_Python" / "EST_networking.py"


def log(message: str) -> None:
    print(f"[est-demo] {message}", flush=True)


def fail(message: str, code: int = 1) -> None:
    print(f"[est-demo] ERROR: {message}", file=sys.stderr, flush=True)
    raise SystemExit(code)


def command_exists(name: str) -> bool:
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(entry) / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return True
    return False


def require_command(name: str) -> None:
    if not command_exists(name):
        fail(f"required command not found in PATH: {name}")


def wait_for_http(base_url: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base_url, timeout=2):
                return
        except urllib.error.HTTPError:
            return
        except Exception as exc:
            last_error = exc
            time.sleep(1)

    fail(f"Lamassu did not become reachable at {base_url}: {last_error}")


def run_checked(
    name: str,
    cmd: list[str],
    cwd: Path | None = None,
    stdin: str | None = None,
) -> None:
    log(f"running {name}: {shlex.join(cmd)}")
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        input=stdin,
        text=True,
    )
    if result.returncode != 0:
        fail(f"{name} failed with exit code {result.returncode}", result.returncode)


def start_process(name: str, cmd: list[str], cwd: Path | None = None) -> subprocess.Popen[str]:
    log(f"starting {name}: {shlex.join(cmd)}")
    return subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        text=True,
        start_new_session=True,
    )


def stop_process(name: str, proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return

    log(f"stopping {name}")
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)


def setup_answers(base_url: str, alg: str) -> str:
    if base_url == DEFAULT_BASE_URL:
        return f"y\n{alg}\ny\n"
    return f"n\n{base_url}\n{alg}\ny\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the Lamassu PQC EST STM demo from one command."
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--alg", choices=("44", "65", "87"), default="44")
    parser.add_argument("--lamassu-dir", type=Path, default=DEFAULT_LAMASSU_DIR)
    parser.add_argument("--proxy-script", type=Path, default=DEFAULT_PROXY)
    parser.add_argument("--serial-port", help="serial device for the STM proxy, e.g. /dev/ttyACM0")
    parser.add_argument("--baudrate", default="115200")
    parser.add_argument("--flash-cmd", help="optional command to flash the STM firmware before starting the proxy")
    parser.add_argument("--skip-lamassu", action="store_true", help="assume Lamassu is already running")
    parser.add_argument("--skip-setup", action="store_true", help="do not run PQCscripts/setup_stm.sh")
    parser.add_argument("--skip-proxy", action="store_true", help="do not start the UART proxy")
    parser.add_argument("--no-wait", action="store_true", help="exit after starting requested background processes")
    parser.add_argument("--lamassu-timeout", type=float, default=90.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    lamassu_dir = args.lamassu_dir.resolve()
    proxy_script = args.proxy_script.resolve()
    lamassu_proc: subprocess.Popen[str] | None = None
    proxy_proc: subprocess.Popen[str] | None = None
    leave_processes_running = False

    if not args.skip_lamassu and not lamassu_dir.exists():
        fail(f"Lamassu directory does not exist: {lamassu_dir}")
    if not args.skip_proxy and not proxy_script.exists():
        fail(f"proxy script does not exist: {proxy_script}")

    require_command("python3")

    try:
        if not args.skip_lamassu:
            require_command("go")
            lamassu_proc = start_process(
                "Lamassu",
                ["go", "run", "./monolithic/cmd/development/main.go"],
                cwd=lamassu_dir,
            )
            wait_for_http(args.base_url, args.lamassu_timeout)
            log(f"Lamassu is reachable at {args.base_url}")
        else:
            log("skipping Lamassu start")
            wait_for_http(args.base_url, args.lamassu_timeout)

        if not args.skip_setup:
            require_command("curl")
            require_command("jq")
            setup_script = lamassu_dir / "PQCscripts" / "setup_stm.sh"
            if not setup_script.exists():
                fail(f"setup script does not exist: {setup_script}")
            run_checked(
                "Lamassu PQC STM setup",
                ["bash", str(setup_script)],
                cwd=setup_script.parent,
                stdin=setup_answers(args.base_url, args.alg),
            )
        else:
            log("skipping Lamassu PQC setup")

        if args.flash_cmd:
            run_checked("STM flash command", shlex.split(args.flash_cmd), cwd=REPO_ROOT)
        else:
            log("no flash command provided; assuming STM firmware is already flashed")

        if not args.skip_proxy:
            proxy_cmd = [sys.executable, str(proxy_script), "--baudrate", args.baudrate]
            if args.serial_port:
                proxy_cmd.extend(["--port", args.serial_port])
            proxy_proc = start_process("UART proxy", proxy_cmd, cwd=REPO_ROOT)
        else:
            log("skipping UART proxy")

        if args.no_wait:
            leave_processes_running = True
            return 0

        log("demo services are running. Press Ctrl+C to stop.")
        while True:
            if lamassu_proc is not None and lamassu_proc.poll() is not None:
                fail(f"Lamassu exited with code {lamassu_proc.returncode}", lamassu_proc.returncode or 1)
            if proxy_proc is not None and proxy_proc.poll() is not None:
                fail(f"UART proxy exited with code {proxy_proc.returncode}", proxy_proc.returncode or 1)
            time.sleep(1)

    except KeyboardInterrupt:
        log("interrupted")
        return 130
    finally:
        if not leave_processes_running:
            if proxy_proc is not None:
                stop_process("UART proxy", proxy_proc)
            if lamassu_proc is not None:
                stop_process("Lamassu", lamassu_proc)


if __name__ == "__main__":
    raise SystemExit(main())

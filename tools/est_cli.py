#!/usr/bin/env python3
"""
Project-level CLI for the STM32 EST demo.

This intentionally sits above STM32CubeIDE. It uses the generated Makefile when
present, can fall back to CubeIDE headless build, flashes with STM32_Programmer_CLI,
and delegates runtime services to the existing Python scripts.
"""

from __future__ import annotations

import argparse
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT_NAME = "EST"
DEFAULT_CONFIG = "Debug"
DEFAULT_ELF = REPO_ROOT / DEFAULT_CONFIG / f"{PROJECT_NAME}.elf"
DEFAULT_PROXY = REPO_ROOT / "EST_Python" / "EST_networking.py"
DEFAULT_ADHOC_RA = REPO_ROOT / "EST_Python" / "adhoc_ra" / "adhoc_est_ra.py"
DEFAULT_DEMO_RUNNER = REPO_ROOT / "tools" / "est_demo_runner.py"
PYTHON_REQUIREMENTS = REPO_ROOT / "EST_Python" / "requirements.txt"
FLASH_ADDRESS = "0x08000000"
PROFILE_DEFINES = {
    "adhoc": "EST_TARGET_ADHOC_RA",
    "lamassu": "EST_TARGET_LAMASSU_PQC_MLDSA44",
}


def log(message: str) -> None:
    print(f"[est] {message}", flush=True)


def fail(message: str, code: int = 1) -> None:
    print(f"[est] ERROR: {message}", file=sys.stderr, flush=True)
    raise SystemExit(code)


def which(name: str) -> str | None:
    return shutil.which(name)


def run(cmd: list[str], cwd: Path | None = None) -> None:
    log("running: " + " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(cwd) if cwd is not None else None)
    if result.returncode != 0:
        fail(f"command failed with exit code {result.returncode}", result.returncode)


def start_process(name: str, cmd: list[str], cwd: Path | None = None) -> subprocess.Popen[str]:
    log(f"starting {name}: " + " ".join(cmd))
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


def require_file(path: Path, description: str) -> None:
    if not path.exists():
        fail(f"{description} not found: {path}")


def has_python_module(module: str) -> bool:
    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def find_cubeide(explicit: str | None) -> str | None:
    candidates = [
        explicit,
        os.environ.get("STM32CUBEIDE"),
        which("stm32cubeide"),
        which("STM32CubeIDE"),
        "/opt/st/stm32cubeide/stm32cubeide",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def configure_generated_profile(config: str, profile: str) -> None:
    define = PROFILE_DEFINES[profile]
    build_dir = REPO_ROOT / config
    makefile = build_dir / "makefile"

    if not makefile.exists():
        return

    changed = 0
    for path in build_dir.rglob("*.mk"):
        text = path.read_text(encoding="utf-8")
        updated = text
        for profile_define in PROFILE_DEFINES.values():
            updated = updated.replace(f"-DEST_TARGET_PROFILE={profile_define}", f"-DEST_TARGET_PROFILE={define}")
        updated = updated.replace(" -fcyclomatic-complexity", "")
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            changed += 1

    if changed:
        log(f"configured generated {config} Makefiles for profile '{profile}'")


def configure_cproject_profile(profile: str) -> None:
    define = PROFILE_DEFINES[profile]
    path = REPO_ROOT / ".cproject"
    if not path.exists():
        return

    text = path.read_text(encoding="utf-8")
    updated = text
    for profile_define in PROFILE_DEFINES.values():
        updated = updated.replace(
            f'value="EST_TARGET_PROFILE={profile_define}"',
            f'value="EST_TARGET_PROFILE={define}"',
        )

    if updated != text:
        path.write_text(updated, encoding="utf-8")
        log(f"configured .cproject for profile '{profile}'")


def install_debian_packages(packages: list[str]) -> None:
    if which("apt-get") is None:
        fail("automatic package install currently supports Debian/Ubuntu/Mint systems with apt-get")

    sudo = []
    if os.geteuid() != 0:
        sudo = ["sudo"]

    run(sudo + ["apt-get", "update"])
    run(sudo + ["apt-get", "install", "-y", *packages])


def install_python_requirements() -> None:
    require_file(PYTHON_REQUIREMENTS, "Python requirements file")
    run([sys.executable, "-m", "pip", "install", "-r", str(PYTHON_REQUIREMENTS)])


def command_doctor(args: argparse.Namespace) -> None:
    checks = [
        ("make", which("make")),
        ("arm-none-eabi-gcc", which("arm-none-eabi-gcc")),
        ("arm-none-eabi-size", which("arm-none-eabi-size")),
        ("arm-none-eabi-objcopy", which("arm-none-eabi-objcopy")),
        ("STM32_Programmer_CLI", which("STM32_Programmer_CLI")),
        ("st-flash", which("st-flash")),
        ("python3", which("python3")),
        ("go", which("go")),
        ("curl", which("curl")),
        ("jq", which("jq")),
    ]

    for name, path in checks:
        status = path if path else "missing"
        print(f"{name:24} {status}")

    print(f"{'active Python':24} {sys.executable}")
    print(f"{'pyserial':24} {'installed' if has_python_module('serial') else 'missing'}")

    makefile = REPO_ROOT / DEFAULT_CONFIG / "makefile"
    print(f"{'generated makefile':24} {makefile if makefile.exists() else 'missing'}")
    print(f"{'firmware elf':24} {DEFAULT_ELF if DEFAULT_ELF.exists() else 'missing'}")

    if args.install:
        command_install_deps(args)


def command_install_deps(_: argparse.Namespace) -> None:
    apt_packages = []
    if which("make") is None:
        apt_packages.append("make")
    if which("arm-none-eabi-gcc") is None or which("arm-none-eabi-size") is None or which("arm-none-eabi-objcopy") is None:
        apt_packages.append("gcc-arm-none-eabi")
    if which("st-flash") is None:
        apt_packages.append("stlink-tools")
    if which("curl") is None:
        apt_packages.append("curl")
    if which("jq") is None:
        apt_packages.append("jq")

    if apt_packages:
        install_debian_packages(apt_packages)
    else:
        log("apt-installable tools are already present")

    if not has_python_module("serial"):
        install_python_requirements()
    else:
        log("Python requirements are already present")

    if which("STM32_Programmer_CLI") is None:
        log(
            "STM32_Programmer_CLI is still missing. That is acceptable if you use "
            "`./scripts/est flash --tool stlink`; otherwise install STM32CubeProgrammer "
            "from ST and add its bin directory to PATH."
        )


def command_build(args: argparse.Namespace) -> None:
    config = args.config
    build_dir = REPO_ROOT / config
    makefile = build_dir / "makefile"
    configure_cproject_profile(args.profile)
    configure_generated_profile(config, args.profile)

    if makefile.exists() and not args.cubeide:
        if which("make") is None:
            fail("make is required for generated Makefile builds")
        if which("arm-none-eabi-gcc") is None:
            fail("arm-none-eabi-gcc is required. Install GNU Arm Embedded or STM32CubeIDE toolchain.")
        cmd = ["make", "-C", str(build_dir), f"-j{args.jobs}", "all"]
        if args.clean:
            run(["make", "-C", str(build_dir), "clean"])
        run(cmd)
        return

    cubeide = find_cubeide(args.cubeide_path)
    if cubeide is None:
        fail(
            "no generated Makefile was found and STM32CubeIDE was not found. "
            "Install STM32CubeIDE or build once in the IDE to generate the Makefile."
        )

    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    build_target = f"{PROJECT_NAME}/{config}"
    cmd = [
        cubeide,
        "--launcher.suppressErrors",
        "-nosplash",
        "-application",
        "org.eclipse.cdt.managedbuilder.core.headlessbuild",
        "-data",
        str(workspace),
        "-import",
        str(REPO_ROOT),
    ]
    if args.clean:
        cmd.extend(["-cleanBuild", build_target])
    else:
        cmd.extend(["-build", build_target])
    run(cmd)


def command_flash(args: argparse.Namespace) -> None:
    elf = args.elf.resolve()
    require_file(elf, "firmware ELF")

    tool = args.tool
    if tool == "auto":
        if args.programmer or which("STM32_Programmer_CLI"):
            tool = "stm32programmer"
        elif which("st-flash"):
            tool = "stlink"
        else:
            fail("no flash tool found. Install STM32CubeProgrammer or run `./scripts/est doctor --install` for stlink-tools.")

    if tool == "stm32programmer":
        programmer = args.programmer or which("STM32_Programmer_CLI")
        if programmer is None:
            fail("STM32_Programmer_CLI is required for `--tool stm32programmer`")
        run(
            [
                programmer,
                "-c",
                f"port={args.port}",
                "mode=UR",
                "reset=HWrst",
                "-w",
                str(elf),
                "-v",
                "-rst",
            ]
        )
        return

    if tool == "stlink":
        objcopy = which("arm-none-eabi-objcopy")
        st_flash = which("st-flash")
        if objcopy is None:
            fail("arm-none-eabi-objcopy is required for `--tool stlink`")
        if st_flash is None:
            fail("st-flash is required for `--tool stlink`; run `./scripts/est doctor --install`")

        with tempfile.TemporaryDirectory(prefix="est-flash-") as tmp:
            bin_path = Path(tmp) / "EST.bin"
            run([objcopy, "-O", "binary", str(elf), str(bin_path)])
            run([st_flash, "--reset", "write", str(bin_path), FLASH_ADDRESS])
        return

    fail(f"unsupported flash tool: {tool}")


def reset_board() -> bool:
    st_flash = which("st-flash")
    if st_flash is not None:
        run([st_flash, "reset"])
        return True

    programmer = which("STM32_Programmer_CLI")
    if programmer is not None:
        run([programmer, "-c", "port=SWD", "mode=UR", "reset=HWrst", "-rst"])
        return True

    return False


def start_stm_log_monitor(reset: bool, clock: str, trace: str) -> subprocess.Popen[str] | None:
    st_trace = which("st-trace")
    if st_trace is None:
        log("st-trace not found; STM ITM log monitor is unavailable")
        return None

    cmd = [st_trace, f"--clock={clock}", f"--trace={trace}"]
    if not reset:
        cmd.append("--no-reset")
    return start_process("STM ITM log", cmd, cwd=REPO_ROOT)


def command_proxy(args: argparse.Namespace) -> None:
    require_file(DEFAULT_PROXY, "UART proxy script")
    cmd = [sys.executable, str(DEFAULT_PROXY), "--baudrate", str(args.baudrate)]
    if args.serial_port:
        cmd.extend(["--port", args.serial_port])
    if args.verbose:
        cmd.append("--verbose")
    run(cmd, cwd=REPO_ROOT)


def command_adhoc_ra(args: argparse.Namespace) -> None:
    require_file(DEFAULT_ADHOC_RA, "ad-hoc RA script")
    cmd = [
        sys.executable,
        str(DEFAULT_ADHOC_RA),
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]
    if args.cert:
        cmd.extend(["--cert", args.cert])
    if args.key:
        cmd.extend(["--key", args.key])
    run(cmd, cwd=REPO_ROOT)


def command_demo(args: argparse.Namespace) -> None:
    require_file(DEFAULT_DEMO_RUNNER, "demo runner")
    cmd = [sys.executable, str(DEFAULT_DEMO_RUNNER)]
    if args.serial_port:
        cmd.extend(["--serial-port", args.serial_port])
    cmd.extend(["--baudrate", str(args.baudrate)])
    if args.flash:
        cmd.extend(["--flash-cmd", f"{sys.executable} {Path(__file__).resolve()} flash"])
    if args.skip_lamassu:
        cmd.append("--skip-lamassu")
    if args.skip_setup:
        cmd.append("--skip-setup")
    if args.skip_proxy:
        cmd.append("--skip-proxy")
    run(cmd, cwd=REPO_ROOT)


def command_adhoc_demo(args: argparse.Namespace) -> None:
    require_file(DEFAULT_ADHOC_RA, "ad-hoc RA script")
    require_file(DEFAULT_PROXY, "UART proxy script")

    if args.build:
        build_args = argparse.Namespace(
            config=DEFAULT_CONFIG,
            jobs=os.cpu_count() or 4,
            clean=args.clean,
            cubeide=False,
            cubeide_path=None,
            workspace=REPO_ROOT / ".stm32cubeide-workspace",
            profile="adhoc",
        )
        command_build(build_args)

    if args.flash:
        flash_args = argparse.Namespace(
            elf=DEFAULT_ELF,
            port="SWD",
            tool="auto",
            programmer=None,
        )
        command_flash(flash_args)

    ra_cmd = [
        sys.executable,
        str(DEFAULT_ADHOC_RA),
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]
    proxy_cmd = [sys.executable, str(DEFAULT_PROXY), "--baudrate", str(args.baudrate)]
    if args.serial_port:
        proxy_cmd.extend(["--port", args.serial_port])
    if args.proxy_verbose:
        proxy_cmd.append("--verbose")

    ra_proc: subprocess.Popen[str] | None = None
    proxy_proc: subprocess.Popen[str] | None = None
    stm_log_proc: subprocess.Popen[str] | None = None

    try:
        ra_proc = start_process("ad-hoc EST RA", ra_cmd, cwd=REPO_ROOT)
        time.sleep(0.5)
        if ra_proc.poll() is not None:
            fail(f"ad-hoc EST RA exited with code {ra_proc.returncode}", ra_proc.returncode or 1)

        proxy_proc = start_process("UART proxy", proxy_cmd, cwd=REPO_ROOT)

        if args.stm_log:
            log("starting STM ITM log monitor")
            stm_log_proc = start_stm_log_monitor(
                reset=args.reset,
                clock=args.stm_clock,
                trace=args.stm_trace,
            )
            if stm_log_proc is None and args.reset:
                log("resetting board now that ad-hoc RA and UART proxy are ready")
                if not reset_board():
                    log("no reset tool found; reset the board manually now")
        elif args.reset:
            log("resetting board now that ad-hoc RA and UART proxy are ready")
            if not reset_board():
                log("no reset tool found; reset the board manually now")

        log("ad-hoc demo services are running. Press Ctrl+C to stop.")
        while True:
            if ra_proc.poll() is not None:
                fail(f"ad-hoc EST RA exited with code {ra_proc.returncode}", ra_proc.returncode or 1)
            if proxy_proc.poll() is not None:
                fail(f"UART proxy exited with code {proxy_proc.returncode}", proxy_proc.returncode or 1)
            if stm_log_proc is not None and stm_log_proc.poll() is not None:
                log(f"STM ITM log monitor exited with code {stm_log_proc.returncode}; continuing without STM log output")
                stm_log_proc = None
            time.sleep(1)
    except KeyboardInterrupt:
        log("interrupted")
    finally:
        if proxy_proc is not None:
            stop_process("UART proxy", proxy_proc)
        if stm_log_proc is not None:
            stop_process("STM ITM log", stm_log_proc)
        if ra_proc is not None:
            stop_process("ad-hoc EST RA", ra_proc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Top-level runner for the STM32 EST demo")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="check local tools and generated artifacts")
    doctor.add_argument("--install", action="store_true", help="install missing apt/Python requirements where possible")
    doctor.set_defaults(func=command_doctor)

    install = sub.add_parser("install-deps", help="install missing host-side requirements where possible")
    install.set_defaults(func=command_install_deps)

    build = sub.add_parser("build", help="build firmware without opening STM32CubeIDE")
    build.add_argument("--config", default=DEFAULT_CONFIG)
    build.add_argument("--profile", choices=tuple(PROFILE_DEFINES), default="adhoc")
    build.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    build.add_argument("--clean", action="store_true")
    build.add_argument("--cubeide", action="store_true", help="force STM32CubeIDE headless build")
    build.add_argument("--cubeide-path", help="path to stm32cubeide executable")
    build.add_argument("--workspace", type=Path, default=REPO_ROOT / ".stm32cubeide-workspace")
    build.set_defaults(func=command_build)

    flash = sub.add_parser("flash", help="flash the built firmware over ST-LINK")
    flash.add_argument("--elf", type=Path, default=DEFAULT_ELF)
    flash.add_argument("--port", default="SWD")
    flash.add_argument("--tool", choices=("auto", "stm32programmer", "stlink"), default="auto")
    flash.add_argument("--programmer", help="path to STM32_Programmer_CLI")
    flash.set_defaults(func=command_flash)

    proxy = sub.add_parser("proxy", help="start the UART-to-TCP proxy")
    proxy.add_argument("--serial-port", help="serial device, e.g. /dev/ttyACM0")
    proxy.add_argument("--baudrate", type=int, default=115200)
    proxy.add_argument("--verbose", action="store_true", help="print raw UART/TCP proxy byte flow")
    proxy.set_defaults(func=command_proxy)

    adhoc = sub.add_parser("adhoc-ra", help="start the local ad-hoc EST RA")
    adhoc.add_argument("--host", default="127.0.0.1")
    adhoc.add_argument("--port", type=int, default=8443)
    adhoc.add_argument("--cert")
    adhoc.add_argument("--key")
    adhoc.set_defaults(func=command_adhoc_ra)

    demo = sub.add_parser("demo", help="run the Lamassu EST demo orchestration")
    demo.add_argument("--serial-port", help="serial device, e.g. /dev/ttyACM0")
    demo.add_argument("--baudrate", type=int, default=115200)
    demo.add_argument("--flash", action="store_true", help="flash firmware before starting runtime services")
    demo.add_argument("--skip-lamassu", action="store_true")
    demo.add_argument("--skip-setup", action="store_true")
    demo.add_argument("--skip-proxy", action="store_true")
    demo.set_defaults(func=command_demo)

    adhoc_demo = sub.add_parser("adhoc-demo", help="run the local ad-hoc EST RA flow")
    adhoc_demo.add_argument("--serial-port", help="serial device, e.g. /dev/ttyACM0")
    adhoc_demo.add_argument("--baudrate", type=int, default=115200)
    adhoc_demo.add_argument("--host", default="127.0.0.1")
    adhoc_demo.add_argument("--port", type=int, default=8443)
    adhoc_demo.add_argument("--build", action="store_true", help="build firmware for the ad-hoc profile before running")
    adhoc_demo.add_argument("--clean", action="store_true", help="clean before building when --build is used")
    adhoc_demo.add_argument("--flash", action="store_true", help="flash firmware before starting runtime services")
    adhoc_demo.add_argument("--reset", dest="reset", action="store_true", default=True, help="reset the board after host services start")
    adhoc_demo.add_argument("--no-reset", dest="reset", action="store_false", help="do not reset the board after host services start")
    adhoc_demo.add_argument("--stm-log", action="store_true", help="show STM printf output via ST-LINK ITM/SWV using st-trace")
    adhoc_demo.add_argument("--stm-clock", default="64m", help="core clock passed to st-trace, e.g. 64m")
    adhoc_demo.add_argument("--stm-trace", default="100k", help="trace clock passed to st-trace, e.g. 100k, 500k, 2m")
    adhoc_demo.add_argument("--proxy-verbose", action="store_true", help="print raw UART/TCP proxy byte flow")
    adhoc_demo.set_defaults(func=command_adhoc_demo)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

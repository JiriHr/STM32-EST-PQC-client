# EST STM32 Demo

This project is an STM32WB55 EST client demo with ML-DSA-44 CSR generation,
EST enrollment, a UART-to-TCP TLS transport proxy, and two runnable RA paths:

- `adhoc`: local Python ad-hoc EST RA, fastest path for STM/client testing.
- `lamassu`: Lamassu PQC EST flow from the `dp-lamassupqc-EST` submodule.

Use `./scripts/est` for normal build, flash, setup, and run tasks. You should
not need to open STM32CubeIDE for the usual workflow.

## Dependencies

Required host tools depend on what you run:

- Firmware build: `make`, `arm-none-eabi-gcc`, `arm-none-eabi-size`
- Flashing: either `STM32_Programmer_CLI`, or `st-flash` plus `arm-none-eabi-objcopy`
- UART proxy and ad-hoc RA: Python 3 and `pyserial`
- Lamassu setup: Go, Docker, `curl`, `jq`
- Lamassu source: initialized `dp-lamassupqc-EST` git submodule

Check your environment with:

```sh
./scripts/est doctor
```

On Debian/Ubuntu/Mint systems, the CLI can install the apt/Python pieces:

```sh
./scripts/est doctor --install
```

This installs `gcc-arm-none-eabi`, `stlink-tools`, `curl`, `jq`, and Python
requirements when missing. STM32CubeProgrammer is distributed by ST, not through
normal apt repositories; install it manually only if you want to use
`STM32_Programmer_CLI`. The flash command auto-selects `STM32_Programmer_CLI`
when present, otherwise `st-flash`.

If a pyenv environment named `EST` exists, `./scripts/est` uses it
automatically. To force a different interpreter:

```sh
EST_PYTHON=/path/to/python3 ./scripts/est doctor
```

## Command Reference

```sh
./scripts/est doctor
```
Checks required tools, Python modules, generated Makefile, firmware ELF, and
Lamassu submodule/setup script presence.

```sh
./scripts/est doctor --install
./scripts/est install-deps
```
Installs missing apt/Python dependencies where supported.

```sh
./scripts/est build --profile adhoc --clean
./scripts/est build --profile lamassu --clean
```
Builds firmware using the generated `Debug/makefile`. The profile selects the
firmware target:

- `adhoc`: DMS/APS ID `est-ra`, TLS client certificate enabled
- `lamassu`: DMS/APS ID `mldsa44-est-dms`, Lamassu PQC flow

If the generated Makefile is missing, a headless STM32CubeIDE build can be used:

```sh
./scripts/est build --cubeide
```

```sh
./scripts/est flash
./scripts/est flash --tool stlink
./scripts/est flash --elf Debug/EST.elf
```
Flashes the built firmware over ST-LINK.

```sh
./scripts/est proxy --serial-port /dev/ttyACM0
```
Starts only the UART-to-TCP proxy.

```sh
./scripts/est adhoc-ra
```
Starts only the local Python ad-hoc EST RA.

```sh
./scripts/est adhoc-demo --serial-port /dev/ttyACM0
```
Starts the ad-hoc RA and UART proxy, then resets the board.

```sh
./scripts/est lamassu-setup --alg 44
```
Configures an already running Lamassu instance for the STM demo by running
`dp-lamassupqc-EST/lamassuiot/PQCscripts/setup_stm.sh`.

```sh
./scripts/est lamassu-run --serial-port /dev/ttyACM0
```
Starts the UART proxy for a running/configured Lamassu instance, then resets the
board.

```sh
./scripts/est demo --serial-port /dev/ttyACM0
```
Legacy one-command Lamassu orchestration. Prefer the split Lamassu workflow
below when debugging.

Useful options:

- `--build`: build before running, available on `adhoc-demo` and `lamassu-run`
- `--flash`: flash before running, available on `adhoc-demo` and `lamassu-run`
- `--no-reset`: do not reset the board after host services start
- `--proxy-verbose`: show raw UART/TCP byte-flow logs
- `--stm-log`: attempt ITM/SWV logging with `st-trace`

The normal UART proxy is quiet about raw TLS transport bytes, but it prints STM
firmware `printf` output carried in UART log frames. Use `--proxy-verbose` only
when debugging the transport itself. The ITM/SWV monitor is optional and may be
unreliable on some host setups.

## Run The Ad-Hoc Version

Use this path first when validating the STM firmware and EST client behavior.
It avoids Lamassu and runs everything locally in Python.

```sh
./scripts/est build --profile adhoc --clean
./scripts/est flash
./scripts/est adhoc-demo --serial-port /dev/ttyACM0
```

`adhoc-demo` starts:

1. `EST_Python/adhoc_ra/adhoc_est_ra.py`
2. `EST_Python/EST_networking.py`
3. a board reset through `st-flash` or `STM32_Programmer_CLI`

The expected successful end of the STM output includes:

```text
est_client_simpleenroll OK
CMS SignedData ML-DSA-44 self-test OK
CMS EnvelopedData ML-KEM-512 + AES-128-GCM self-test OK
EST test finished
```

## Run The Lamassu PQC Version

Initialize the Lamassu PQC submodule if needed:

```sh
git submodule update --init --recursive
```

Start Lamassu manually in its own terminal so the service logs and Docker
lifecycle stay visible:

```sh
cd dp-lamassupqc-EST/lamassuiot
go run ./monolithic/cmd/development/main.go
```

In a second terminal, from the project root:

```sh
./scripts/est build --profile lamassu --clean
./scripts/est flash
./scripts/est lamassu-setup --alg 44
./scripts/est lamassu-run --serial-port /dev/ttyACM0
```

`lamassu-setup` waits for `http://127.0.0.1:8080`, then configures the
ML-DSA-44 CA/profile/DMS using the submodule setup script.

`lamassu-run` assumes Lamassu has already been started and configured. It starts
only the UART proxy, resets the board by default, and prints STM firmware output
from the UART log frames.

## Replug On Failure

The board/host USB CDC and ST-LINK state can remain stale after a previous run.
If the first run after flashing or after a failed run shows any of these:

- empty proxy reply
- TLS EOF
- `SSL - An invalid SSL record was received`
- mixed or corrupted log text
- no UART progress after reset

Stop the demo with `Ctrl+C`, unplug and reconnect the board USB cable, confirm
the serial device is still `/dev/ttyACM0` or update `--serial-port`, and rerun
`adhoc-demo` or `lamassu-run`.

In practice, the Lamassu path is most reliable if the board USB cable is
replugged after each demo run. This clears stale USB CDC/ST-LINK state and any
partial UART frames left from the previous attempt.

# EST STM32 Demo

This project is an STM32WB55 EST client demo with ML-DSA-44 CSR generation,
EST enrollment, a UART-to-TCP TLS transport proxy, and Lamassu/ad-hoc RA
runtime helpers.

Use the top-level CLI instead of opening STM32CubeIDE for normal runs:

```sh
./scripts/est doctor
./scripts/est doctor --install
./scripts/est build --profile adhoc
./scripts/est flash
./scripts/est adhoc-demo --serial-port /dev/ttyACM0
```

Useful commands:

```sh
./scripts/est doctor
./scripts/est install-deps
./scripts/est build --profile adhoc --clean
./scripts/est build --profile lamassu --clean
./scripts/est flash --elf Debug/EST.elf
./scripts/est flash --tool stlink
./scripts/est proxy --serial-port /dev/ttyACM0
./scripts/est adhoc-ra
./scripts/est adhoc-demo --serial-port /dev/ttyACM0 --build --flash
./scripts/est demo --serial-port /dev/ttyACM0 --flash
```

The build command uses `Debug/makefile` when it exists. If the generated
Makefile is missing, it can ask STM32CubeIDE to build headlessly:

```sh
./scripts/est build --cubeide
```

Required host tools depend on the command:

- Firmware build: `make`, `arm-none-eabi-gcc`, `arm-none-eabi-size`
- Flashing: `STM32_Programmer_CLI`, or `st-flash` plus `arm-none-eabi-objcopy`
- UART proxy: Python 3 and `pyserial`
- Lamassu demo orchestration: Go, `curl`, `jq`

On Debian/Ubuntu/Mint systems, the CLI can install the apt/Python pieces:

```sh
./scripts/est doctor --install
```

This installs `gcc-arm-none-eabi`, `stlink-tools`, `curl`, `jq`, and the Python
requirements if they are missing. STM32CubeProgrammer is distributed by ST, not
through the normal apt repositories; install it manually only if you want to use
`STM32_Programmer_CLI`. The default flash command auto-selects
`STM32_Programmer_CLI` when present, otherwise `st-flash`.

If a pyenv environment named `EST` exists, `./scripts/est` uses it
automatically. To force a different interpreter, set `EST_PYTHON`:

```sh
EST_PYTHON=/path/to/python3 ./scripts/est doctor
```

The firmware profiles are selected by the CLI before building:

- `adhoc`: local Python EST RA, DMS/APS ID `est-ra`, TLS client cert enabled
- `lamassu`: Lamassu PQC flow, DMS/APS ID `mldsa44-est-dms`

For the simpler local path, use:

```sh
./scripts/est build --profile adhoc --clean
./scripts/est flash
./scripts/est adhoc-demo --serial-port /dev/ttyACM0
```

`adhoc-demo` starts `EST_Python/adhoc_ra/adhoc_est_ra.py` and the UART-to-TCP
proxy, then resets the board once both host services are ready. Use
`--no-reset` if you want to reset the board manually while debugging.

The UART proxy is quiet by default about raw TLS transport bytes, but it prints
STM firmware `printf` output carried in log frames over the same UART. Use
`--proxy-verbose` only when debugging the transport itself.

The older ITM/SWV monitor is still available with `--stm-log`, but it depends on
ST-LINK/SWV support and may be unreliable on some host setups. The demo keeps
running even if that monitor exits.

If the first run after flashing or after a failed run shows an empty proxy reply,
TLS EOF, mixed log text, or no UART progress, stop the demo with `Ctrl+C`,
unplug and reconnect the board USB cable, confirm the serial device is still
`/dev/ttyACM0` or update `--serial-port`, and rerun `adhoc-demo`. This clears
stale USB CDC/ST-LINK state and any partial UART frames left from the previous
attempt.

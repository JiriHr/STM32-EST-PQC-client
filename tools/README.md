# EST Demo Runner

`est_demo_runner.py` is the older single host-side entrypoint for the Lamassu
PQC EST STM demo. The preferred workflow is now split so Lamassu can run in its
own terminal:

```bash
./scripts/est lamassu-setup --alg 44
./scripts/est lamassu-run --serial-port /dev/ttyACM0
```

The older runner still exists for one-command orchestration experiments.

Its default flow:

1. Start Lamassu monolithic development server.
2. Wait for `http://127.0.0.1:8080` to answer.
3. Run `dp-lamassupqc-EST/lamassuiot/PQCscripts/setup_stm.sh`
   non-interactively for ML-DSA-44.
4. Optionally run a user-provided STM flash command.
5. Start the UART proxy.

Legacy usage:

```bash
./scripts/run-est-demo.sh --serial-port /dev/ttyACM0
```

If Lamassu is already running:

```bash
./scripts/run-est-demo.sh --skip-lamassu --serial-port /dev/ttyACM0
```

If the STM is not flashed yet, pass the exact local flashing command:

```bash
./scripts/run-est-demo.sh \
  --serial-port /dev/ttyACM0 \
  --flash-cmd "STM32_Programmer_CLI -c port=SWD -w build/EST.elf -rst"
```

The runner does not hardcode a flashing tool because different machines may use
STM32CubeProgrammer, OpenOCD, or an IDE-generated build artifact path.

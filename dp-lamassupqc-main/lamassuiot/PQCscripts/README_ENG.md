# Quick Setup Guide

## Testing with STM

To set up the environment for STM testing, start the Lamassu monolithic development server first:

```bash
cd .../lamassuiot
go run monolithic/cmd/development/main.go
```

Wait until the following message appears:

```text
Ready to PKI
```

Then open a second terminal and run the setup script:

```bash
cd .../lamassuiotPQCscripts
./setup_stm.sh
```

The script will ask you to:

1. Select the ML-DSA version.
2. Confirm the default base URL or enter your own.

By default, the script is configured to work with:

```text
http://127.0.0.1:8080
```

The base URL must match the Lamassu configuration. If you are using the default configuration, no changes are required.

You can switch the port from `8080` to `8443` without changing the Lamassu configuration.

**Note:
> The TLS configuration is located in lamassuiot/backend/pkg/routes/utils.go, around line 140. Hybrid security is hardcoded there. For devices without TLS 1.3 support, comment out MinVersion and CurvePreferences, and uncomment MaxVersion. This will set the endpoint to the default LamassuIoT values.
---

## Solo Testing

Solo testing is intended for testing only with Lamassu, without STM.

Run one of the following commands from the `lamassuiot` directory, depending on the ML-DSA variant you want to test.

### ML-DSA-87

```bash
cd .../lamassuiot
go run ./monolithic/cmd/generate-est-mldsa87
```

### ML-DSA-65

```bash
cd .../lamassuiot
go run ./monolithic/cmd/generate-est-mldsa65
```

### ML-DSA-44

```bash
cd .../lamassuiot
go run ./monolithic/cmd/generate-est-mldsa44
```

The resulting certificate is saved as:

```text
/tmp/lamassu-est-<ML-DSA-Variant>-cert.pem
```

For ease of use, open the generated certificate directly from the terminal output.

> **Note:**  
> The solo testing configuration exits after outputting the certificate. It cannot be used for STM test runs.

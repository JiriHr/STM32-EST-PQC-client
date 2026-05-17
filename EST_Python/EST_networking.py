import argparse
import atexit
import glob
import json
import serial
import socket
import ssl
import sys
import time
from pathlib import Path

from serial.tools import list_ports

DEFAULT_BAUDRATE = 115200
UART_FRAME_LOG = 0x01
UART_FRAME_DATA = 0x02


def available_ports():
    ports = [p.device for p in list_ports.comports()]
    if ports:
        return ports

    return sorted(glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*"))


def choose_serial_port(requested_port):
    if requested_port is not None:
        return requested_port

    ports = available_ports()
    if len(ports) == 1:
        return ports[0]

    if not ports:
        raise RuntimeError(
            "no serial ports found. Connect/reset the board, then check "
            "`python EST_networking.py --list-ports` or pass `--port /dev/ttyACM1`."
        )

    raise RuntimeError(
        "multiple serial ports found; choose one with --port:\n  " +
        "\n  ".join(ports)
    )


def parse_args():
    parser = argparse.ArgumentParser(description="UART-to-TCP proxy for STM32 EST testing")
    parser.add_argument("--port", help="serial device, e.g. /dev/ttyACM0")
    parser.add_argument("--baudrate", type=int, default=DEFAULT_BAUDRATE)
    parser.add_argument("--list-ports", action="store_true", help="list detected serial ports and exit")
    parser.add_argument("--verbose", action="store_true", help="print raw UART/TCP proxy byte flow")
    parser.add_argument("--measure-log", type=Path, help="append UART proxy measurements as JSONL")
    return parser.parse_args()


args = parse_args()
if args.list_ports:
    ports = available_ports()
    if ports:
        print("\n".join(ports))
    else:
        print("No serial ports found")
    sys.exit(0)

try:
    serial_port = choose_serial_port(args.port)
    ser = serial.Serial(serial_port, args.baudrate, timeout=0.1)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
except Exception as e:
    print(f"Could not open serial port: {e}", file=sys.stderr)
    sys.exit(2)

sock = None
connected = False
started_at = time.monotonic()
started_at_ns = time.monotonic_ns()
reported_waiting = False
connection_id = 0
active_connection_id = None
active_connection_started_ns = None
active_connection_uart_to_net_bytes = 0
active_connection_net_to_uart_bytes = 0
total_uart_to_net_bytes = 0
total_net_to_uart_bytes = 0
total_log_bytes = 0
total_uart_data_frames = 0
total_net_data_frames = 0

print(f"Proxy started on {serial_port} @ {args.baudrate}")


def log_verbose(message):
    if args.verbose:
        print(message)


def wall_time():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def emit_measurement(event, **fields):
    if args.measure_log is None:
        return

    record = {
        "source": "uart_proxy",
        "event": event,
        "wall_time": wall_time(),
        "monotonic_ns": time.monotonic_ns(),
        **fields,
    }
    args.measure_log.parent.mkdir(parents=True, exist_ok=True)
    with args.measure_log.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def emit_summary():
    emit_measurement(
        "proxy_summary",
        serial_port=serial_port,
        baudrate=args.baudrate,
        duration_ns=time.monotonic_ns() - started_at_ns,
        total_uart_to_net_bytes=total_uart_to_net_bytes,
        total_net_to_uart_bytes=total_net_to_uart_bytes,
        total_log_bytes=total_log_bytes,
        total_uart_data_frames=total_uart_data_frames,
        total_net_data_frames=total_net_data_frames,
    )


atexit.register(emit_summary)
emit_measurement("proxy_start", serial_port=serial_port, baudrate=args.baudrate)


def read_serial_exact(length):
    data = bytearray()
    deadline = time.monotonic() + 5

    while len(data) < length and time.monotonic() < deadline:
        chunk = ser.read(length - len(data))
        if chunk:
            data.extend(chunk)
        else:
            time.sleep(0.001)

    if len(data) != length:
        raise TimeoutError(f"timed out reading {length} bytes from UART")

    return bytes(data)


def print_stm_log(payload):
    global total_log_bytes
    total_log_bytes += len(payload)
    text = payload.decode("utf-8", errors="replace")
    emit_measurement("stm_log", payload_bytes=len(payload), text=text)
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 4 and parts[0] == "MEASURE":
            kind = parts[1]
            name = parts[2]
            value = parts[3]
            try:
                parsed_value = int(value, 0)
            except ValueError:
                parsed_value = value

            if kind == "cycles":
                emit_measurement("stm_cycles", name=name, cycles=parsed_value)
            elif kind == "size":
                emit_measurement("stm_size", name=name, bytes=parsed_value)
            elif kind == "meta":
                emit_measurement("stm_meta", name=name, value=parsed_value)

    sys.stdout.write(text)
    sys.stdout.flush()


def handle_uart_frame(frame_type):
    global sock, connected
    global active_connection_uart_to_net_bytes, total_uart_to_net_bytes, total_uart_data_frames

    hdr = read_serial_exact(2)
    payload_len = int.from_bytes(hdr, "big")
    payload = read_serial_exact(payload_len) if payload_len else b""

    if frame_type == UART_FRAME_LOG:
        print_stm_log(payload)
        return

    if frame_type == UART_FRAME_DATA:
        if not connected or sock is None:
            log_verbose(f"Ignoring UART data frame while disconnected ({payload_len} bytes)")
            return

        try:
            sock.sendall(payload)
            active_connection_uart_to_net_bytes += payload_len
            total_uart_to_net_bytes += payload_len
            total_uart_data_frames += 1
            emit_measurement(
                "uart_to_net_frame",
                connection_id=active_connection_id,
                payload_bytes=payload_len,
                connection_uart_to_net_bytes=active_connection_uart_to_net_bytes,
                total_uart_to_net_bytes=total_uart_to_net_bytes,
            )
            log_verbose(f"UART -> NET: {payload_len} bytes")
        except Exception as e:
            print("Send failed:", e)
            close_socket()
        return

    log_verbose(f"Ignoring unknown UART frame type {frame_type}")


def read_command_line(first_byte):
    line = first_byte + ser.readline()
    try:
        return line.decode("utf-8", errors="ignore").strip(), line
    except Exception:
        return "", line


def handle_connect_command(cmd):
    global sock, connected
    global connection_id, active_connection_id, active_connection_started_ns
    global active_connection_uart_to_net_bytes, active_connection_net_to_uart_bytes

    parts = cmd.split()
    if len(parts) != 3:
        ser.write(b"ERR\n")
        ser.flush()
        return

    host = parts[1]

    try:
        port = int(parts[2])
    except ValueError:
        ser.write(b"ERR\n")
        ser.flush()
        return

    close_socket()
    command_started_ns = time.monotonic_ns()

    try:
        sock = socket.create_connection((host, port), timeout=5)
        sock.setblocking(False)
        connected = True
        connection_id += 1
        active_connection_id = connection_id
        active_connection_started_ns = time.monotonic_ns()
        active_connection_uart_to_net_bytes = 0
        active_connection_net_to_uart_bytes = 0
        ser.write(b"OK\n")
        ser.flush()
        emit_measurement(
            "connect",
            connection_id=active_connection_id,
            host=host,
            port=port,
            status="ok",
            duration_ns=time.monotonic_ns() - command_started_ns,
        )
        log_verbose(f"Connected to {host}:{port}")
    except Exception as e:
        ser.write(b"ERR\n")
        ser.flush()
        print("Connect failed:", e)
        emit_measurement(
            "connect",
            host=host,
            port=port,
            status="error",
            error=str(e),
            duration_ns=time.monotonic_ns() - command_started_ns,
        )
        close_socket()


def handle_cert_command(cmd):
    parts = cmd.split()
    if len(parts) != 3:
        ser.write(b"ERR\n")
        ser.flush()
        return

    host = parts[1]

    try:
        port = int(parts[2])
    except ValueError:
        ser.write(b"ERR\n")
        ser.flush()
        return

    close_socket()
    command_started_ns = time.monotonic_ns()

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)

        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert).encode("ascii")
        ser.write(f"OK {len(pem_cert)}\n".encode("ascii"))
        ser.write(pem_cert)
        ser.flush()
        print(f"Fetched server certificate from {host}:{port} ({len(pem_cert)} bytes)")
        emit_measurement(
            "cert_fetch",
            host=host,
            port=port,
            status="ok",
            cert_pem_bytes=len(pem_cert),
            duration_ns=time.monotonic_ns() - command_started_ns,
        )
    except Exception as e:
        ser.write(b"ERR\n")
        ser.flush()
        print("Certificate fetch failed:", e)
        emit_measurement(
            "cert_fetch",
            host=host,
            port=port,
            status="error",
            error=str(e),
            duration_ns=time.monotonic_ns() - command_started_ns,
        )


def send_eof_frame():
    try:
        ser.write(b"\x00\x00")
        ser.flush()
        emit_measurement("net_to_uart_eof", connection_id=active_connection_id)
        log_verbose("NET -> UART: EOF frame")
    except Exception as e:
        print("Failed to send EOF frame:", e)


def close_socket(notify_uart=False):
    global sock, connected, active_connection_id, active_connection_started_ns
    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass
    if connected and notify_uart:
        send_eof_frame()
    if connected:
        emit_measurement(
            "disconnect",
            connection_id=active_connection_id,
            notify_uart=notify_uart,
            duration_ns=(time.monotonic_ns() - active_connection_started_ns) if active_connection_started_ns else None,
            uart_to_net_bytes=active_connection_uart_to_net_bytes,
            net_to_uart_bytes=active_connection_net_to_uart_bytes,
        )
    sock = None
    connected = False
    active_connection_id = None
    active_connection_started_ns = None

while True:
    if not connected:
        first = ser.read(1)

        if first:
            reported_waiting = True

            if first[0] in (UART_FRAME_LOG, UART_FRAME_DATA):
                try:
                    handle_uart_frame(first[0])
                except Exception as e:
                    print("UART frame handling failed:", e)
                time.sleep(0.01)
                continue

            cmd, line = read_command_line(first)

            log_verbose("UART CMD: " + repr(cmd))

            if cmd.startswith("CERT "):
                handle_cert_command(cmd)
            elif cmd.startswith("CONNECT "):
                handle_connect_command(cmd)
            else:
                log_verbose("Ignoring data before CERT/CONNECT")
        elif not reported_waiting and time.monotonic() - started_at > 5:
            reported_waiting = True
            print("Waiting for UART CERT/CONNECT command from firmware. If this stays idle, reset the board or check --port.")

        time.sleep(0.01)
        continue

    first = ser.read(1)
    if first:
        if first[0] in (UART_FRAME_LOG, UART_FRAME_DATA):
            try:
                handle_uart_frame(first[0])
            except Exception as e:
                print("UART frame handling failed:", e)
                close_socket(notify_uart=True)
            time.sleep(0.01)
            continue

        if first in (b"C",):
            cmd, _ = read_command_line(first)
            log_verbose("UART CMD while connected: " + repr(cmd))
            if cmd.startswith("CERT "):
                handle_cert_command(cmd)
            elif cmd.startswith("CONNECT "):
                handle_connect_command(cmd)
            else:
                log_verbose("Ignoring command-like UART data while connected")
            time.sleep(0.01)
            continue

        try:
            data = first + ser.read(1023)
            sock.sendall(data)
            active_connection_uart_to_net_bytes += len(data)
            total_uart_to_net_bytes += len(data)
            total_uart_data_frames += 1
            emit_measurement(
                "uart_to_net_raw",
                connection_id=active_connection_id,
                payload_bytes=len(data),
                connection_uart_to_net_bytes=active_connection_uart_to_net_bytes,
                total_uart_to_net_bytes=total_uart_to_net_bytes,
            )
            log_verbose(f"UART -> NET: {len(data)} bytes")
        except Exception as e:
            print("Send failed:", e)
            close_socket()
            continue

    if connected and sock is not None:
        try:
            net_data = sock.recv(1024)
            if net_data:
                active_connection_net_to_uart_bytes += len(net_data)
                total_net_to_uart_bytes += len(net_data)
                total_net_data_frames += 1
                emit_measurement(
                    "net_to_uart_frame",
                    connection_id=active_connection_id,
                    payload_bytes=len(net_data),
                    connection_net_to_uart_bytes=active_connection_net_to_uart_bytes,
                    total_net_to_uart_bytes=total_net_to_uart_bytes,
                )
                log_verbose(f"NET -> UART: {len(net_data)} bytes")
                hdr = len(net_data).to_bytes(2, "big")
                ser.write(hdr)
                ser.write(net_data)
                ser.flush()
            else:
                log_verbose("Remote closed")
                close_socket(notify_uart=True)
        except BlockingIOError:
            pass
        except Exception as e:
            print("Recv failed:", e)
            close_socket(notify_uart=True)

    time.sleep(0.01)

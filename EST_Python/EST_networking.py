import argparse
import glob
import serial
import socket
import sys
import time

from serial.tools import list_ports

DEFAULT_BAUDRATE = 115200


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
except Exception as e:
    print(f"Could not open serial port: {e}", file=sys.stderr)
    sys.exit(2)

sock = None
connected = False

print(f"Proxy started on {serial_port} @ {args.baudrate}")

def send_eof_frame():
    try:
        ser.write(b"\x00\x00")
        ser.flush()
        print("NET -> UART: EOF frame")
    except Exception as e:
        print("Failed to send EOF frame:", e)


def close_socket(notify_uart=False):
    global sock, connected
    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass
    if connected and notify_uart:
        send_eof_frame()
    sock = None
    connected = False

while True:
    if not connected:
        line = ser.readline()

        if line:
            print("UART CMD RAW:", repr(line))

            try:
                cmd = line.decode("utf-8", errors="ignore").strip()
            except Exception:
                cmd = ""

            print("UART CMD:", repr(cmd))

            if cmd.startswith("CONNECT "):
                parts = cmd.split()
                if len(parts) == 3:
                    host = parts[1]

                    try:
                        port = int(parts[2])
                    except ValueError:
                        ser.write(b"ERR\n")
                        continue

                    try:
                        sock = socket.create_connection((host, port), timeout=5)
                        sock.setblocking(False)
                        connected = True
                        ser.write(b"OK\n")
                        ser.flush()
                        print(f"Connected to {host}:{port}")
                    except Exception as e:
                        ser.write(b"ERR\n")
                        ser.flush()
                        print("Connect failed:", e)
                        close_socket()
                else:
                    ser.write(b"ERR\n")
                    ser.flush()
            else:
                print("Ignoring data before CONNECT")

        time.sleep(0.01)
        continue

    data = ser.read(1024)
    if data:
        try:
            sock.sendall(data)
            print(f"UART -> NET: {len(data)} bytes")
        except Exception as e:
            print("Send failed:", e)
            close_socket()
            continue

    if connected and sock is not None:
        try:
            net_data = sock.recv(1024)
            if net_data:
                print(f"NET -> UART: {len(net_data)} bytes")
                hdr = len(net_data).to_bytes(2, "big")
                ser.write(hdr)
                ser.write(net_data)
                ser.flush()
            else:
                print("Remote closed")
                close_socket(notify_uart=True)
        except BlockingIOError:
            pass
        except Exception as e:
            print("Recv failed:", e)
            close_socket(notify_uart=True)

    time.sleep(0.01)

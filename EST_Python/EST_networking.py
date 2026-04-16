import serial
import socket
import time

SERIAL_PORT = "/dev/ttyACM0"
BAUDRATE = 115200

ser = serial.Serial(SERIAL_PORT, BAUDRATE, timeout=0.1)

sock = None
connected = False

print(f"Proxy started on {SERIAL_PORT} @ {BAUDRATE}")

def close_socket():
    global sock, connected
    if sock is not None:
        try:
            sock.close()
        except Exception:
            pass
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
                close_socket()
        except BlockingIOError:
            pass
        except Exception as e:
            print("Recv failed:", e)
            close_socket()

    time.sleep(0.01)

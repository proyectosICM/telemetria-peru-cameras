#!/usr/bin/env python3
import socket
import datetime
import sys

UDP_IP = "0.0.0.0"
UDP_PORT = 7200

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Reuse address por si reinicias rápido
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind((UDP_IP, UDP_PORT))
    print(f"[{datetime.datetime.now()}] Escuchando A/V UDP en {UDP_IP}:{UDP_PORT}")

    pkt_count = 0

    # Opcional: guardar algo a archivo para analizar luego
    dump_file = open("av_raw_7200.bin", "ab")

    try:
        while True:
            data, addr = sock.recvfrom(65535)  # máx UDP
            pkt_count += 1
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Preview de los primeros bytes en hex
            preview = data[:32].hex()
            print(
                f"[{ts}] PKT #{pkt_count} from {addr} "
                f"len={len(data)} bytes hex={preview}{'...' if len(data) > 32 else ''}"
            )

            # Guardamos en bruto para inspección posterior
            dump_file.write(data)
            dump_file.flush()
    except KeyboardInterrupt:
        print("\nCerrando listener UDP...")
    finally:
        dump_file.close()
        sock.close()


if __name__ == "__main__":
    main()

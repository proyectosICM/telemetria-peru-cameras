#!/usr/bin/env python3
import socket
import datetime
import sys

TCP_IP = "0.0.0.0"
TCP_PORT = 7200

def main():
    # Servidor TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Reuse address por si reinicias rápido
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind((TCP_IP, TCP_PORT))
    sock.listen(5)

    print(f"[{datetime.datetime.now()}] Escuchando A/V TCP en {TCP_IP}:{TCP_PORT}")

    # Opcional: guardar algo a archivo para analizar luego
    dump_file = open("av_raw_7200_tcp.bin", "ab")

    try:
        while True:
            conn, addr = sock.accept()
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{ts}] Nueva conexión desde {addr}")

            pkt_count = 0

            while True:
                data = conn.recv(65535)
                if not data:
                    print(f"[{datetime.datetime.now()}] Conexión cerrada por {addr}")
                    break

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

            conn.close()
    except KeyboardInterrupt:
        print("\nCerrando listener TCP...")
    finally:
        dump_file.close()
        sock.close()


if __name__ == "__main__":
    main()

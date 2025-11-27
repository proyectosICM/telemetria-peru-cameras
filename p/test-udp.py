#!/usr/bin/env python3
import socket
import time

#LISTEN_IP = "0.0.0.0"
SERVER_IP = "38.43.134.172"  # cámbialo si corresponde
SERVER_PORT = 7200

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

msg = b"PRUEBA_UDP_TELEMETRIA"

print(f"Enviando mensajes UDP a {SERVER_IP}:{SERVER_PORT} ...")

while True:
    sock.sendto(msg, (SERVER_IP, SERVER_PORT))
    print("-> enviado:", msg)
    time.sleep(1)

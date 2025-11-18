#!/usr/bin/env python3
# jt1078_dump_test.py

import socket
import binascii
from pathlib import Path

RAW_OUT = Path("full_dump_000012345678_1.h264")

DATA_BODY_LEN_OFFSET = 28
DATA_BODY_OFFSET     = 30

def bcd6_to_str(b: bytes) -> str:
    out = []
    for x in b:
        out.append(f"{(x >> 4) & 0xF}{x & 0xF}")
    return "".join(out)

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 7200))
    print("Escuchando UDP 7200, escribiendo H264 crudo en", RAW_OUT)

    with RAW_OUT.open("wb") as f:
        while True:
            data, addr = sock.recvfrom(65535)

            # Chequeo de magic
            if len(data) < DATA_BODY_OFFSET:
                continue
            if data[0:4] != b"\x30\x31\x63\x64":
                continue

            sim_bcd = data[8:14]
            sim = bcd6_to_str(sim_bcd)
            chan = data[14]

            if sim != "000012345678" or chan != 1:
                # si quieres sólo ese canal
                continue

            if len(data) < DATA_BODY_LEN_OFFSET + 2:
                continue

            body_len = int.from_bytes(
                data[DATA_BODY_LEN_OFFSET:DATA_BODY_LEN_OFFSET + 2], "big"
            )
            body_off = DATA_BODY_OFFSET

            if body_len <= 0 or len(data) < body_off + body_len:
                continue

            body = data[body_off:body_off + body_len]

            # 🔴 aquí NO reensamblamos nada, sólo tiramos todo en orden
            f.write(body)

if __name__ == "__main__":
    main()

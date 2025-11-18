#!/usr/bin/env python3
# jt1078_reasm_dump.py

import socket
from pathlib import Path
import binascii

DATA_BODY_LEN_OFFSET = 28
DATA_BODY_OFFSET     = 30

OUT_PATH = Path("full_dump_reasm_000012345678_1.h264")

def bcd6_to_str(b: bytes) -> str:
    out = []
    for x in b:
        out.append(f"{(x >> 4) & 0xF}{x & 0xF}")
    return "".join(out)

class Reassembler:
    def __init__(self):
        self.buffers = {}

    def feed(self, key: str, subflag: int, payload: bytes):
        # 0 = paquete completo
        if subflag == 0:
            return payload

        buf = self.buffers.setdefault(key, bytearray())

        if subflag == 1:     # first
            buf.clear()
            buf += payload
            return None
        elif subflag == 2:   # middle
            buf += payload
            return None
        elif subflag == 3:   # last
            buf += payload
            out = bytes(buf)
            buf.clear()
            return out
        else:
            return payload

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 7200))
    print("Escuchando UDP 7200, volcando frames reensamblados en", OUT_PATH)

    reasm = Reassembler()

    with OUT_PATH.open("wb") as out_f:
        while True:
            data, addr = sock.recvfrom(65535)

            if len(data) < DATA_BODY_OFFSET:
                continue
            if data[0:4] != b"\x30\x31\x63\x64":
                continue

            sim_bcd = data[8:14]
            sim = bcd6_to_str(sim_bcd)
            chan = data[14]
            typ_sub = data[15]
            data_type = (typ_sub >> 4) & 0x0F
            subflag   = typ_sub & 0x0F

            if sim != "000012345678" or chan != 1:
                continue

            if len(data) < DATA_BODY_LEN_OFFSET + 2:
                continue

            body_len = int.from_bytes(
                data[DATA_BODY_LEN_OFFSET:DATA_BODY_LEN_OFFSET + 2],
                "big",
            )
            body_off = DATA_BODY_OFFSET

            if body_len <= 0 or len(data) < body_off + body_len:
                continue

            body = data[body_off:body_off + body_len]

            out = reasm.feed(f"{sim}_{chan}", subflag, body)
            if out:
                out_f.write(out)

if __name__ == "__main__":
    main()

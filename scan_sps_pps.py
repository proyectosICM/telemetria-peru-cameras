#!/usr/bin/env python3
# scan_sps_pps.py
#
# Escanea uno o varios .bin / .h264 y cuenta NALUs:
#  - IDR (tipo 5)
#  - non-IDR (tipo 1)
#  - SPS  (tipo 7)
#  - PPS  (tipo 8)

import sys
from pathlib import Path

START3 = b"\x00\x00\x01"
START4 = b"\x00\x00\x00\x01"


def scan_file(path: Path) -> None:
    data = path.read_bytes()
    size = len(data)

    total_nalus = 0
    counts = {
        1: 0,  # non-IDR slice
        5: 0,  # IDR slice
        7: 0,  # SPS
        8: 0,  # PPS
    }

    i = 0
    while i < size - 4:
        # Busca start code 0x000001 o 0x00000001
        if data[i:i+4] == START4:
            nal_start = i + 4
        elif data[i:i+3] == START3:
            nal_start = i + 3
        else:
            i += 1
            continue

        if nal_start >= size:
            break

        header = data[nal_start]
        nal_type = header & 0x1F  # H.264: 5 bits menos significativos

        total_nalus += 1
        if nal_type in counts:
            counts[nal_type] += 1

        # seguimos avanzando; no necesitamos saber la longitud exacta
        i = nal_start + 1

    print(f"[SCAN] {path}")
    print(f"  size bytes : {size}")
    print(f"  NALUs tot  : {total_nalus}")
    print(f"  non-IDR(1) : {counts[1]}")
    print(f"  IDR   (5)  : {counts[5]}")
    print(f"  SPS   (7)  : {counts[7]}")
    print(f"  PPS   (8)  : {counts[8]}")
    print("")


def main():
    if len(sys.argv) < 2:
        print("Uso: python3 scan_sps_pps.py <file1> [file2 ...]")
        sys.exit(1)

    for arg in sys.argv[1:]:
        p = Path(arg)
        if not p.exists():
            print(f"[SCAN] {p} → no existe")
            continue
        scan_file(p)


if __name__ == "__main__":
    main()

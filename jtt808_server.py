#!/usr/bin/env python3
# jtt808_server.py
import asyncio
import binascii
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime

# === JT/T 808 framing/escape ===
START_END = b'\x7e'
ESC = b'\x7d'
ESC_MAP = {b'\x02': b'\x7e', b'\x01': b'\x7d'}
REVERSE_ESC_MAP = {b'\x7e': b'\x7d\x02', b'\x7d': b'\x7d\x01'}

def de_escape(payload: bytes) -> bytes:
    out, i = bytearray(), 0
    while i < len(payload):
        if payload[i:i+1] == ESC and i+1 < len(payload):
            out += ESC_MAP.get(payload[i+1:i+2], payload[i+1:i+2])
            i += 2
        else:
            out += payload[i:i+1]
            i += 1
    return bytes(out)

def do_escape(raw: bytes) -> bytes:
    # aplica escape a 0x7E y 0x7D
    out = bytearray()
    for b in raw:
        bb = bytes([b])
        if bb in REVERSE_ESC_MAP:
            out += REVERSE_ESC_MAP[bb]
        else:
            out += bb
    return bytes(out)

def checksum(data: bytes) -> int:
    s = 0
    for b in data:
        s ^= b
    return s & 0xFF

# === Helpers BCD/coords ===
def bcd_to_str(b: bytes) -> str:
    # Convierte BCD a string (e.g. phone/time)
    out = ""
    for x in b:
        out += f"{(x >> 4) & 0xF}{x & 0xF}"
    return out

def parse_time_bcd6(b: bytes) -> datetime:
    # YYMMDDhhmmss (6 bytes BCD)
    s = bcd_to_str(b)  # e.g. "241103153012"
    yy = int(s[0:2])
    year = 2000 + yy if yy < 70 else 1900 + yy
    return datetime(year, int(s[2:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]), int(s[10:12]))

def parse_coord_u32(raw: bytes) -> float:
    # 4 bytes unsigned int, en 1e-6 grados
    v = int.from_bytes(raw, 'big', signed=False)
    return v / 1_000_000.0

# === Logger ===
logger = logging.getLogger("jtt808")
logger.setLevel(logging.INFO)
fh = RotatingFileHandler("jtt808.log", maxBytes=5_000_000, backupCount=3)
sh = logging.StreamHandler()
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
fh.setFormatter(fmt); sh.setFormatter(fmt)
logger.addHandler(fh); logger.addHandler(sh)

raw_logger = logging.getLogger("jtt808.raw")
raw_logger.setLevel(logging.INFO)
raw_fh = RotatingFileHandler("jtt808_raw.log", maxBytes=10_000_000, backupCount=2)
raw_fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
raw_logger.addHandler(raw_fh)

pos_logger = logging.getLogger("jtt808.pos")
pos_logger.setLevel(logging.INFO)
pos_fh = RotatingFileHandler("jtt808_pos.jsonl", maxBytes=10_000_000, backupCount=2)
pos_logger.addHandler(pos_fh)

# === Header 808 (2013) ===
# msgId(2) | msgBodyProps(2) | terminalPhone(6 BCD) | flowId(2) | [subpkg(4)?]
def parse_header(payload: bytes):
    if len(payload) < 12:
        raise ValueError("Frame demasiado corto para header 808")
    msg_id = payload[0:2]
    props = payload[2:4]
    phone = payload[4:10]       # BCD
    flow_id = payload[10:12]
    body_len = ((props[0] & 0x03) << 8) | props[1]  # 10 bits de longitud
    has_subpkg = (props[0] & 0x20) != 0
    idx = 12
    subpkg = None
    if has_subpkg:
        if len(payload) < 16:
            raise ValueError("Header indica subpaquetes pero faltan bytes")
        subpkg = payload[12:16]  # totalPkt(2) + pktIdx(2)
        idx = 16
    return {
        "msg_id": msg_id,
        "props": props,
        "phone_bcd": phone,
        "phone_str": bcd_to_str(phone),
        "flow_id": flow_id,
        "has_subpkg": has_subpkg,
        "subpkg": subpkg,
        "body_len": body_len,
        "body_idx": idx
    }

# === Build headers/responses ===
def build_props(body_len: int, subpkg=False, encrypt=0):
    # props: 0-9 len, 10-12 encrypt, 13 subpkg, 14-15 reserved
    val = 0
    val |= (body_len & 0x03FF)
    val |= (encrypt & 0x7) << 10
    if subpkg:
        val |= (1 << 13)
    return val.to_bytes(2, 'big')

class Flow:
    def __init__(self):
        self._v = 0
    def next(self) -> bytes:
        self._v = (self._v + 1) & 0xFFFF
        return self._v.to_bytes(2, 'big')

# Respuesta general plataforma 0x8001
def build_0x8001(phone_bcd: bytes, flow_id_platform: bytes, orig_flow_id: bytes, orig_msg_id: bytes, result: int):
    body = b'\x80\x01' + orig_flow_id + orig_msg_id + bytes([result])
    props = build_props(len(body))
    header = b'\x80\x01' + props + phone_bcd + flow_id_platform  # msgId=0x8001
    frame = header + body
    cs = bytes([checksum(frame)])
    esc = do_escape(frame + cs)
    return START_END + esc + START_END

# Registro 0x8100
def build_0x8100(phone_bcd: bytes, flow_id_platform: bytes, orig_flow_id: bytes, result: int = 0, auth_code: bytes = b''):
    # 0=éxito, 1=ya registrado, 2=no en DB, 3=IMEI existe, 4=vehículo existe
    # body: [0x81 0x00] + flowId(2) + result(1) + authCode(n)
    body = b'\x81\x00' + orig_flow_id + bytes([result]) + auth_code
    props = build_props(len(body))
    header = b'\x81\x00' + props + phone_bcd + flow_id_platform  # msgId=0x8100
    frame = header + body
    cs = bytes([checksum(frame)])
    esc = do_escape(frame + cs)
    return START_END + esc + START_END

# === Handlers ===
def handle_0002_heartbeat(session, hdr, body):
    # responde 0 (éxito)
    resp = build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)
    return resp

def handle_0100_register(session, hdr, body):
    # Para MVP: aceptamos y devolvemos 0x8100 con result=0, sin authCode.
    resp = build_0x8100(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], result=0, auth_code=b'')
    return resp

def handle_0102_auth(session, hdr, body):
    # 0x0102 = autenticación
    try:
        token = body.decode(errors='ignore') if body else ''
    except Exception:
        token = body.hex()
    logger.info(f"[0102] auth phone={hdr['phone_str']} token={token!r}")
    # ACK general (0x8001) → éxito
    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)

def handle_0200_position(session, hdr, body):
    # 0x0200 body mínimo:
    #   alarm (4) | status (4) | lat(4) | lon(4) | alt(2) | speed(2) (0.1km/h) | course(2) | time(6 BCD)
    try:
        alarm = int.from_bytes(body[0:4], 'big')
        status = int.from_bytes(body[4:8], 'big')
        lat = parse_coord_u32(body[8:12])
        lon = parse_coord_u32(body[12:16])
        alt = int.from_bytes(body[16:18], 'big', signed=False)
        speed = int.from_bytes(body[18:20], 'big', signed=False) / 10.0  # 0.1 km/h
        course = int.from_bytes(body[20:22], 'big', signed=False)
        dt = parse_time_bcd6(body[22:28])
        item = {
            "phone": hdr["phone_str"],
            "msgId": "0x0200",
            "alarm": alarm,
            "status": status,
            "lat": lat,
            "lon": lon,
            "alt": alt,
            "speed_kmh": speed,
            "course": course,
            "time": dt.isoformat()
        }
        pos_logger.info(json.dumps(item, ensure_ascii=False))
        logger.info(f"[0200] {item}")
    except Exception as e:
        logger.exception(f"Error parseando 0x0200: {e}")
    # 0x0200 suele requerir 0x8001 general response (éxito)
    resp = build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)
    return resp

MSG_HANDLERS = {
    b'\x00\x02': handle_0002_heartbeat,   # 0x0002 heartbeat
    b'\x01\x00': handle_0100_register,    # 0x0100 registro
    b'\x01\x02': handle_0102_auth,        # 0x0102 autenticación (NUEVO)
    b'\x02\x00': handle_0200_position,    # 0x0200 posición
    # agrega aquí más: 0x0704 (lotes), 0x0801 (multimedia), etc.
}

class SessionState:
    def __init__(self):
        self.flow = Flow()
    def next_flow(self) -> bytes:
        return self.flow.next()

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    logger.info(f"Conexión desde {peer}")
    session = SessionState()
    buf = b''
    try:
        while not reader.at_eof():
            chunk = await reader.read(4096)
            if not chunk:
                break
            buf += chunk
            # Cortar por 0x7E ... 0x7E
            while True:
                s = buf.find(START_END)
                if s == -1:
                    break
                e = buf.find(START_END, s+1)
                if e == -1:
                    break
                frame = buf[s+1:e]  # sin 0x7E
                buf = buf[e+1:]

                try:
                    payload = de_escape(frame)
                    if len(payload) < 13:
                        continue
                    # Verifica checksum
                    calc = checksum(payload[:-1])
                    if calc != payload[-1]:
                        logger.warning("Checksum inválido, descartando frame")
                        continue

                    hdr = parse_header(payload[:-1])  # sin checksum
                    body = payload[:-1][hdr["body_idx"] : hdr["body_idx"] + hdr["body_len"]]

                    # Log raw frame/hex
                    raw_logger.info(binascii.hexlify(payload).decode())

                    msg_id = hdr["msg_id"]
                    handler = MSG_HANDLERS.get(msg_id)
                    if handler:
                        resp = handler(session, hdr, body)
                        if resp:
                            logger.info(f"→ RESP to {hdr['phone_str']} msgId=0x{hdr['msg_id'].hex()} flow={int.from_bytes(hdr['flow_id'],'big')}")
                            writer.write(resp)
                            await writer.drain()
                    else:
                        # Si no hay handler, solo loguea (puedes opcionalmente responder 0x8001 aquí)
                        logger.info(f"MsgId no manejado: 0x{msg_id.hex()} phone={hdr['phone_str']} len={hdr['body_len']}")
                        # Opcional:
                        # resp = build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)
                        # writer.write(resp); await writer.drain()

                except Exception as ex:
                    logger.exception(f"Error manejando frame: {ex}")

    except Exception as e:
        logger.exception(f"Error en conexión {peer}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(f"Conexión cerrada {peer}")

async def main():
    host = "0.0.0.0"
    port = 6808  # ajusta según tu escenario
    server = await asyncio.start_server(handle_client, host, port)
    addr = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info(f"Servidor JT/T 808 escuchando en {addr}")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Servidor detenido por teclado")

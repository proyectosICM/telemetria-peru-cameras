#!/usr/bin/env python3
# server.py - JT/T 808 minimal (registro + auth + heartbeat + posición) en puerto 6808

import asyncio
import binascii
import logging
import socket
from datetime import datetime

# ========== Config básica ==========
HOST = "0.0.0.0"
PORT = 6808

ALWAYS_ACK_UNKNOWN = True  # responde 0x8001 a mensajes no manejados

# ========== Framing / escape JT808 ==========
START_END = b"\x7e"
ESC = b"\x7d"
ESC_MAP = {b"\x02": b"\x7e", b"\x01": b"\x7d"}
REVERSE_ESC_MAP = {b"\x7e": b"\x7d\x02", b"\x7d": b"\x7d\x01"}


def de_escape(payload: bytes) -> bytes:
    out, i = bytearray(), 0
    while i < len(payload):
        if payload[i:i+1] == ESC and i + 1 < len(payload):
            out += ESC_MAP.get(payload[i+1:i+2], payload[i+1:i+2])
            i += 2
        else:
            out += payload[i:i+1]
            i += 1
    return bytes(out)


def do_escape(raw: bytes) -> bytes:
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


# ========== Helpers BCD / coords ==========
def bcd_to_str(b: bytes) -> str:
    out = ""
    for x in b:
        out += f"{(x >> 4) & 0xF}{x & 0xF}"
    return out


def parse_time_bcd6(b: bytes) -> datetime:
    s = bcd_to_str(b)  # "YYMMDDhhmmss"
    yy = int(s[0:2])
    year = 2000 + yy if yy < 70 else 1900 + yy
    return datetime(
        year,
        int(s[2:4]),
        int(s[4:6]),
        int(s[6:8]),
        int(s[8:10]),
        int(s[10:12]),
    )


def parse_coord_u32(raw: bytes) -> float:
    """
    Coordenada JT808: entero * 1e-6
    """
    v = int.from_bytes(raw, "big", signed=False)
    return v / 1_000_000.0


# ========== Logging simple ==========
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("jtt808-mini")
raw_logger = logging.getLogger("jtt808-mini.raw")


# ========== Header 808 ==========
def parse_header(payload: bytes):
    """
    payload: header+body SIN checksum
    """
    if len(payload) < 12:
        raise ValueError("Frame demasiado corto para header 808")
    msg_id = payload[0:2]
    props = payload[2:4]
    phone = payload[4:10]  # BCD
    flow_id = payload[10:12]
    body_len = ((props[0] & 0x03) << 8) | props[1]  # 10 bits
    has_subpkg = (props[0] & 0x20) != 0
    idx = 12
    subpkg = None
    if has_subpkg:
        if len(payload) < 16:
            raise ValueError("Header indica subpaquetes pero faltan bytes")
        subpkg = payload[12:16]
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
        "body_idx": idx,
    }


# ========== Construcción de downlinks ==========
def build_props(body_len: int, subpkg=False, encrypt=0):
    val = 0
    val |= (body_len & 0x03FF)
    val |= (encrypt & 0x7) << 10
    if subpkg:
        val |= (1 << 13)
    return val.to_bytes(2, "big")


class Flow:
    def __init__(self):
        self._v = 0

    def next(self) -> bytes:
        self._v = (self._v + 1) & 0xFFFF
        return self._v.to_bytes(2, "big")


def build_downlink(
    msg_id: bytes,
    phone_bcd: bytes,
    flow_id_platform: bytes,
    body: bytes = b"",
):
    header = msg_id + build_props(len(body)) + phone_bcd + flow_id_platform
    frame = header + body
    cs = bytes([checksum(frame)])
    esc = do_escape(frame + cs)
    return START_END + esc + START_END


# 0x8001 – Platform general response
def build_0x8001(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    orig_flow_id: bytes,
    orig_msg_id: bytes,
    result: int,
):
    # Body: resp_flowId (WORD) + resp_msgId (WORD) + result (BYTE)
    body = orig_flow_id + orig_msg_id + bytes([result])
    return build_downlink(b"\x80\x01", phone_bcd, flow_id_platform, body)


# 0x8100 – Register response
def build_0x8100(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    orig_flow_id: bytes,
    result: int = 0,
    auth_code: bytes = b"",
):
    # Body: flowId (WORD) + result (BYTE) + auth_code (n)
    body = orig_flow_id + bytes([result]) + auth_code
    return build_downlink(b"\x81\x00", phone_bcd, flow_id_platform, body)


# ========== Handlers uplink mínimos ==========
def handle_0001_terminal_general_resp(session, hdr, body):
    """
    0x0001 – Terminal general response
    body: resp_flow_id(2) + resp_msg_id(2) + result(1)
    """
    if len(body) < 5:
        logger.warning(f"[0001] body demasiado corto: len={len(body)}")
        return None
    resp_flow = int.from_bytes(body[0:2], "big")
    resp_msg_id = body[2:4]
    result = body[4]
    logger.info(
        f"[0001] Ack terminal phone={hdr['phone_str']} "
        f"resp_flow={resp_flow} resp_msgId=0x{resp_msg_id.hex()} result={result}"
    )
    return None  # a 0x0001 no respondemos nada


def handle_0002_heartbeat(session, hdr, body):
    logger.info(f"[0002] Heartbeat desde phone={hdr['phone_str']}")
    # respondemos con 0x8001 OK
    return build_0x8001(
        hdr["phone_bcd"],
        session.next_flow(),
        hdr["flow_id"],
        hdr["msg_id"],
        0,
    )


def handle_0100_register(session, hdr, body):
    """
    0x0100 – Registro terminal
    """
    try:
        prov = int.from_bytes(body[0:2], "big")
        city = int.from_bytes(body[2:4], "big")
        manu = body[4:9].decode("ascii", errors="ignore").strip()
        model = body[9:29].decode("ascii", errors="ignore").strip()
        term_id = body[29:36].decode("ascii", errors="ignore").strip()
        plate_color = body[36] if len(body) > 36 else None
        plate = (
            body[37:].decode("ascii", errors="ignore").strip()
            if len(body) > 37
            else ""
        )
        logger.info(
            f"[0100] Registro terminal phone={hdr['phone_str']} "
            f"prov={prov} city={city} manu={manu!r} model={model!r} "
            f"term_id={term_id!r} plate_color={plate_color} plate={plate!r}"
        )
    except Exception as e:
        logger.exception(f"Error parseando 0x0100: {e}")
        logger.info(
            f"[0100] Registro terminal phone={hdr['phone_str']} "
            f"(body_len={len(body)})"
        )

    # Registro aceptado (result=0)
    return build_0x8100(
        hdr["phone_bcd"],
        session.next_flow(),
        hdr["flow_id"],
        result=0,
        auth_code=b"",  # sin token por ahora
    )


def handle_0102_auth(session, hdr, body):
    # Autenticación
    try:
        token = body.decode(errors="ignore") if body else ""
    except Exception:
        token = body.hex()
    logger.info(f"[0102] Auth phone={hdr['phone_str']} token={token!r}")
    # solo respondemos con 0x8001 OK
    return build_0x8001(
        hdr["phone_bcd"],
        session.next_flow(),
        hdr["flow_id"],
        hdr["msg_id"],
        0,
    )


def handle_0200_position(session, hdr, body):
    """
    0x0200 – LocationReport
    Campos básicos: alarm(4) + status(4) + lat(4) + lon(4) + alt(2) + speed(2) + course(2) + time(6 BCD)
    """
    try:
        if len(body) < 28:
            logger.warning(
                f"[0200] body demasiado corto: len={len(body)} phone={hdr['phone_str']}"
            )
        else:
            alarm = int.from_bytes(body[0:4], "big")
            status = int.from_bytes(body[4:8], "big")
            lat = parse_coord_u32(body[8:12])
            lon = parse_coord_u32(body[12:16])
            alt = int.from_bytes(body[16:18], "big", signed=False)
            speed = int.from_bytes(body[18:20], "big", signed=False) / 10.0
            course = int.from_bytes(body[20:22], "big", signed=False)
            dt = parse_time_bcd6(body[22:28])

            logger.info(
                f"[0200] phone={hdr['phone_str']} "
                f"alarm={alarm} status={status} "
                f"lat={lat:.6f} lon={lon:.6f} alt={alt}m "
                f"speed={speed:.1f}km/h course={course} "
                f"time={dt.isoformat()}"
            )
    except Exception as e:
        logger.exception(f"Error parseando 0x0200: {e}")

    # Devolvemos ACK general OK
    return build_0x8001(
        hdr["phone_bcd"],
        session.next_flow(),
        hdr["flow_id"],
        hdr["msg_id"],
        0,
    )


MSG_HANDLERS = {
    b"\x00\x01": handle_0001_terminal_general_resp,
    b"\x00\x02": handle_0002_heartbeat,
    b"\x01\x00": handle_0100_register,
    b"\x01\x02": handle_0102_auth,
    b"\x02\x00": handle_0200_position,  # <- ahora ya manejamos 0x0200
}


# ========== Estado de sesión ==========
class SessionState:
    def __init__(self):
        self.flow = Flow()

    def next_flow(self) -> bytes:
        return self.flow.next()


# ========== Loop por conexión ==========
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    # Activar TCP keepalive
    sock = writer.get_extra_info("socket")
    if isinstance(sock, socket.socket):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

    peer = writer.get_extra_info("peername")
    logger.info(f"Conexión desde {peer}")
    session = SessionState()
    buf = b""
    try:
        while not reader.at_eof():
            chunk = await reader.read(4096)
            if not chunk:
                break
            buf += chunk

            # buscar frames 0x7E ... 0x7E
            while True:
                s = buf.find(START_END)
                if s == -1:
                    break
                e = buf.find(START_END, s + 1)
                if e == -1:
                    break

                frame = buf[s + 1 : e]  # sin 0x7E
                buf = buf[e + 1 :]

                try:
                    payload = de_escape(frame)
                    if len(payload) < 13:
                        continue

                    calc = checksum(payload[:-1])
                    if calc != payload[-1]:
                        logger.warning("Checksum inválido, descartando frame")
                        continue

                    hdr = parse_header(payload[:-1])
                    body = payload[:-1][
                        hdr["body_idx"] : hdr["body_idx"] + hdr["body_len"]
                    ]

                    # Log crudo
                    hex_payload = binascii.hexlify(payload).decode()
                    raw_logger.info(
                        "RX term->srv phone=%s msgId=0x%s %s",
                        hdr["phone_str"],
                        hdr["msg_id"].hex(),
                        hex_payload,
                    )

                    logger.info(
                        f"[RX] msgId=0x{hdr['msg_id'].hex()} "
                        f"phone={hdr['phone_str']} body_len={hdr['body_len']} "
                        f"has_subpkg={hdr['has_subpkg']}"
                    )

                    msg_id = hdr["msg_id"]
                    handler = MSG_HANDLERS.get(msg_id)

                    if handler:
                        resp = handler(session, hdr, body)
                        if resp:
                            logger.info(
                                f"[TX] phone={hdr['phone_str']} "
                                f"resp_for=0x{hdr['msg_id'].hex()} "
                                f"flow={int.from_bytes(hdr['flow_id'], 'big')}"
                            )
                            writer.write(resp)
                            await writer.drain()
                    else:
                        logger.info(
                            f"MsgId no manejado: 0x{msg_id.hex()} "
                            f"phone={hdr['phone_str']} len={hdr['body_len']}"
                        )
                        if ALWAYS_ACK_UNKNOWN:
                            resp = build_0x8001(
                                hdr["phone_bcd"],
                                session.next_flow(),
                                hdr["flow_id"],
                                hdr["msg_id"],
                                0,
                            )
                            logger.info(
                                f"[TX] phone={hdr['phone_str']} "
                                f"msgId=0x8001 (Ack UNKNOWN 0x{hdr['msg_id'].hex()})"
                            )
                            writer.write(resp)
                            await writer.drain()

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


# ========== main ==========
async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info(f"Servidor JT/T 808 (mínimo) escuchando en {addr}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Servidor detenido por teclado")

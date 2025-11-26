#!/usr/bin/env python3
# jtt808_server.py
import asyncio
import binascii
import json
import logging
import socket
from logging.handlers import RotatingFileHandler
from datetime import datetime

# === Config comportamiento ===
ALWAYS_ACK_UNKNOWN = True          # ACK 0x8001 también a msgId no manejados (recomendado en pruebas)
ASK_LOCATION_AFTER_AUTH = True     # tras 0x0102, enviar 0x8201
START_TEMP_TRACKING_AFTER_AUTH = True  # opción A: tras 0x0102, enviar 0x8202
TEMP_TRACK_INTERVAL_S = 10         # cada 10s
TEMP_TRACK_DURATION_MIN = 10       # por 10 minutos

# === Config de video (JT/T 1078 sobre 808; el stream va a tu media-server) ===
VIDEO_TARGET_IP     = "38.43.134.172"  # <-- cámbialo a tu IP pública o dominio
VIDEO_TCP_PORT      = 7200             # puerto TCP para video (puede ser el mismo que UDP)
VIDEO_UDP_PORT      = 7200             # puerto UDP donde escucha tu jt1078_media_server
VIDEO_CHANNEL       = 1                # canal lógico del DVR (1..N)
VIDEO_DATA_TYPE     = 1                # 0=audio+video, 1=solo video, 2=solo audio, etc. (depende vendor)
VIDEO_FRAME_TYPE    = 0                # 0=main stream, 1=sub stream (depende vendor)

# === JT/T 808 framing/escape ===
START_END = b'\x7e'
ESC = b'\x7d'
ESC_MAP = {b'\x02': b'\x7e', b'\x01': b'\x7d'}
REVERSE_ESC_MAP = {b'\x7e': b'\x7d\x02', b'\x7d': b'\x7d\x01'}


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


# === Helpers BCD/coords ===
def bcd_to_str(b: bytes) -> str:
    out = ""
    for x in b:
        out += f"{(x >> 4) & 0xF}{x & 0xF}"
    return out


def parse_time_bcd6(b: bytes) -> datetime:
    s = bcd_to_str(b)  # "YYMMDDhhmmss"
    yy = int(s[0:2])
    year = 2000 + yy if yy < 70 else 1900 + yy
    return datetime(year, int(s[2:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]), int(s[10:12]))


def parse_coord_u32(raw: bytes) -> float:
    v = int.from_bytes(raw, 'big', signed=False)
    return v / 1_000_000.0

def _to_bcd_byte(v: int) -> int:
    """
    Convierte un entero 0-99 en un byte BCD (ej. 23 -> 0x23).
    """
    v = max(0, min(99, int(v)))
    return ((v // 10) << 4) | (v % 10)


def encode_time_bcd6(dt: datetime | None) -> bytes:
    """
    Codifica datetime a BCD[6] YYMMDDhhmmss.
    Si dt es None, devuelve 6 bytes 0x00 (sin condición de tiempo).
    """
    if dt is None:
        return b"\x00" * 6

    yy = dt.year % 100
    vals = (yy, dt.month, dt.day, dt.hour, dt.minute, dt.second)
    return bytes(_to_bcd_byte(v) for v in vals)


# === Logger ===
logger = logging.getLogger("jtt808")
logger.setLevel(logging.INFO)
fh = RotatingFileHandler("jtt808.log", maxBytes=5_000_000, backupCount=3)
sh = logging.StreamHandler()
fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
fh.setFormatter(fmt)
sh.setFormatter(fmt)
logger.addHandler(fh)
logger.addHandler(sh)

raw_logger = logging.getLogger("jtt808.raw")
raw_logger.setLevel(logging.INFO)
raw_fh = RotatingFileHandler("jtt808_raw.log", maxBytes=10_000_000, backupCount=2)
raw_fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
raw_logger.addHandler(raw_fh)
# No propagar al logger padre para que no salga en consola
raw_logger.propagate = False

pos_logger = logging.getLogger("jtt808.pos")
pos_logger.setLevel(logging.INFO)
pos_fh = RotatingFileHandler("jtt808_pos.jsonl", maxBytes=10_000_000, backupCount=2)
pos_logger.addHandler(pos_fh)
# Igual: solo archivo, no consola
pos_logger.propagate = False


# === Header 808 (2013) ===
def parse_header(payload: bytes):
    if len(payload) < 12:
        raise ValueError("Frame demasiado corto para header 808")
    msg_id = payload[0:2]
    props = payload[2:4]
    phone = payload[4:10]       # BCD
    flow_id = payload[10:12]
    body_len = ((props[0] & 0x03) << 8) | props[1]  # 10 bits
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


def build_downlink(msg_id: bytes, phone_bcd: bytes, flow_id_platform: bytes, body: bytes = b''):
    header = msg_id + build_props(len(body)) + phone_bcd + flow_id_platform
    frame = header + body
    cs = bytes([checksum(frame)])
    esc = do_escape(frame + cs)
    return START_END + esc + START_END


# 0x8001 – Platform general response
def build_0x8001(phone_bcd: bytes, flow_id_platform: bytes,
                 orig_flow_id: bytes, orig_msg_id: bytes, result: int):
    # Body: resp_msgId (WORD) + resp_flowId (WORD) + result(BYTE)
    body = orig_flow_id + orig_msg_id + bytes([result])
    return build_downlink(b'\x80\x01', phone_bcd, flow_id_platform, body)


# 0x8100 – Register response
def build_0x8100(phone_bcd: bytes, flow_id_platform: bytes,
                 orig_flow_id: bytes, result: int = 0, auth_code: bytes = b''):
    # Body: flowId (WORD) + result (BYTE) + auth_code(n)
    body = orig_flow_id + bytes([result]) + auth_code
    return build_downlink(b'\x81\x00', phone_bcd, flow_id_platform, body)


# 0x8201 – Location information query (cuerpo vacío)
def build_0x8201(phone_bcd: bytes, flow_id_platform: bytes):
    return build_downlink(b'\x82\x01', phone_bcd, flow_id_platform, b'')


# 0x8202 – Temporary tracking control: interval_s(2B) + validity_min(4B)
def build_0x8202(phone_bcd: bytes, flow_id_platform: bytes,
                 interval_s: int, validity_min: int):
    body = interval_s.to_bytes(2, 'big') + validity_min.to_bytes(4, 'big')
    return build_downlink(b'\x82\x02', phone_bcd, flow_id_platform, body)


# === JT/T 1078: A/V control downlinks (via enlace 808) ===
# 0x9101 – Real-time audio and video transmit request
def build_0x9101(phone_bcd: bytes, flow_id_platform: bytes,
                 ip: str,
                 tcp_port: int,
                 udp_port: int,
                 logical_channel: int,
                 data_type: int = 1,      # 0=audio+video, 1=solo video, etc.
                 frame_type: int = 0):    # 0=main, 1=sub
    ip_bytes = ip.encode("ascii")

    body = bytearray()
    body.append(len(ip_bytes))                # IP_len
    body += ip_bytes                          # IP
    body += tcp_port.to_bytes(2, 'big')       # TCP port
    body += udp_port.to_bytes(2, 'big')       # UDP port
    body.append(logical_channel & 0xFF)       # logical channel
    body.append(data_type & 0xFF)             # data type
    body.append(frame_type & 0xFF)            # frame type

    return build_downlink(b'\x91\x01', phone_bcd, flow_id_platform, bytes(body))


# 0x9102 – Real-time AV transmit control
def build_0x9102(phone_bcd: bytes, flow_id_platform: bytes,
                 logical_channel: int,
                 control_cmd: int = 1,
                 close_av_type: int = 0,
                 switch_stream_type: int = 0):
    body = bytearray()
    body.append(logical_channel & 0xFF)
    body.append(control_cmd & 0xFF)
    body += close_av_type.to_bytes(2, 'big')
    body += switch_stream_type.to_bytes(2, 'big')
    return build_downlink(b'\x91\x02', phone_bcd, flow_id_platform, bytes(body))

# 0x9105 – Real-time AV transmission status notification
def build_0x9105_av_status_notify(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    logical_channel: int,
    packet_loss_rate: int,
):
    """
    logical_channel: número de canal lógico (según tabla de canales del fabricante)
    packet_loss_rate: 0-100, porcentaje (la norma dice *valor *100 e int*, pero
                      en la práctica se maneja 0-100 y el terminal lo interpreta).
    """
    pl = max(0, min(100, int(packet_loss_rate)))
    body = bytearray()
    body.append(logical_channel & 0xFF)
    body.append(pl & 0xFF)
    return build_downlink(b'\x91\x05', phone_bcd, flow_id_platform, bytes(body))

# 0x9301 – PTZ rotation
def build_0x9301_ptz_rotate(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    logical_channel: int,
    direction: int,
    speed: int,
):
    """
    direction:
      0 = stop
      1 = up
      2 = down
      3 = left
      4 = right
    speed: 0-255
    """
    body = bytearray()
    body.append(logical_channel & 0xFF)
    body.append(direction & 0xFF)
    body.append(max(0, min(255, speed)) & 0xFF)
    return build_downlink(b'\x93\x01', phone_bcd, flow_id_platform, bytes(body))

# 0x9302 – PTZ focus control
def build_0x9302_ptz_focus(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    logical_channel: int,
    focus_direction: int,
):
    """
    focus_direction (según implementaciones típicas):
      0 = far / enfocar lejos
      1 = near / enfocar cerca
    """
    body = bytearray()
    body.append(logical_channel & 0xFF)
    body.append(focus_direction & 0xFF)
    return build_downlink(b'\x93\x02', phone_bcd, flow_id_platform, bytes(body))


# === Handlers uplink ===
def handle_0001_terminal_general_resp(session, hdr, body):
    """
    0x0001 – Terminal general response
    body: resp_flow_id(2) + resp_msg_id(2) + result(1)
    """
    if len(body) < 5:
        logger.warning(f"[0001] body demasiado corto: len={len(body)}")
        return None
    resp_flow = int.from_bytes(body[0:2], 'big')
    resp_msg_id = body[2:4]
    result = body[4]
    logger.info(
        f"[0001] Ack terminal phone={hdr['phone_str']} "
        f"resp_flow={resp_flow} resp_msgId=0x{resp_msg_id.hex()} result={result}"
    )
    # Normalmente NO se responde nada a 0x0001
    return None


def handle_0002_heartbeat(session, hdr, body):
    # Terminal heartbeat → responde ACK general
    logger.info(f"[0002] Heartbeat desde phone={hdr['phone_str']}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(),
                        hdr["flow_id"], hdr["msg_id"], 0)


def handle_0100_register(session, hdr, body):
    """
    0x0100 – Registro terminal
    body layout (2013):
      provinceId(2) + cityId(2) +
      manufacturerId(5) +
      terminalType(20) +
      terminalId(7) +
      plateColor(1) +
      plate (GBK/ASCII, variable)
    """
    try:
        prov = int.from_bytes(body[0:2], 'big')
        city = int.from_bytes(body[2:4], 'big')
        manu = body[4:9].decode('ascii', errors='ignore').strip()
        model = body[9:29].decode('ascii', errors='ignore').strip()
        term_id = body[29:36].decode('ascii', errors='ignore').strip()
        plate_color = body[36]
        plate = body[37:].decode('ascii', errors='ignore').strip()

        logger.info(
            f"[0100] Registro terminal OK phone={hdr['phone_str']} "
            f"prov={prov} city={city} manu={manu!r} model={model!r} "
            f"term_id={term_id!r} plate_color={plate_color} plate={plate!r}"
        )
    except Exception as e:
        logger.exception(f"Error parseando 0x0100: {e}")
        logger.info(f"[0100] Registro terminal phone={hdr['phone_str']} (body_len={len(body)})")

    # Registro aceptado (result=0)
    return build_0x8100(hdr["phone_bcd"], session.next_flow(),
                        hdr["flow_id"], result=0, auth_code=b'')


def handle_0102_auth(session, hdr, body):
    # Autenticación
    try:
        token = body.decode(errors='ignore') if body else ''
    except Exception:
        token = body.hex()
    logger.info(f"[0102] auth phone={hdr['phone_str']} token={token!r}")
    # ACK general
    return build_0x8001(hdr["phone_bcd"], session.next_flow(),
                        hdr["flow_id"], hdr["msg_id"], 0)


def handle_0200_position(session, hdr, body):
    # Posición
    try:
        alarm = int.from_bytes(body[0:4], 'big')
        status = int.from_bytes(body[4:8], 'big')
        lat = parse_coord_u32(body[8:12])
        lon = parse_coord_u32(body[12:16])
        alt = int.from_bytes(body[16:18], 'big', signed=False)
        speed = int.from_bytes(body[18:20], 'big', signed=False) / 10.0
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
    return build_0x8001(hdr["phone_bcd"], session.next_flow(),
                        hdr["flow_id"], hdr["msg_id"], 0)


def handle_0201_location_query_resp(session, hdr, body):
    # Respuesta a 0x8201: flowId(2) + estructura similar a 0x0200
    try:
        if len(body) >= 2:
            resp_flow = int.from_bytes(body[0:2], 'big')
            rest = body[2:]
        else:
            resp_flow = None
            rest = body
        if len(rest) >= 28:
            alarm = int.from_bytes(rest[0:4], 'big')
            status = int.from_bytes(rest[4:8], 'big')
            lat = parse_coord_u32(rest[8:12])
            lon = parse_coord_u32(rest[12:16])
            alt = int.from_bytes(rest[16:18], 'big', signed=False)
            speed = int.from_bytes(rest[18:20], 'big', signed=False) / 10.0
            course = int.from_bytes(rest[20:22], 'big', signed=False)
            dt = parse_time_bcd6(rest[22:28])
            item = {
                "phone": hdr["phone_str"],
                "msgId": "0x0201",
                "resp_flow": resp_flow,
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
            logger.info(f"[0201] {item}")
        else:
            logger.info(f"[0201] resp_flow={resp_flow} body_len={len(body)} (no parseable como 0x0200)")
    except Exception as e:
        logger.exception(f"Error parseando 0x0201: {e}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(),
                        hdr["flow_id"], hdr["msg_id"], 0)


def handle_0704_batch_positions(session, hdr, body):
    """
    0x0704 – Location Information Batch Upload
    body:
      count (1B)
      type  (1B)
      [for i in range(count)]:
          data_len (2B)
          data     (data_len bytes)  # igual que cuerpo 0x0200
    """
    try:
        if len(body) < 4:
            logger.warning(f"[0704] body demasiado corto: len={len(body)}")
            return build_0x8001(hdr["phone_bcd"], session.next_flow(),
                                hdr["flow_id"], hdr["msg_id"], 0)

        count = body[0]
        batch_type = body[1]
        idx = 2

        logger.info(f"[0704] phone={hdr['phone_str']} count={count} type={batch_type}")

        for i in range(count):
            if idx + 2 > len(body):
                logger.warning(f"[0704] sin espacio para data_len en registro {i}")
                break

            data_len = int.from_bytes(body[idx:idx + 2], "big")
            idx += 2

            if idx + data_len > len(body):
                logger.warning(
                    f"[0704] data_len={data_len} excede body_len, registro {i}"
                )
                break

            data = body[idx:idx + data_len]
            idx += data_len

            # 'data' es como el body de 0x0200
            try:
                alarm = int.from_bytes(data[0:4], 'big')
                status = int.from_bytes(data[4:8], 'big')
                lat = parse_coord_u32(data[8:12])
                lon = parse_coord_u32(data[12:16])
                alt = int.from_bytes(data[16:18], 'big', signed=False)
                speed = int.from_bytes(data[18:20], 'big', signed=False) / 10.0
                course = int.from_bytes(data[20:22], 'big', signed=False)
                dt = parse_time_bcd6(data[22:28])

                item = {
                    "phone": hdr["phone_str"],
                    "msgId": "0x0704",
                    "batch_type": batch_type,
                    "idx": i,
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
                logger.info(f"[0704] item[{i}] {item}")
            except Exception as ex_item:
                logger.exception(f"Error parseando registro {i} de 0x0704: {ex_item}")

    except Exception as e:
        logger.exception(f"Error manejando 0x0704: {e}")

    # Devolver ACK general OK
    return build_0x8001(hdr["phone_bcd"], session.next_flow(),
                        hdr["flow_id"], hdr["msg_id"], 0)


MSG_HANDLERS = {
    b'\x00\x01': handle_0001_terminal_general_resp,   # ACK general del terminal
    b'\x00\x02': handle_0002_heartbeat,              # heartbeat terminal
    b'\x01\x00': handle_0100_register,               # registro
    b'\x01\x02': handle_0102_auth,                   # autenticación
    b'\x02\x00': handle_0200_position,               # posición
    b'\x02\x01': handle_0201_location_query_resp,    # respuesta a 0x8201
    b'\x07\x04': handle_0704_batch_positions,        # posiciones en lote
    # agrega aquí más: 0x0801 (multimedia), etc.
}


class SessionState:
    def __init__(self):
        self.flow = Flow()
        self.video_started = False  # <--- FLAG

    def next_flow(self) -> bytes:
        return self.flow.next()


async def start_video_if_needed(session: SessionState, hdr, writer):
    """
    Envía 0x9101 + 0x9102 una sola vez por sesión (video_started).
    """
    if session.video_started:
        return

    session.video_started = True

    # 0x9101 – Start AV
    av = build_0x9101(
        hdr["phone_bcd"], session.next_flow(),
        ip=VIDEO_TARGET_IP,
        tcp_port=VIDEO_TCP_PORT,
        udp_port=VIDEO_UDP_PORT,
        logical_channel=VIDEO_CHANNEL,
        data_type=VIDEO_DATA_TYPE,
        frame_type=VIDEO_FRAME_TYPE,
    )
    logger.info(
        f"[TX srv->term] phone={hdr['phone_str']} "
        f"msgId=0x9101 (StartAV ch={VIDEO_CHANNEL} "
        f"to {VIDEO_TARGET_IP}:TCP={VIDEO_TCP_PORT}/UDP={VIDEO_UDP_PORT})"
    )
    writer.write(av)
    await writer.drain()

    # 0x9102 – Control START (algunos vendors lo exigen además de 0x9101)
    av_ctrl = build_0x9102(
        hdr["phone_bcd"], session.next_flow(),
        logical_channel=VIDEO_CHANNEL,
        control_cmd=1,
        close_av_type=0,
        switch_stream_type=VIDEO_FRAME_TYPE,
    )
    logger.info(
        f"[TX srv->term] phone={hdr['phone_str']} "
        f"msgId=0x9102 (AVControl START ch={VIDEO_CHANNEL})"
    )
    writer.write(av_ctrl)
    await writer.drain()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    # Activa TCP keepalive por conexión (evita cortes por NAT/ISP)
    sock = writer.get_extra_info('socket')
    if isinstance(sock, socket.socket):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            if hasattr(socket, "TCP_KEEPIDLE"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            if hasattr(socket, "TCP_KEEPINTVL"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            if hasattr(socket, "TCP_KEEPCNT"):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        except Exception as e:
            logger.warning(f"No se pudo configurar TCP keepalive: {e}")

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
                e = buf.find(START_END, s + 1)
                if e == -1:
                    break
                frame = buf[s + 1:e]  # sin 0x7E
                buf = buf[e + 1:]

                try:
                    payload = de_escape(frame)
                    if len(payload) < 13:
                        continue
                    # Verifica checksum
                    calc = checksum(payload[:-1])
                    if calc != payload[-1]:
                        logger.warning("Checksum inválido, descartando frame")
                        continue

                    # sin checksum
                    hdr = parse_header(payload[:-1])
                    body = payload[:-1][hdr["body_idx"]: hdr["body_idx"] + hdr["body_len"]]

                    # Log raw frame/hex con dirección RX
                    hex_payload = binascii.hexlify(payload).decode()
                    raw_logger.info(
                        "RX term->srv phone=%s msgId=0x%s %s",
                        hdr["phone_str"],
                        hdr["msg_id"].hex(),
                        hex_payload,
                    )

                    logger.info(
                        f"[RX term->srv] msgId=0x{hdr['msg_id'].hex()} "
                        f"phone={hdr['phone_str']} body_len={hdr['body_len']} "
                        f"has_subpkg={hdr['has_subpkg']}"
                    )

                    msg_id = hdr["msg_id"]
                    handler = MSG_HANDLERS.get(msg_id)
                    if handler:
                        resp = handler(session, hdr, body)
                        if resp:
                            logger.info(
                                f"[TX srv->term] phone={hdr['phone_str']} "
                                f"resp_for=0x{hdr['msg_id'].hex()} "
                                f"flow={int.from_bytes(hdr['flow_id'], 'big')}"
                            )
                            writer.write(resp)
                            await writer.drain()

                        # Después de autenticación, orquestar consultas y VIDEO
                        if msg_id == b'\x01\x02':
                            if ASK_LOCATION_AFTER_AUTH:
                                cmd = build_0x8201(hdr["phone_bcd"], session.next_flow())
                                logger.info(
                                    f"[TX srv->term] phone={hdr['phone_str']} "
                                    f"msgId=0x8201 (LocationQuery)"
                                )
                                writer.write(cmd)
                                await writer.drain()
                            if START_TEMP_TRACKING_AFTER_AUTH:
                                cmd2 = build_0x8202(
                                    hdr["phone_bcd"], session.next_flow(),
                                    interval_s=TEMP_TRACK_INTERVAL_S,
                                    validity_min=TEMP_TRACK_DURATION_MIN
                                )
                                logger.info(
                                    f"[TX srv->term] phone={hdr['phone_str']} "
                                    f"msgId=0x8202 (TempTracking "
                                    f"{TEMP_TRACK_INTERVAL_S}s x {TEMP_TRACK_DURATION_MIN}min)"
                                )
                                writer.write(cmd2)
                                await writer.drain()

                            # Iniciar VIDEO tras 0x0102
                            await start_video_if_needed(session, hdr, writer)

                        # Fallback: si ya está mandando 0x0200 y aún no hemos arrancado video,
                        # disparamos el 0x9101/0x9102 aquí.
                        if msg_id == b'\x02\x00' and not session.video_started:
                            logger.info(
                                f"[VIDEO] trigger por 0x0200 (RX term->srv) "
                                f"phone={hdr['phone_str']}, arrancando 0x9101/0x9102 (TX srv->term)"
                            )
                            await start_video_if_needed(session, hdr, writer)

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
                                0
                            )
                            logger.info(
                                f"[TX srv->term] phone={hdr['phone_str']} "
                                f"msgId=0x8001 (Ack UNKNOWN 0x{hdr['msg_id'].hex()})"
                            )
                            writer.write(resp)
                            await writer.drain()

                except Exception as ex:
                    logger.exception(f"Error manejando frame: {ex}")

    except Exception as e:
        # Silencia el traceback ruidoso cuando el peer corta
        if isinstance(e, ConnectionResetError):
            logger.info(f"Conexión reseteada por peer {peer}")
        else:
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
    port = 6808
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

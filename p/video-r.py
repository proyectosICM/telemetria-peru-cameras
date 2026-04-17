#!/usr/bin/env python3
from __future__ import annotations

"""
video.py - Servidor JT808/JT1078 con:

- Puerto 7200 (CONTROL VIDEO JT808)
- Puerto 6808 (CONTROL COMANDOS JT808)
- Puerto 7201 (VIDEO JT1078)
- Puerto HTTP interno para catalogo/ejecucion de comandos DVR

El objetivo es aislar cada DVR por su propia sesion de video y su propia
sesion de comandos, enviando comandos de forma serial por dvrPhone sin
cruzarlos con el canal usado para levantar video.
"""

import asyncio
import binascii
from contextlib import AsyncExitStack
import glob
import json
import logging
import os
import socket
import stat
import subprocess
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

# ========== Config basica ==========

HOST = "0.0.0.0"
VIDEO_CONTROL_PORT = int(os.getenv("VIDEO_CONTROL_PORT", "7200"))
#COMMAND_CONTROL_PORT = int(os.getenv("COMMAND_CONTROL_PORT", "6808"))
COMMAND_CONTROL_PORT = int(os.getenv("COMMAND_CONTROL_PORT", "1009"))
VIDEO_TCP_PORT = int(os.getenv("VIDEO_TCP_PORT", "7201"))
VIDEO_UDP_PORT = int(os.getenv("VIDEO_UDP_PORT", str(VIDEO_TCP_PORT)))
COMMAND_HTTP_PORT = int(os.getenv("COMMAND_HTTP_PORT", "7302"))
ENABLE_VIDEO_CONTROL = os.getenv("ENABLE_VIDEO_CONTROL", "1") != "0"
ENABLE_VIDEO_STREAM = os.getenv("ENABLE_VIDEO_STREAM", "1") != "0"
ENABLE_COMMAND_CONTROL = os.getenv("ENABLE_COMMAND_CONTROL", "1") != "0"
ENABLE_COMMAND_HTTP = os.getenv("ENABLE_COMMAND_HTTP", "1") != "0"

ALWAYS_ACK_UNKNOWN = True
ENABLE_CONTROL_RAW_DUMP = os.getenv("ENABLE_CONTROL_RAW_DUMP") == "1"
COMMAND_API_TOKEN = os.getenv("COMMAND_API_TOKEN", "").strip()
COMMAND_ACK_TIMEOUT_SECONDS = float(os.getenv("COMMAND_ACK_TIMEOUT_SECONDS", "5"))
ALARM_PARAM_ID = int(os.getenv("ALARM_PARAM_ID", "0x00FF0001"), 0)
DVR_GPS_API_URL = os.getenv(
    "DVR_GPS_API_URL",
    "http://telemetria-peru-api:7070/api/vehicle-snapshots/dvr",
).strip()
DVR_GPS_API_TOKEN = os.getenv("DVR_GPS_API_TOKEN", "").strip()
DVR_GPS_API_TIMEOUT_SECONDS = float(os.getenv("DVR_GPS_API_TIMEOUT_SECONDS", "2.5"))

# Fallback para asociar video por peer si todavia no hay mapping mejor.
CURRENT_PHONE = None

# ========== Config de video / AV (JT/T 1078) ==========

VIDEO_TARGET_IP = os.getenv("VIDEO_TARGET_IP", "38.43.134.172")
VIDEO_COMMAND_FORMAT = os.getenv("VIDEO_COMMAND_FORMAT", "spec").strip().lower()
VIDEO_USE_UDP = os.getenv("VIDEO_USE_UDP", "1") != "0"
VIDEO_MEDIA_TYPE = int(os.getenv("VIDEO_MEDIA_TYPE", "2"))
VIDEO_STREAM_TYPE = int(os.getenv("VIDEO_STREAM_TYPE", "1"))
VIDEO_DATA_TYPE = 1
VIDEO_FRAME_TYPE = 0
VIDEO_CODEC_CODE = int(os.getenv("VIDEO_CODEC_CODE", "0"))
MAX_CHANNELS = 8
VIDEO_CHANNELS = [
    ch
    for ch in (
        int(part.strip())
        for part in os.getenv("VIDEO_CHANNELS", "1,2,3,4,5,6,7,8").split(",")
        if part.strip()
    )
    if 1 <= ch <= MAX_CHANNELS
]
AUTO_START_VIDEO_ON_AUTH = os.getenv("AUTO_START_VIDEO_ON_AUTH", "1") != "0"
AUTO_START_VIDEO_WAIT_FOR_POSITION = os.getenv("AUTO_START_VIDEO_WAIT_FOR_POSITION", "1") != "0"
AUTO_START_VIDEO_CHANNELS = [
    ch
    for ch in (
        int(part.strip())
        for part in os.getenv("AUTO_START_VIDEO_CHANNELS", "1").split(",")
        if part.strip()
    )
    if 1 <= ch <= MAX_CHANNELS and ch in VIDEO_CHANNELS
]

H264_PIPE_DIR = "/tmp"
HLS_OUTPUT_DIR = "/var/www/video"
FFMPEG_BIN = "/usr/bin/ffmpeg"
VIDEO_DISABLE_LOCAL_PIPELINE = os.getenv("VIDEO_DISABLE_LOCAL_PIPELINE", "0") == "1"
CHANNEL_IDLE_TIMEOUT_SECONDS = float(os.getenv("CHANNEL_IDLE_TIMEOUT_SECONDS", "20"))
CHANNEL_REAPER_INTERVAL_SECONDS = float(os.getenv("CHANNEL_REAPER_INTERVAL_SECONDS", "5"))
HLS_DRAIN_SECONDS = float(os.getenv("HLS_DRAIN_SECONDS", "1.5"))
VIDEO_START_AFTER_0704_COOLDOWN_SECONDS = float(
    os.getenv("VIDEO_START_AFTER_0704_COOLDOWN_SECONDS", "5")
)
VIDEO_START_AFTER_0704_MAX_WAIT_SECONDS = float(
    os.getenv("VIDEO_START_AFTER_0704_MAX_WAIT_SECONDS", "0.75")
)
VIDEO_START_9102_ENABLED = os.getenv("VIDEO_START_9102_ENABLED", "1") != "0"
VIDEO_STATUS_NOTIFY_ENABLED = os.getenv("VIDEO_STATUS_NOTIFY_ENABLED", "0") == "1"
VIDEO_STATUS_NOTIFY_INTERVAL_SECONDS = float(
    os.getenv("VIDEO_STATUS_NOTIFY_INTERVAL_SECONDS", "5")
)
VIDEO_9208_ENABLED = os.getenv("VIDEO_9208_ENABLED", "0") == "1"
VIDEO_9208_BODY_HEX = os.getenv("VIDEO_9208_BODY_HEX", "").strip()

# Un ffmpeg por phone+canal
FFMPEG_PROCS = {}
CHANNEL_STATES = {}

# ========== Catalogo configurable de alertas DVR ==========

DEFAULT_DVR_ALERTS = [
    {
        "code": "manual_emergency",
        "name": "Emergencia manual",
        "description": "Aviso de emergencia por TTS en el terminal.",
        "durationSecondsDefault": 3,
        "requiresChannel": False,
        "command": {
            "kind": "text_tts",
            "flags": 0x0D,
            "text": "Emergencia manual",
        },
    },
    {
        "code": "adas_warning",
        "name": "Alerta ADAS",
        "description": "Alertas avanzadas de conduccion asistida.",
        "durationSecondsDefault": 3,
        "requiresChannel": False,
        "subalerts": [
            {
                "code": "fatigue",
                "name": "Fatiga",
                "command": {
                    "kind": "text_tts",
                    "flags": 0x0C,
                    "text": "Alerta de fatiga",
                },
            },
            {
                "code": "distraction",
                "name": "Distraccion",
                "command": {
                    "kind": "text_tts",
                    "flags": 0x0C,
                    "text": "Alerta de distraccion",
                },
            },
            {
                "code": "lane_departure",
                "name": "Cambio de carril",
                "command": {
                    "kind": "text_tts",
                    "flags": 0x0C,
                    "text": "Alerta de cambio de carril",
                },
            },
            {
                "code": "collision_warning",
                "name": "Colision frontal",
                "command": {
                    "kind": "text_tts",
                    "flags": 0x0C,
                    "text": "Alerta de colision frontal",
                },
            },
        ],
    },
    {
        "code": "dms_warning",
        "name": "Alerta DMS",
        "description": "Alertas del monitor de conductor.",
        "durationSecondsDefault": 3,
        "requiresChannel": False,
        "subalerts": [
            {
                "code": "smoking",
                "name": "Fumar",
                "command": {
                    "kind": "text_tts",
                    "flags": 0x0C,
                    "text": "No fumar mientras conduce",
                },
            },
            {
                "code": "phone_use",
                "name": "Uso de celular",
                "command": {
                    "kind": "text_tts",
                    "flags": 0x0C,
                    "text": "No use el celular al conducir",
                },
            },
            {
                "code": "camera_blocked",
                "name": "Camara bloqueada",
                "command": {
                    "kind": "text_tts",
                    "flags": 0x0C,
                    "text": "Camara bloqueada",
                },
            },
        ],
    },
]


def load_dvr_alerts():
    raw = os.getenv("DVR_ALERTS_JSON", "").strip()
    if not raw:
        return DEFAULT_DVR_ALERTS

    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
        logger.warning("[DVR] DVR_ALERTS_JSON no es una lista, usando default")
    except Exception as exc:
        logger.warning(f"[DVR] No se pudo parsear DVR_ALERTS_JSON: {exc}")
    return DEFAULT_DVR_ALERTS


DVR_ALERTS = load_dvr_alerts()


def normalize_phone_loose(raw_phone: str | None) -> str | None:
    if not raw_phone:
        return None
    digits = "".join(ch for ch in str(raw_phone) if ch.isdigit())
    if not digits:
        return None
    if len(digits) < 12:
        digits = ("0" * (12 - len(digits))) + digits
    elif len(digits) > 12:
        digits = digits[-12:]
    return digits


def load_auth_code_overrides():
    raw = os.getenv("JT808_AUTH_CODE_OVERRIDES_JSON", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except Exception as exc:
        logger.warning(f"[AUTH] No se pudo parsear JT808_AUTH_CODE_OVERRIDES_JSON: {exc}")
        return {}
    if not isinstance(data, dict):
        logger.warning("[AUTH] JT808_AUTH_CODE_OVERRIDES_JSON no es un objeto, se ignora")
        return {}
    overrides = {}
    for phone, token in data.items():
        phone_str = normalize_phone_loose(str(phone))
        if not phone_str:
            continue
        overrides[phone_str] = str(token)
    return overrides


JT808_AUTH_CODE_OVERRIDES = load_auth_code_overrides()
JT808_AUTH_CODE_PREFIX = os.getenv("JT808_AUTH_CODE_PREFIX", "83")
JT808_AUTH_CODE_TRIM_DIGITS = max(0, int(os.getenv("JT808_AUTH_CODE_TRIM_DIGITS", "1")))
ISSUED_AUTH_CODES = {}


def build_auth_code_for_phone(phone_str: str) -> str:
    normalized_phone = normalize_phone_loose(phone_str)
    if not normalized_phone:
        return ""
    override = JT808_AUTH_CODE_OVERRIDES.get(normalized_phone)
    if override is not None:
        return override
    base = normalized_phone
    if JT808_AUTH_CODE_TRIM_DIGITS > 0 and len(base) > JT808_AUTH_CODE_TRIM_DIGITS:
        base = base[:-JT808_AUTH_CODE_TRIM_DIGITS]
    return f"{JT808_AUTH_CODE_PREFIX}{base}"

# ========== Framing / escape JT808 ==========

START_END = b"\x7e"
ESC = b"\x7d"
ESC_MAP = {b"\x02": b"\x7e", b"\x01": b"\x7d"}
REVERSE_ESC_MAP = {b"\x7e": b"\x7d\x02", b"\x7d": b"\x7d\x01"}

# ========== Cabecera JT/T 1078 stream ==========

JT1078_MAGIC = b"\x30\x31\x63\x64"
JT1078_HEADER_MIN = 30
JT1078_PHONE_BCD_OFFSET = 8
JT1078_PHONE_BCD_LEN = 6
JT1078_LOGICAL_CHANNEL_OFFSET = 14
JT1078_DATA_TYPE_OFFSET = 15
JT1078_BODY_LEN_OFFSET = 28
JT1078_BODY_OFFSET = JT1078_BODY_LEN_OFFSET + 2
JT1078_MAX_BODY_LEN = int(os.getenv("JT1078_MAX_BODY_LEN", "8192"))


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_phone(raw_phone: str | None) -> str | None:
    if not raw_phone:
        return None
    digits = "".join(ch for ch in raw_phone if ch.isdigit())
    if not digits:
        return None
    if len(digits) < 12:
        digits = ("0" * (12 - len(digits))) + digits
    elif len(digits) > 12:
        digits = digits[-12:]
    return digits


def parse_intish(value, *, default=None):
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"Valor no soportado: {value!r}")


def json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=True).encode("utf-8")


def de_escape(payload: bytes) -> bytes:
    out, i = bytearray(), 0
    while i < len(payload):
        if payload[i:i + 1] == ESC and i + 1 < len(payload):
            out += ESC_MAP.get(payload[i + 1:i + 2], payload[i + 1:i + 2])
            i += 2
        else:
            out += payload[i:i + 1]
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


def bcd_to_str(b: bytes) -> str:
    out = ""
    for x in b:
        out += f"{(x >> 4) & 0xF}{x & 0xF}"
    return out


def parse_time_bcd6(b: bytes) -> datetime:
    s = bcd_to_str(b)
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
    return int.from_bytes(raw, "big", signed=False) / 1_000_000.0


def status_acc_on(status: int) -> bool:
    return (status & 0x1) != 0


def should_push_dvr_gps(session: "SessionState") -> bool:
    ctx = session.control_context
    return (
        bool(DVR_GPS_API_URL)
        and ctx is not None
        and not ctx.closed
        and ctx.listen_port == COMMAND_CONTROL_PORT
    )


def _post_dvr_gps_snapshot(payload: dict):
    if not DVR_GPS_API_URL:
        return
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
    }
    if DVR_GPS_API_TOKEN:
        headers["Authorization"] = f"Bearer {DVR_GPS_API_TOKEN}"
    request = Request(DVR_GPS_API_URL, data=body, headers=headers, method="POST")
    with urlopen(request, timeout=DVR_GPS_API_TIMEOUT_SECONDS) as response:
        response.read()


async def push_dvr_gps_snapshot(
    session: "SessionState",
    phone_str: str,
    *,
    latitude: float,
    longitude: float,
    speed_kmh: float,
    ignition_status: bool,
    alarm_status: bool,
    timestamp_iso: str,
):
    if not should_push_dvr_gps(session):
        return

    payload = {
        "dvrPhone": phone_str,
        "latitude": f"{latitude:.6f}",
        "longitude": f"{longitude:.6f}",
        "speed": int(round(speed_kmh)),
        "ignitionStatus": ignition_status,
        "alarmStatus": alarm_status,
        "timestamp": timestamp_iso,
    }
    try:
        await asyncio.to_thread(_post_dvr_gps_snapshot, payload)
        logger.info(
            f"[GPS-DVR] Snapshot enviado phone={phone_str} lat={payload['latitude']} "
            f"lon={payload['longitude']} speed={payload['speed']} registry=command-control"
        )
    except Exception as exc:
        logger.warning(f"[GPS-DVR] No se pudo enviar snapshot DVR phone={phone_str}: {exc}")


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("video808")
raw_logger = logging.getLogger("video808.raw")


def _parse_hex_bytes_env(name: str, raw_value: str) -> bytes:
    value = raw_value.strip().replace(" ", "")
    if not value:
        return b""
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        logger.warning(f"[CFG] {name} invalido; se ignorara: {exc}")
        return b""


VIDEO_9208_BODY = _parse_hex_bytes_env("VIDEO_9208_BODY_HEX", VIDEO_9208_BODY_HEX)
if VIDEO_9208_ENABLED and VIDEO_9208_BODY:
    logger.info(
        f"[CFG] 0x9208 habilitado body_len={len(VIDEO_9208_BODY)} "
        f"hex={VIDEO_9208_BODY.hex()}"
    )
elif VIDEO_9208_ENABLED:
    logger.warning("[CFG] 0x9208 habilitado pero VIDEO_9208_BODY_HEX esta vacio; se omitira el envio")


def get_announced_media_ports() -> tuple[int, int]:
    tcp_port = VIDEO_TCP_PORT
    udp_port = VIDEO_UDP_PORT if VIDEO_UDP_PORT > 0 else VIDEO_TCP_PORT
    return tcp_port, udp_port


def parse_header(payload: bytes):
    if len(payload) < 12:
        raise ValueError("Frame demasiado corto para header 808")
    msg_id = payload[0:2]
    props = payload[2:4]
    phone = payload[4:10]
    flow_id = payload[10:12]
    body_len = ((props[0] & 0x03) << 8) | props[1]
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
        "phone_str": normalize_phone(bcd_to_str(phone)) or bcd_to_str(phone),
        "flow_id": flow_id,
        "has_subpkg": has_subpkg,
        "subpkg": subpkg,
        "body_len": body_len,
        "body_idx": idx,
    }


def build_props(body_len: int, subpkg=False, encrypt=0):
    val = 0
    val |= body_len & 0x03FF
    val |= (encrypt & 0x7) << 10
    if subpkg:
        val |= 1 << 13
    return val.to_bytes(2, "big")


class Flow:
    def __init__(self):
        self._v = 0

    def next(self) -> bytes:
        self._v = (self._v + 1) & 0xFFFF
        return self._v.to_bytes(2, "big")


def build_downlink(msg_id: bytes, phone_bcd: bytes, flow_id_platform: bytes, body: bytes = b""):
    header = msg_id + build_props(len(body)) + phone_bcd + flow_id_platform
    frame = header + body
    cs = bytes([checksum(frame)])
    esc = do_escape(frame + cs)
    return START_END + esc + START_END


def build_0x8001(phone_bcd: bytes, flow_id_platform: bytes, orig_flow_id: bytes, orig_msg_id: bytes, result: int):
    body = orig_flow_id + orig_msg_id + bytes([result])
    return build_downlink(b"\x80\x01", phone_bcd, flow_id_platform, body)


def build_0x8100(phone_bcd: bytes, flow_id_platform: bytes, orig_flow_id: bytes, result: int = 0, auth_code: bytes = b""):
    body = orig_flow_id + bytes([result]) + auth_code
    return build_downlink(b"\x81\x00", phone_bcd, flow_id_platform, body)


def build_0x8103_single_param(phone_bcd: bytes, flow_id_platform: bytes, param_id: int, value_bytes: bytes):
    body = bytearray()
    body.append(1)
    body += param_id.to_bytes(4, "big")
    body.append(len(value_bytes))
    body += value_bytes
    return build_downlink(b"\x81\x03", phone_bcd, flow_id_platform, bytes(body))


def build_0x8300_text_message(phone_bcd: bytes, flow_id_platform: bytes, flags: int, text: str):
    body = bytearray()
    body.append(flags & 0xFF)
    body += text.encode("gbk", errors="replace")
    return build_downlink(b"\x83\x00", phone_bcd, flow_id_platform, bytes(body))


def build_0x9101(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    ip: str,
    tcp_port: int,
    udp_port: int,
    logical_channel: int,
    data_type: int = 1,
    frame_type: int = 0,
):
    ip_bytes = ip.encode("ascii")
    announced_udp_port = udp_port if udp_port > 0 else tcp_port
    if VIDEO_COMMAND_FORMAT == "legacy":
        body = bytearray()
        body += b"\x91\x01"
        body.append(len(ip_bytes))
        body += ip_bytes
        body.append(1 if VIDEO_USE_UDP else 0)
        body.append(VIDEO_MEDIA_TYPE & 0xFF)
        body.append(logical_channel & 0xFF)
        body.append(VIDEO_STREAM_TYPE & 0xFF)
        body.append(data_type & 0xFF)
        body.append(VIDEO_CODEC_CODE & 0xFF)
        body += tcp_port.to_bytes(2, "big")
        return build_downlink(b"\x91\x01", phone_bcd, flow_id_platform, bytes(body))

    body = bytearray()
    body.append(len(ip_bytes))
    body += ip_bytes
    body += tcp_port.to_bytes(2, "big")
    body += announced_udp_port.to_bytes(2, "big")
    body.append(logical_channel & 0xFF)
    body.append(data_type & 0xFF)
    body.append(frame_type & 0xFF)
    return build_downlink(b"\x91\x01", phone_bcd, flow_id_platform, bytes(body))


def build_0x9102(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    logical_channel: int,
    control_cmd: int = 1,
    close_av_type: int = 0,
    switch_stream_type: int = 0,
):
    if VIDEO_COMMAND_FORMAT == "legacy":
        body = bytearray()
        body += b"\x91\x02"
        body.append(logical_channel & 0xFF)
        body.append(control_cmd & 0xFF)
        body.append(0)
        body.append(0 if close_av_type == 2 else 1 if close_av_type == 1 else 0)
        body.append(switch_stream_type & 0xFF)
        return build_downlink(b"\x91\x02", phone_bcd, flow_id_platform, bytes(body))

    body = bytearray()
    body.append(logical_channel & 0xFF)
    body.append(control_cmd & 0xFF)
    body += close_av_type.to_bytes(2, "big")
    body += switch_stream_type.to_bytes(2, "big")
    return build_downlink(b"\x91\x02", phone_bcd, flow_id_platform, bytes(body))


def build_0x9105_av_status_notify(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    logical_channel: int,
    packet_loss_rate: int = 0,
):
    body = bytearray()
    body.append(logical_channel & 0xFF)
    body.append(max(0, min(100, int(packet_loss_rate))) & 0xFF)
    return build_downlink(b"\x91\x05", phone_bcd, flow_id_platform, bytes(body))


def build_0x9208_raw(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    body: bytes,
):
    return build_downlink(b"\x92\x08", phone_bcd, flow_id_platform, body)


def build_0x9208_from_template(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    template_body: bytes,
    ip: str,
    tcp_port: int,
    udp_port: int,
):
    if not template_body:
        raise ValueError("Template vacio para 0x9208")

    ip_bytes = ip.encode("ascii")
    original_ip_len = template_body[0]
    min_len = 1 + original_ip_len + 4
    if len(template_body) < min_len:
        raise ValueError("Template 0x9208 demasiado corto para reemplazar IP/puertos")

    remainder = template_body[min_len:]
    announced_udp_port = udp_port if udp_port > 0 else tcp_port

    body = bytearray()
    body.append(len(ip_bytes))
    body += ip_bytes
    body += tcp_port.to_bytes(2, "big")
    body += announced_udp_port.to_bytes(2, "big")
    body += remainder
    return build_downlink(b"\x92\x08", phone_bcd, flow_id_platform, bytes(body))


class SessionState:
    def __init__(self):
        self.flow = Flow()
        self.video_started = False
        self.authenticated = False
        self.position_seen = False
        self.phone_str = None
        self.phone_bcd = None
        self.control_context = None
        self.jt1078_buf = b""
        self.channels = {}
        self.first_video_chunk_logged = False
        self.jt1078_packet_count = 0
        self.jt1078_reassembly = {}
        self.media_connected = False
        self.last_media_packet = 0.0
        self.media_started = False

    def next_flow(self) -> bytes:
        return self.flow.next()

    def ensure_phone_and_pipes(self, phone_str: str):
        normalized_phone = normalize_phone(phone_str)
        if not normalized_phone:
            return
        if self.phone_str is not None:
            if self.phone_str != normalized_phone:
                logger.error(
                    f"[VID] Cambio inesperado de phone en la misma sesion: "
                    f"{self.phone_str} -> {normalized_phone}. Se ignora para evitar mezclar canales."
                )
            return

        self.phone_str = normalized_phone
        logger.info(f"[H264] Inicializando FIFOs para phone={normalized_phone}")

        for ch in VIDEO_CHANNELS:
            path = os.path.join(H264_PIPE_DIR, f"{normalized_phone}_{ch}.h264")
            try:
                st = os.stat(path)
                if stat.S_ISFIFO(st.st_mode):
                    logger.info(f"[H264] FIFO ya existia: {path}")
                else:
                    logger.warning(f"[H264] {path} existe y no es FIFO, se deja tal cual")
            except FileNotFoundError:
                try:
                    os.mkfifo(path, 0o666)
                    logger.info(f"[H264] FIFO creado: {path}")
                except FileExistsError:
                    logger.info(f"[H264] FIFO ya existia (race): {path}")
                except Exception as exc:
                    logger.warning(f"[H264] No se pudo crear FIFO {path}: {exc}")

        logger.info(f"[H264] FIFOs preparados para phone={normalized_phone} canales {VIDEO_CHANNELS}")

    def extract_phone_from_jt1078(self, buf: bytes) -> str | None:
        if len(buf) < JT1078_HEADER_MIN:
            return None
        phone_bcd = buf[JT1078_PHONE_BCD_OFFSET:JT1078_PHONE_BCD_OFFSET + JT1078_PHONE_BCD_LEN]
        if len(phone_bcd) != JT1078_PHONE_BCD_LEN:
            return None
        return normalize_phone(bcd_to_str(phone_bcd))

    def get_channel_state(self, logical_channel: int):
        if not self.phone_str or logical_channel not in VIDEO_CHANNELS:
            return None
        state = self.channels.get(logical_channel)
        if state is None:
            key = f"{self.phone_str}_{logical_channel}"
            state = CHANNEL_STATES.get(key)
            if state is None:
                state = ChannelState(self.phone_str, logical_channel)
                CHANNEL_STATES[state.key] = state
            self.channels[logical_channel] = state
        return state

    def close_all_pipes(self):
        for key, pending in list(self.jt1078_reassembly.items()):
            if not pending:
                continue
            try:
                logical_channel = int(str(key).rsplit("_", 1)[1])
            except Exception:
                logger.warning(f"[JT1078] No se pudo resolver canal para flush final key={key}")
                continue
            ch_state = self.get_channel_state(logical_channel)
            if ch_state is None:
                continue
            logger.info(
                f"[JT1078] Reensamblado incompleto al cierre, descartando "
                f"phone={self.phone_str} ch={logical_channel} bytes={len(pending)}"
            )
        for st in self.channels.values():
            try:
                st.feed_h264(b"", final=True)
            except Exception as exc:
                logger.warning(
                    f"[H264] Flush final fallido phone={st.phone_str} ch={st.channel}: {exc}"
                )
            if st.h264_started:
                logger.info(
                    f"[H264] Preservando canal phone={st.phone_str} ch={st.channel} "
                    f"tras cierre de socket 7201; se esperara reconexion o timeout"
                )
                st.touch()
                continue
            st.close(
                "sesion de video cerrada",
                cleanup_outputs=True,
                drain_seconds=0.0,
                stop_hls=True,
            )
            CHANNEL_STATES.pop(st.key, None)
        self.channels.clear()
        self.jt1078_reassembly.clear()

    def reassemble_jt1078_payload(self, logical_channel: int, sub_flag: int, payload: bytes) -> bytes | None:
        key = f"{self.phone_str}_{logical_channel}"
        if sub_flag == 0:
            self.jt1078_reassembly.pop(key, None)
            if self.jt1078_packet_count <= 20:
                logger.info(
                    f"[JT1078-ASM] ch={logical_channel} sub=0 single_len={len(payload)}"
                )
            return payload

        buf = self.jt1078_reassembly.setdefault(key, bytearray())
        if sub_flag == 1:
            buf.clear()
            buf += payload
            if self.jt1078_packet_count <= 20:
                logger.info(
                    f"[JT1078-ASM] ch={logical_channel} sub=1 start_len={len(payload)} total={len(buf)}"
                )
            return None
        if sub_flag == 3:
            buf += payload
            if self.jt1078_packet_count <= 20:
                logger.info(
                    f"[JT1078-ASM] ch={logical_channel} sub=3 append_len={len(payload)} total={len(buf)}"
                )
            return None
        if sub_flag == 2:
            buf += payload
            out = bytes(buf)
            buf.clear()
            if self.jt1078_packet_count <= 20:
                logger.info(
                    f"[JT1078-ASM] ch={logical_channel} sub=2 end_len={len(payload)} total={len(out)}"
                )
            return out
        logger.warning(
            f"[JT1078-ASM] ch={logical_channel} sub_flag desconocido={sub_flag} len={len(payload)}"
        )
        return payload

    def extract_jt1078_body(self, packet: bytes) -> tuple[bytes | None, int | None]:
        if len(packet) < JT1078_BODY_OFFSET:
            return None, None

        body_len = int.from_bytes(
            packet[JT1078_BODY_LEN_OFFSET:JT1078_BODY_LEN_OFFSET + 2],
            "big",
            signed=False,
        )
        if body_len <= 0 or body_len > JT1078_MAX_BODY_LEN:
            logger.warning(
                f"[JT1078] body_len invalido={body_len} phone={self.phone_str} "
                f"buf_len={len(packet)}"
            )
            return b"", 4

        total_len = JT1078_BODY_OFFSET + body_len
        if len(packet) < total_len:
            return None, None
        return packet[JT1078_BODY_OFFSET:total_len], total_len

    def feed_jt1078(self, chunk: bytes):
        if not self.first_video_chunk_logged:
            self.first_video_chunk_logged = True
            logger.info(f"[VID-RAW] Primer chunk recibido en 7201 len={len(chunk)} hex={chunk[:64].hex()}")

        self.jt1078_buf += chunk

        while True:
            buf = self.jt1078_buf
            if len(buf) < 4:
                return

            if buf[0:4] != JT1078_MAGIC:
                # No descartar agresivamente: puede llegar handshake previo al stream.
                if not self.first_video_chunk_logged:
                    logger.info(f"[MEDIA] Data no-JT1078 detectada (posible handshake) len={len(buf)}")
                idx = buf.find(JT1078_MAGIC, 1)
                if idx == -1:
                    self.jt1078_buf = buf[-64:]
                    return
                logger.warning(f"[JT1078] Basura antes de magic, descartando {idx} bytes.")
                self.jt1078_buf = buf[idx:]
                buf = self.jt1078_buf

            if len(buf) < JT1078_HEADER_MIN:
                return

            parsed_phone = self.extract_phone_from_jt1078(buf)
            if not self.phone_str and parsed_phone:
                self.ensure_phone_and_pipes(parsed_phone)
            elif self.phone_str and parsed_phone and self.phone_str != parsed_phone:
                logger.error(
                    f"[VID] Paquete JT1078 con phone={parsed_phone} en sesion ya ligada a "
                    f"phone={self.phone_str}. Se descarta para evitar cruce de video."
                )
                self.jt1078_buf = buf[JT1078_HEADER_MIN:]
                continue

            if not self.phone_str:
                return

            logical_channel = buf[JT1078_LOGICAL_CHANNEL_OFFSET]
            data_type_and_sub = buf[JT1078_DATA_TYPE_OFFSET]
            data_type = (data_type_and_sub & 0xF0) >> 4
            sub_flag = data_type_and_sub & 0x0F
            body, total_len = self.extract_jt1078_body(buf)
            if body is None or total_len is None:
                return
            if body == b"" and total_len == 4:
                self.jt1078_buf = buf[total_len:]
                continue
            self.jt1078_buf = buf[total_len:]
            self.jt1078_packet_count += 1
            if not self.media_started:
                self.media_started = True
                logger.info(f"[MEDIA] Primer paquete JT1078 valido recibido phone={self.phone_str}")

            if self.jt1078_packet_count <= 20:
                logger.info(
                    f"[JT1078] pkt#{self.jt1078_packet_count} ch={logical_channel} "
                    f"data_type={data_type} sub_flag={sub_flag} body_len={len(body)}"
                )

            if data_type in (0, 1, 2):
                ch_state = self.get_channel_state(logical_channel)
                if ch_state is not None:
                    payload = self.reassemble_jt1078_payload(logical_channel, sub_flag, body)
                    if payload:
                        ch_state.feed_h264(payload)
            else:
                if self.jt1078_packet_count <= 20:
                    logger.info(
                        f"[JT1078] pkt#{self.jt1078_packet_count} tipo no-video "
                        f"(ch={logical_channel} data_type={data_type}), ignorado."
                    )


class ChannelState:
    def __init__(self, phone_str: str, channel: int):
        self.phone_str = phone_str
        self.channel = channel
        self.key = f"{phone_str}_{channel}"
        self.pipe_path = os.path.join(H264_PIPE_DIR, f"{phone_str}_{channel}.h264")
        self.h264_pipe = None
        self.h264_pipe_failed = False
        self.h264_buf = b""
        self.sps_seen = False
        self.pps_seen = False
        self.idr_started = False
        self.last_sps = None
        self.last_pps = None
        self.h264_started = False
        self.first_write_logged = False
        self.last_activity_monotonic = time.monotonic()
        self.last_status_notify_monotonic = 0.0
        self.logged_nal_types = set()

    def _disable_h264_pipe(self):
        self.h264_pipe_failed = True
        if self.h264_pipe is not None:
            try:
                self.h264_pipe.close()
            except Exception:
                pass
        self.h264_pipe = None
        logger.warning(f"[H264] FIFO deshabilitado para phone={self.phone_str} ch={self.channel} (Broken pipe)")

    def _reset_parser_state(self):
        self.h264_pipe = None
        self.h264_pipe_failed = False
        self.h264_buf = b""
        self.sps_seen = False
        self.pps_seen = False
        self.idr_started = False
        self.last_sps = None
        self.last_pps = None
        self.h264_started = False
        self.first_write_logged = False
        self.logged_nal_types.clear()

    def touch(self):
        self.last_activity_monotonic = time.monotonic()

    def close(
        self,
        reason: str,
        cleanup_outputs: bool,
        drain_seconds: float = 0.0,
        stop_hls: bool = True,
    ):
        logger.info(
            f"[H264] Cerrando canal phone={self.phone_str} ch={self.channel} "
            f"reason={reason} sps_seen={self.sps_seen} pps_seen={self.pps_seen} "
            f"idr_started={self.idr_started} pending_buf={len(self.h264_buf)}"
        )
        if self.h264_pipe is not None:
            try:
                self.h264_pipe.close()
            except Exception:
                pass
        self.h264_pipe = None
        if drain_seconds > 0 and stop_hls:
            logger.info(
                f"[HLS] Esperando drenaje final phone={self.phone_str} ch={self.channel} "
                f"for {drain_seconds:.1f}s antes de detener ffmpeg"
            )
            time.sleep(drain_seconds)
        if stop_hls:
            stop_hls_for_phone(self.phone_str, self.channel, reason, cleanup_outputs=cleanup_outputs)
        self._reset_parser_state()

    def ensure_fifo_exists(self):
        try:
            st = os.stat(self.pipe_path)
            if not stat.S_ISFIFO(st.st_mode):
                logger.warning(f"[H264] {self.pipe_path} existe y no es FIFO, se deja tal cual")
        except FileNotFoundError:
            try:
                os.mkfifo(self.pipe_path, 0o666)
                logger.info(f"[H264] FIFO creada on-demand: {self.pipe_path}")
            except FileExistsError:
                logger.info(f"[H264] FIFO ya existia (race): {self.pipe_path}")
            except Exception as exc:
                logger.warning(f"[H264] No se pudo crear FIFO {self.pipe_path}: {exc}")

    def ensure_h264_pipe(self):
        if VIDEO_DISABLE_LOCAL_PIPELINE:
            return None
        if self.h264_pipe_failed:
            return None
        if self.h264_pipe is None:
            self.ensure_fifo_exists()
            try:
                self.h264_pipe = open(self.pipe_path, "wb", buffering=0)
                logger.info(f"[H264] FIFO abierto para escritura: {self.pipe_path}")
            except Exception as exc:
                logger.warning(f"[H264] No se pudo abrir FIFO {self.pipe_path}: {exc}")
                self.h264_pipe_failed = True
                self.h264_pipe = None
        return self.h264_pipe

    def _find_start_code(self, data: bytes, start: int = 0):
        n = len(data)
        i = start
        while i + 3 <= n:
            if data[i] == 0 and data[i + 1] == 0 and data[i + 2] == 1:
                return i, 3
            if i + 4 <= n and data[i] == 0 and data[i + 1] == 0 and data[i + 2] == 0 and data[i + 3] == 1:
                return i, 4
            i += 1
        return -1, 0

    def feed_h264(self, chunk: bytes, final: bool = False):
        if self.h264_pipe_failed:
            return

        self.touch()
        now = time.monotonic()
        if (
            VIDEO_STATUS_NOTIFY_ENABLED
            and not final
            and VIDEO_STATUS_NOTIFY_INTERVAL_SECONDS > 0
            and (now - self.last_status_notify_monotonic) >= VIDEO_STATUS_NOTIFY_INTERVAL_SECONDS
        ):
            self.last_status_notify_monotonic = now
            asyncio.create_task(
                notify_video_status(self.phone_str, self.channel, packet_loss_rate=0)
            )
        self.h264_buf += chunk
        data = self.h264_buf
        out = bytearray()
        pos = 0

        while True:
            sc_pos, sc_len = self._find_start_code(data, pos)
            if sc_pos == -1:
                break
            next_pos, _ = self._find_start_code(data, sc_pos + sc_len)
            if next_pos == -1:
                if not final:
                    break
                next_pos = len(data)

            nalu = data[sc_pos:next_pos]
            if sc_pos + sc_len < len(data):
                nal_type = data[sc_pos + sc_len] & 0x1F
            else:
                nal_type = -1

            if nal_type >= 0 and nal_type not in self.logged_nal_types:
                self.logged_nal_types.add(nal_type)
                logger.info(
                    f"[H264] NAL detectado phone={self.phone_str} ch={self.channel} "
                    f"nal_type={nal_type} final={final} len={len(nalu)}"
                )

            if not self.idr_started:
                if nal_type == 7:
                    if not self.sps_seen:
                        logger.info(f"[H264] SPS detectado phone={self.phone_str} ch={self.channel} (nal_type=7)")
                    self.sps_seen = True
                    self.last_sps = nalu
                elif nal_type == 8:
                    if not self.pps_seen:
                        logger.info(f"[H264] PPS detectado phone={self.phone_str} ch={self.channel} (nal_type=8)")
                    self.pps_seen = True
                    self.last_pps = nalu
                elif nal_type == 5:
                    logger.info(
                        f"[H264] IDR detectado phone={self.phone_str} ch={self.channel} "
                        f"(nal_type=5), sps_seen={self.sps_seen} pps_seen={self.pps_seen}"
                    )
                    self.idr_started = True
                    self.h264_started = True
                    logger.info(
                        f"[H264] Stream iniciado (modo tolerante) phone={self.phone_str} ch={self.channel}"
                    )
                    if VIDEO_DISABLE_LOCAL_PIPELINE:
                        logger.info(
                            f"[H264] Pipeline local deshabilitado phone={self.phone_str} ch={self.channel}; "
                            f"no se lanzara ffmpeg ni se escribira FIFO"
                        )
                    else:
                        start_hls_for_phone(self.phone_str, self.channel)
                    if self.last_sps:
                        out += self.last_sps
                    if self.last_pps:
                        out += self.last_pps
                    out += nalu
            else:
                if 1 <= nal_type <= 23:
                    out += nalu

            pos = next_pos

        self.h264_buf = b"" if final else data[pos:]
        if not out:
            return

        try:
            if VIDEO_DISABLE_LOCAL_PIPELINE:
                return
            pipe = self.ensure_h264_pipe()
            if pipe is not None:
                pipe.write(out)
                if self.h264_started and not self.first_write_logged:
                    self.first_write_logged = True
                    logger.info(
                        f"[H264] Stream de video iniciado para phone={self.phone_str} "
                        f"ch={self.channel} FIFO={self.pipe_path}"
                    )
        except BrokenPipeError as exc:
            logger.error(f"[H264] Broken pipe al escribir en FIFO phone={self.phone_str} ch={self.channel}: {exc}")
            self.close("broken pipe al escribir H264", cleanup_outputs=True)
        except Exception as exc:
            logger.error(f"[H264] Error escribiendo en FIFO phone={self.phone_str} ch={self.channel}: {exc}")


def cleanup_hls_outputs(phone_str: str, channel: int):
    prefix = os.path.join(HLS_OUTPUT_DIR, f"{phone_str}_{channel}")
    for path in glob.glob(f"{prefix}*"):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except IsADirectoryError:
            continue
        except Exception as exc:
            logger.warning(f"[HLS] No se pudo borrar {path}: {exc}")


def stop_ffmpeg_for_key(key: str, reason: str, cleanup_outputs: bool):
    proc = FFMPEG_PROCS.pop(key, None)
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2)
        except Exception as exc:
            logger.warning(f"[HLS] No se pudo detener ffmpeg {key}: {exc}")
    if cleanup_outputs:
        phone_str, channel_str = key.rsplit("_", 1)
        cleanup_hls_outputs(phone_str, int(channel_str))
    logger.info(f"[HLS] ffmpeg detenido para {key} ({reason})")


def stop_hls_for_phone(phone_str: str, channel: int, reason: str, cleanup_outputs: bool = False):
    stop_ffmpeg_for_key(f"{phone_str}_{channel}", reason, cleanup_outputs)


async def notify_video_status(phone_str: str, logical_channel: int, packet_loss_rate: int = 0):
    session_ctx = await get_control_session(phone_str, registry=VIDEO_CONTROL_SESSIONS)
    if session_ctx is None or session_ctx.closed:
        return

    flow_id = session_ctx.session.next_flow()
    await session_ctx.enqueue_command(
        "video-status",
        [
            {
                "msg_id_hex": "9105",
                "flow_id_int": int.from_bytes(flow_id, "big"),
                "frame": build_0x9105_av_status_notify(
                    session_ctx.phone_bcd,
                    flow_id,
                    logical_channel=logical_channel,
                    packet_loss_rate=packet_loss_rate,
                ),
                "wait_ack": False,
            }
        ],
    )


def start_hls_for_phone(phone_str: str, channel: int):
    key = f"{phone_str}_{channel}"
    proc = FFMPEG_PROCS.get(key)
    if proc is not None and proc.poll() is None:
        return

    fifo_path = os.path.join(H264_PIPE_DIR, f"{phone_str}_{channel}.h264")
    m3u8_path = os.path.join(HLS_OUTPUT_DIR, f"{phone_str}_{channel}.m3u8")
    segment_pattern = os.path.join(HLS_OUTPUT_DIR, f"{phone_str}_{channel}_%06d.ts")

    try:
        os.makedirs(HLS_OUTPUT_DIR, exist_ok=True)
    except Exception as exc:
        logger.warning(f"[HLS] No se pudo crear {HLS_OUTPUT_DIR}: {exc}")
        return

    cleanup_hls_outputs(phone_str, channel)
    cmd = [
        FFMPEG_BIN,
        "-loglevel", "warning",
        "-f", "h264",
        "-fflags", "+genpts+discardcorrupt",
        "-err_detect", "ignore_err",
        "-probesize", "10000000",
        "-analyzeduration", "10000000",
        "-thread_queue_size", "4096",
        "-framerate", "25",
        "-i", fifo_path,
        "-an",
        "-c:v", "libx264",
        "-preset", "veryfast",
        "-tune", "zerolatency",
        "-r", "25",
        "-g", "50",
        "-keyint_min", "50",
        "-sc_threshold", "0",
        "-force_key_frames", "expr:gte(t,n_forced*2)",
        "-f", "hls",
        "-hls_time", "2",
        "-hls_list_size", "10",
        "-hls_flags", "delete_segments+independent_segments+omit_endlist+temp_file",
        "-hls_segment_filename", segment_pattern,
        m3u8_path,
    ]

    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
        FFMPEG_PROCS[key] = proc
        logger.info(f"[HLS] Lanzado ffmpeg para phone={phone_str} ch={channel}: {' '.join(cmd)}")
    except Exception as exc:
        logger.warning(f"[HLS] No se pudo lanzar ffmpeg para {key}: {exc}")


def build_video_command_frames(session_ctx: ControlSessionContext, channels: list[int], *, start_stream: bool):
    frames = []
    action_name = "START" if start_stream else "STOP"
    announced_tcp_port, announced_udp_port = get_announced_media_ports()
    for logical_channel in channels:
        if logical_channel not in VIDEO_CHANNELS:
            raise ValueError(f"Canal de video no permitido: {logical_channel}")

        if start_stream:
            flow_9101 = int.from_bytes(session_ctx.session.next_flow(), "big")
            frames.append(
                {
                    "frame": build_0x9101(
                        session_ctx.phone_bcd,
                        flow_9101.to_bytes(2, "big"),
                        ip=VIDEO_TARGET_IP,
                        tcp_port=announced_tcp_port,
                        udp_port=announced_udp_port,
                        logical_channel=logical_channel,
                        data_type=VIDEO_DATA_TYPE,
                        frame_type=VIDEO_FRAME_TYPE,
                    ),
                    "flow_id_int": flow_9101,
                    "msg_id_hex": "9101",
                    "wait_ack": False,
                    "pause_after": 0.05,
                    "log_hex": True,
                    "announced_ip": VIDEO_TARGET_IP,
                    "announced_tcp_port": announced_tcp_port,
                    "announced_udp_port": announced_udp_port,
                }
            )
            frames.extend(
                build_standard_video_start_control_frames(
                    session_ctx,
                    logical_channel=logical_channel,
                )
            )
            frames.extend(
                build_proprietary_video_start_frames(
                    session_ctx,
                    logical_channel=logical_channel,
                    announced_tcp_port=announced_tcp_port,
                    announced_udp_port=announced_udp_port,
                )
            )
        else:
            flow_9102 = int.from_bytes(session_ctx.session.next_flow(), "big")
            frames.append(
                {
                    "frame": build_0x9102(
                        session_ctx.phone_bcd,
                        flow_9102.to_bytes(2, "big"),
                        logical_channel=logical_channel,
                        control_cmd=0,
                        close_av_type=0,
                        switch_stream_type=VIDEO_FRAME_TYPE,
                    ),
                    "flow_id_int": flow_9102,
                    "msg_id_hex": "9102",
                    "wait_ack": False,
                    "pause_after": 0.05,
                }
            )
        logger.info(
            f"[VIDEO] Preparado comando {action_name} para phone={session_ctx.phone_str} ch={logical_channel} "
            f"media_ip={VIDEO_TARGET_IP} media_tcp={announced_tcp_port} media_udp={announced_udp_port}"
        )
    return frames


def build_standard_video_start_control_frames(
    session_ctx: ControlSessionContext,
    *,
    logical_channel: int,
):
    frames = []
    if VIDEO_START_9102_ENABLED:
        flow_9102 = int.from_bytes(session_ctx.session.next_flow(), "big")
        frames.append(
            {
                "frame": build_0x9102(
                    session_ctx.phone_bcd,
                    flow_9102.to_bytes(2, "big"),
                    logical_channel=logical_channel,
                    control_cmd=1,
                    close_av_type=0,
                    switch_stream_type=VIDEO_FRAME_TYPE,
                ),
                "flow_id_int": flow_9102,
                "msg_id_hex": "9102",
                "wait_ack": False,
                "pause_after": 0.05,
            }
        )
    return frames


def build_proprietary_video_start_frames(
    session_ctx: ControlSessionContext,
    *,
    logical_channel: int,
    announced_tcp_port: int,
    announced_udp_port: int,
):
    frames = []
    if VIDEO_9208_ENABLED and VIDEO_9208_BODY:
        flow_9208 = int.from_bytes(session_ctx.session.next_flow(), "big")
        logger.info(
            f"[VIDEO] Preparado comando propietario 0x9208 para phone={session_ctx.phone_str} "
            f"ch={logical_channel} flow={flow_9208} body_len={len(VIDEO_9208_BODY)}"
        )
        frames.append(
            {
                "frame": build_0x9208_from_template(
                    session_ctx.phone_bcd,
                    flow_9208.to_bytes(2, "big"),
                    VIDEO_9208_BODY,
                    VIDEO_TARGET_IP,
                    announced_tcp_port,
                    announced_udp_port,
                ),
                "flow_id_int": flow_9208,
                "msg_id_hex": "9208",
                "wait_ack": False,
                "pause_after": 0.05,
                "log_hex": True,
                "announced_ip": VIDEO_TARGET_IP,
                "announced_tcp_port": announced_tcp_port,
                "announced_udp_port": announced_udp_port,
            }
        )
        logger.info(
            f"[9208] STREAM propietario solicitado phone={session_ctx.phone_str} ch={logical_channel} "
            f"esperando conexion de media..."
        )
    return frames


async def ensure_video_channels(phone: str | None, channels: list[int]):
    session_ctx = await get_control_session(phone, registry=VIDEO_CONTROL_SESSIONS)
    if session_ctx is None:
        raise RuntimeError("DVR sin sesion de video-control activa")
    total_wait = 0.0
    while True:
        remaining_cooldown = session_ctx.remaining_0704_cooldown()
        if remaining_cooldown <= 0:
            break
        wait_now = remaining_cooldown
        if VIDEO_START_AFTER_0704_MAX_WAIT_SECONDS > 0:
            remaining_budget = VIDEO_START_AFTER_0704_MAX_WAIT_SECONDS - total_wait
            if remaining_budget <= 0:
                logger.info(
                    f"[VIDEO] Iniciando video sin esperar mas phone={session_ctx.phone_str} "
                    f"aunque siga 0x0704 activo"
                )
                break
            wait_now = min(wait_now, remaining_budget)
        logger.info(
            f"[VIDEO] Esperando {wait_now:.2f}s para iniciar video "
            f"phone={session_ctx.phone_str} por actividad reciente 0x0704"
        )
        await asyncio.sleep(wait_now)
        total_wait += wait_now
        if session_ctx.closed:
            raise RuntimeError("Sesion de video-control cerrada durante espera por 0x0704")
    result = await session_ctx.enqueue_command(
        "video-start",
        build_video_command_frames(session_ctx, channels, start_stream=True),
    )
    return session_ctx, result


async def stop_video_channels(phone: str | None, channels: list[int]):
    session_ctx = await get_control_session(phone, registry=VIDEO_CONTROL_SESSIONS)
    if session_ctx is None:
        raise RuntimeError("DVR sin sesion de video-control activa")
    result = await session_ctx.enqueue_command(
        "video-stop",
        build_video_command_frames(session_ctx, channels, start_stream=False),
    )
    for logical_channel in channels:
        stop_hls_for_phone(session_ctx.phone_str, logical_channel, "canal detenido por API", cleanup_outputs=True)
    return session_ctx, result


async def reap_idle_channels():
    while True:
        await asyncio.sleep(CHANNEL_REAPER_INTERVAL_SECONDS)
        now = time.monotonic()
        for key, state in list(CHANNEL_STATES.items()):
            if hasattr(state, "phone_str"):
                logger.debug(
                    f"[DEBUG] Checking channel {state.phone_str}_{state.channel} "
                    f"idle={now - state.last_activity_monotonic:.2f}s"
                )
            if now - state.last_activity_monotonic <= CHANNEL_IDLE_TIMEOUT_SECONDS:
                continue
            logger.info(
                f"[HLS] Canal inactivo {key} por {CHANNEL_IDLE_TIMEOUT_SECONDS}s, deteniendo ffmpeg y limpiando salida"
            )
            state.close("canal inactivo", cleanup_outputs=True)


class ControlSessionContext:
    def __init__(
        self,
        phone_str: str,
        phone_bcd: bytes,
        session: SessionState,
        writer: asyncio.StreamWriter,
        peer,
        *,
        registry_name: str,
        listen_port: int,
    ):
        self.phone_str = phone_str
        self.phone_bcd = phone_bcd
        self.session = session
        self.writer = writer
        self.peer = peer
        self.registry_name = registry_name
        self.listen_port = listen_port
        self.created_at = utc_now_iso()
        self.last_seen_at = self.created_at
        self.last_0704_monotonic = 0.0
        self.pending_acks = {}
        self.command_queue = asyncio.Queue()
        self.closed = False
        self.worker_task = asyncio.create_task(
            self._command_worker(),
            name=f"dvr-{registry_name}-{phone_str}",
        )

    def touch(self):
        self.last_seen_at = utc_now_iso()

    def mark_batch_positions(self):
        self.last_0704_monotonic = time.monotonic()

    def remaining_0704_cooldown(self) -> float:
        if self.last_0704_monotonic <= 0 or VIDEO_START_AFTER_0704_COOLDOWN_SECONDS <= 0:
            return 0.0
        remaining = (self.last_0704_monotonic + VIDEO_START_AFTER_0704_COOLDOWN_SECONDS) - time.monotonic()
        return remaining if remaining > 0 else 0.0

    async def enqueue_command(self, command_name: str, frames: list[dict]):
        if self.closed:
            raise RuntimeError("Sesion de control cerrada")
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        await self.command_queue.put(
            {
                "command_name": command_name,
                "frames": frames,
                "future": future,
            }
        )
        return await future

    async def _command_worker(self):
        while True:
            job = await self.command_queue.get()
            if job is None:
                self.command_queue.task_done()
                break

            future = job["future"]
            try:
                results = []
                for frame_spec in job["frames"]:
                    result = await self._send_frame(frame_spec)
                    results.append(result)
                    pause_after = frame_spec.get("pause_after")
                    if pause_after:
                        await asyncio.sleep(pause_after)

                if not future.done():
                    future.set_result(
                        {
                            "status": "ack",
                            "commandName": job["command_name"],
                            "results": results,
                        }
                    )
            except Exception as exc:
                if not future.done():
                    future.set_exception(exc)
            finally:
                self.command_queue.task_done()

    async def _send_frame(self, frame_spec: dict):
        if self.closed:
            raise RuntimeError("Sesion de control cerrada")

        frame = frame_spec["frame"]
        flow_id_int = frame_spec["flow_id_int"]
        msg_id_hex = frame_spec["msg_id_hex"]
        wait_ack = frame_spec.get("wait_ack", True)

        ack_future = None
        ack_key = (flow_id_int, msg_id_hex)
        if wait_ack:
            ack_future = asyncio.get_running_loop().create_future()
            self.pending_acks[ack_key] = ack_future

        if frame_spec.get("log_hex"):
            logger.info(
                f"[CMD] preparando envio registry={self.registry_name} port={self.listen_port} "
                f"phone={self.phone_str} msgId=0x{msg_id_hex} flow={flow_id_int} hex={frame.hex()}"
            )

        self.writer.write(frame)
        await self.writer.drain()

        log_msg = (
            f"[CMD] registry={self.registry_name} port={self.listen_port} "
            f"phone={self.phone_str} msgId=0x{msg_id_hex} "
            f"flow={flow_id_int} bytes={len(frame)}"
        )
        announced_ip = frame_spec.get("announced_ip")
        announced_tcp_port = frame_spec.get("announced_tcp_port")
        announced_udp_port = frame_spec.get("announced_udp_port")
        if announced_ip is not None and announced_tcp_port is not None:
            log_msg += (
                f" media_ip={announced_ip} media_tcp={announced_tcp_port}"
                f" media_udp={announced_udp_port}"
            )
        if frame_spec.get("log_hex"):
            log_msg += f" hex={frame.hex()}"
        logger.info(log_msg)

        if not wait_ack:
            return {
                "status": "sent",
                "flowId": flow_id_int,
                "msgId": msg_id_hex,
                "commandHex": frame.hex(),
            }

        try:
            ack_result = await asyncio.wait_for(ack_future, timeout=COMMAND_ACK_TIMEOUT_SECONDS)
            ack_result["commandHex"] = frame.hex()
            return ack_result
        except asyncio.TimeoutError as exc:
            self.pending_acks.pop(ack_key, None)
            raise TimeoutError(f"Timeout esperando ACK de phone={self.phone_str} msgId=0x{msg_id_hex}") from exc

    def resolve_terminal_ack(self, resp_flow: int, resp_msg_id: bytes, result: int):
        key = (resp_flow, resp_msg_id.hex())
        future = self.pending_acks.pop(key, None)
        if future and not future.done():
            future.set_result(
                {
                    "status": "ack",
                    "flowId": resp_flow,
                    "msgId": resp_msg_id.hex(),
                    "resultCode": result,
                }
            )

    def close(self, reason: str):
        if self.closed:
            return
        self.closed = True
        for future in self.pending_acks.values():
            if not future.done():
                future.set_exception(RuntimeError(f"Sesion cerrada: {reason}"))
        self.pending_acks.clear()
        if self.worker_task and not self.worker_task.done():
            self.worker_task.cancel()

VIDEO_CONTROL_SESSIONS = {}
COMMAND_CONTROL_SESSIONS = {}
PEER_PHONE_INDEX = {}
REGISTRY_LOCK = asyncio.Lock()


async def register_control_session(
    phone_str: str,
    phone_bcd: bytes,
    session: SessionState,
    writer: asyncio.StreamWriter,
    peer,
    *,
    registry_name: str,
    registry: dict,
    peer_index: dict | None = None,
    listen_port: int,
):
    global CURRENT_PHONE

    normalized_phone = normalize_phone(phone_str)
    if not normalized_phone:
        return None

    async with REGISTRY_LOCK:
        existing = registry.get(normalized_phone)
        if existing is not None and existing.writer is not writer:
            existing.close("sesion reemplazada por nueva conexion")

        if existing is not None and existing.writer is writer:
            existing.phone_bcd = phone_bcd
            existing.session = session
            existing.touch()
            ctx = existing
        else:
            ctx = ControlSessionContext(
                normalized_phone,
                phone_bcd,
                session,
                writer,
                peer,
                registry_name=registry_name,
                listen_port=listen_port,
            )
            registry[normalized_phone] = ctx

        session.phone_str = normalized_phone
        session.phone_bcd = phone_bcd
        session.control_context = ctx
        if peer_index is not None:
            CURRENT_PHONE = normalized_phone

        if peer_index is not None and peer and peer[0]:
            peer_index[str(peer[0])] = normalized_phone

        logger.info(
            f"[REGISTRY] registry={registry_name} port={listen_port} "
            f"phone={normalized_phone} peer={peer}"
        )
        return ctx


async def unregister_control_session(
    phone_str: str | None,
    writer: asyncio.StreamWriter,
    *,
    registry_name: str,
    registry: dict,
):
    if not phone_str:
        return
    normalized_phone = normalize_phone(phone_str)
    if not normalized_phone:
        return

    async with REGISTRY_LOCK:
        ctx = registry.get(normalized_phone)
        if ctx is not None and ctx.writer is writer:
            ctx.close("conexion cerrada")
            registry.pop(normalized_phone, None)
            logger.info(f"[REGISTRY] Session removida registry={registry_name} phone={normalized_phone}")


async def get_control_session(phone_str: str | None, *, registry: dict):
    normalized_phone = normalize_phone(phone_str)
    if not normalized_phone:
        return None
    async with REGISTRY_LOCK:
        return registry.get(normalized_phone)


async def get_phone_for_peer(peer):
    if not peer:
        return normalize_phone(CURRENT_PHONE)
    async with REGISTRY_LOCK:
        return PEER_PHONE_INDEX.get(str(peer[0])) or normalize_phone(CURRENT_PHONE)


def catalog_item_to_response(item: dict):
    subalerts = []
    for sub in item.get("subalerts", []) or []:
        subalerts.append(
            {
                "code": sub.get("code"),
                "name": sub.get("name"),
                "description": sub.get("description"),
                "available": sub.get("command") is not None,
            }
        )

    has_direct_command = item.get("command") is not None
    has_subalert_command = any(sub.get("command") is not None for sub in item.get("subalerts", []) or [])
    return {
        "code": item.get("code"),
        "name": item.get("name"),
        "description": item.get("description"),
        "durationSecondsDefault": item.get("durationSecondsDefault"),
        "requiresChannel": bool(item.get("requiresChannel")),
        "available": has_direct_command or has_subalert_command,
        "subalerts": subalerts,
    }


def build_catalog_response(phone: str | None, session_ctx: ControlSessionContext | None):
    normalized_phone = normalize_phone(phone)
    return {
        "phone": normalized_phone,
        "online": session_ctx is not None and not session_ctx.closed,
        "connectedAt": session_ctx.created_at if session_ctx else None,
        "lastSeenAt": session_ctx.last_seen_at if session_ctx else None,
        "alerts": [catalog_item_to_response(item) for item in DVR_ALERTS],
    }


def resolve_alert_definition(alert_code: str, subalert_code: str | None):
    for alert in DVR_ALERTS:
        if alert.get("code") != alert_code:
            continue
        if subalert_code:
            for sub in alert.get("subalerts", []) or []:
                if sub.get("code") == subalert_code:
                    return alert, sub, sub.get("command")
            return alert, None, None
        return alert, None, alert.get("command")
    return None, None, None


def build_command_frames(session_ctx: ControlSessionContext, *, alert_code: str, subalert_code: str | None, command: dict, channel: int | None, duration_seconds: int | None):
    kind = (command or {}).get("kind")
    if not kind:
        raise ValueError(f"Alerta {alert_code}/{subalert_code or '-'} no tiene command configurado")

    frames = []

    if kind == "set_param_u8":
        param_id = parse_intish(command.get("paramId"))
        on_value = parse_intish(command.get("onValue", 1))
        off_value = parse_intish(command.get("offValue"), default=None)
        value_on = bytes([on_value & 0xFF])
        flow_id = session_ctx.session.next_flow()
        frames.append(
            {
                "msg_id_hex": "8103",
                "flow_id_int": int.from_bytes(flow_id, "big"),
                "frame": build_0x8103_single_param(session_ctx.phone_bcd, flow_id, param_id, value_on),
                "wait_ack": True,
            }
        )

        effective_duration = duration_seconds if duration_seconds is not None else parse_intish(command.get("durationSeconds"), default=None)
        if off_value is not None and effective_duration and effective_duration > 0:
            off_flow = session_ctx.session.next_flow()
            frames.append(
                {
                    "msg_id_hex": "8103",
                    "flow_id_int": int.from_bytes(off_flow, "big"),
                    "frame": build_0x8103_single_param(
                        session_ctx.phone_bcd,
                        off_flow,
                        param_id,
                        bytes([off_value & 0xFF]),
                    ),
                    "wait_ack": True,
                    "pause_after": effective_duration,
                }
            )
        return frames

    if kind == "text_tts":
        text_value = str(command.get("text") or "").strip()
        if not text_value:
            raise ValueError(f"Alerta {alert_code}/{subalert_code or '-'} no tiene texto configurado")
        flags = parse_intish(command.get("flags"), default=0x0C)
        flow_id = session_ctx.session.next_flow()
        frames.append(
            {
                "msg_id_hex": "8300",
                "flow_id_int": int.from_bytes(flow_id, "big"),
                "frame": build_0x8300_text_message(session_ctx.phone_bcd, flow_id, flags, text_value),
                "wait_ack": True,
            }
        )
        return frames

    if kind == "av_control":
        logical_channel = channel if channel is not None else parse_intish(command.get("channel"), default=1)
        control_cmd = parse_intish(command.get("controlCmd"), default=1)
        close_av_type = parse_intish(command.get("closeAvType"), default=0)
        switch_stream_type = parse_intish(command.get("switchStreamType"), default=VIDEO_FRAME_TYPE)
        flow_id = session_ctx.session.next_flow()
        frames.append(
            {
                "msg_id_hex": "9102",
                "flow_id_int": int.from_bytes(flow_id, "big"),
                "frame": build_0x9102(
                    session_ctx.phone_bcd,
                    flow_id,
                    logical_channel=logical_channel,
                    control_cmd=control_cmd,
                    close_av_type=close_av_type,
                    switch_stream_type=switch_stream_type,
                ),
                "wait_ack": True,
            }
        )
        return frames

    raise ValueError(f"Tipo de comando no soportado: {kind}")


def handle_0001_terminal_general_resp(session, hdr, body):
    if len(body) < 5:
        logger.warning(f"[0001] body demasiado corto: len={len(body)}")
        return None
    resp_flow = int.from_bytes(body[0:2], "big")
    resp_msg_id = body[2:4]
    result = body[4]
    logger.info(
        f"[0001] Ack terminal phone={hdr['phone_str']} resp_flow={resp_flow} "
        f"resp_msgId=0x{resp_msg_id.hex()} result={result}"
    )
    if resp_msg_id.hex() == "9208":
        logger.info(
            f"[9208] Ack terminal phone={hdr['phone_str']} resp_flow={resp_flow} result={result}"
        )
    if session.control_context is not None:
        session.control_context.resolve_terminal_ack(resp_flow, resp_msg_id, result)
    return None


def handle_0002_heartbeat(session, hdr, body):
    logger.info(f"[0002] Heartbeat desde phone={hdr['phone_str']}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


def handle_0003_logout(session, hdr, body):
    session.authenticated = False
    session.position_seen = False
    session.video_started = False
    logger.info(f"[0003] Logout terminal phone={hdr['phone_str']}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


def handle_0100_register(session, hdr, body):
    try:
        prov = int.from_bytes(body[0:2], "big")
        city = int.from_bytes(body[2:4], "big")
        manu = body[4:9].decode("ascii", errors="ignore").strip()
        model = body[9:29].decode("ascii", errors="ignore").strip()
        term_id = body[29:36].decode("ascii", errors="ignore").strip()
        plate_color = body[36] if len(body) > 36 else None
        plate = body[37:].decode("ascii", errors="ignore").strip() if len(body) > 37 else ""
        logger.info(
            f"[0100] Registro terminal phone={hdr['phone_str']} prov={prov} city={city} "
            f"manu={manu!r} model={model!r} term_id={term_id!r} "
            f"plate_color={plate_color} plate={plate!r}"
        )
    except Exception as exc:
        logger.exception(f"Error parseando 0x0100: {exc}")
        logger.info(f"[0100] Registro terminal phone={hdr['phone_str']} (body_len={len(body)})")

    auth_code = build_auth_code_for_phone(hdr["phone_str"])
    ISSUED_AUTH_CODES[hdr["phone_str"]] = auth_code
    logger.info(f"[0100] Auth code emitido para phone={hdr['phone_str']}: {auth_code!r}")
    return build_0x8100(
        hdr["phone_bcd"],
        session.next_flow(),
        hdr["flow_id"],
        result=0,
        auth_code=auth_code.encode("ascii", errors="ignore"),
    )


def handle_0102_auth(session, hdr, body):
    try:
        token = body.decode(errors="ignore") if body else ""
    except Exception:
        token = body.hex()
    expected_token = ISSUED_AUTH_CODES.get(hdr["phone_str"], "")
    session.authenticated = True
    if expected_token and token != expected_token:
        logger.warning(
            f"[0102] Auth phone={hdr['phone_str']} token={token!r} "
            f"esperado={expected_token!r}"
        )
    else:
        logger.info(f"[0102] Auth phone={hdr['phone_str']} token={token!r}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


def handle_0200_position(session, hdr, body):
    try:
        session.position_seen = True
        if len(body) < 28:
            logger.warning(f"[0200] body demasiado corto: len={len(body)} phone={hdr['phone_str']}")
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
                f"[0200] phone={hdr['phone_str']} alarm={alarm} status={status} "
                f"lat={lat:.6f} lon={lon:.6f} alt={alt}m speed={speed:.1f}km/h "
                f"course={course} time={dt.isoformat()}"
            )
            if should_push_dvr_gps(session):
                asyncio.create_task(
                    push_dvr_gps_snapshot(
                        session,
                        hdr["phone_str"],
                        latitude=lat,
                        longitude=lon,
                        speed_kmh=speed,
                        ignition_status=status_acc_on(status),
                        alarm_status=alarm != 0,
                        timestamp_iso=dt.isoformat(),
                    )
                )
    except Exception as exc:
        logger.exception(f"Error parseando 0x0200: {exc}")

    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


def handle_0704_batch_positions(session, hdr, body):
    try:
        session.position_seen = True
        if session.control_context is not None:
            session.control_context.mark_batch_positions()
        if len(body) < 3:
            logger.warning(f"[0704] body demasiado corto: len={len(body)} phone={hdr['phone_str']}")
            return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)

        count = int.from_bytes(body[0:2], "big")
        batch_type = body[2]
        idx = 3
        last_position_payload = None
        logger.info(f"[0704] phone={hdr['phone_str']} count={count} type={batch_type}")

        for i in range(count):
            if idx + 2 > len(body):
                logger.warning(f"[0704] sin espacio para data_len en registro {i} phone={hdr['phone_str']}")
                break

            data_len = int.from_bytes(body[idx:idx + 2], "big")
            idx += 2
            if idx + data_len > len(body):
                logger.warning(
                    f"[0704] data_len={data_len} excede body_len en registro {i} phone={hdr['phone_str']}"
                )
                break

            data = body[idx:idx + data_len]
            idx += data_len
            if len(data) < 28:
                logger.warning(
                    f"[0704] item[{i}] demasiado corto len={len(data)} phone={hdr['phone_str']}"
                )
                continue

            try:
                alarm = int.from_bytes(data[0:4], "big")
                status = int.from_bytes(data[4:8], "big")
                lat = parse_coord_u32(data[8:12])
                lon = parse_coord_u32(data[12:16])
                alt = int.from_bytes(data[16:18], "big", signed=False)
                speed = int.from_bytes(data[18:20], "big", signed=False) / 10.0
                course = int.from_bytes(data[20:22], "big", signed=False)
                dt = parse_time_bcd6(data[22:28])
                logger.info(
                    f"[0704] item[{i}] phone={hdr['phone_str']} type={batch_type} "
                    f"alarm={alarm} status={status} lat={lat:.6f} lon={lon:.6f} "
                    f"alt={alt}m speed={speed:.1f}km/h course={course} time={dt.isoformat()}"
                )
                last_position_payload = {
                    "latitude": lat,
                    "longitude": lon,
                    "speed_kmh": speed,
                    "ignition_status": status_acc_on(status),
                    "alarm_status": alarm != 0,
                    "timestamp_iso": dt.isoformat(),
                }
            except Exception as exc:
                logger.exception(f"[0704] Error parseando item[{i}] phone={hdr['phone_str']}: {exc}")
        if should_push_dvr_gps(session) and last_position_payload is not None:
            asyncio.create_task(
                push_dvr_gps_snapshot(
                    session,
                    hdr["phone_str"],
                    **last_position_payload,
                )
            )
    except Exception as exc:
        logger.exception(f"[0704] Error manejando batch phone={hdr['phone_str']}: {exc}")

    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


MSG_HANDLERS = {
    b"\x00\x01": handle_0001_terminal_general_resp,
    b"\x00\x02": handle_0002_heartbeat,
    b"\x00\x03": handle_0003_logout,
    b"\x01\x00": handle_0100_register,
    b"\x01\x02": handle_0102_auth,
    b"\x02\x00": handle_0200_position,
    b"\x07\x04": handle_0704_batch_positions,
}


async def bind_control_session(
    session: SessionState,
    hdr,
    writer: asyncio.StreamWriter,
    peer,
    *,
    registry_name: str,
    registry: dict,
    peer_index: dict | None = None,
    listen_port: int,
):
    normalized_phone = normalize_phone(hdr["phone_str"])
    if not normalized_phone:
        return None
    ctx = await register_control_session(
        normalized_phone,
        hdr["phone_bcd"],
        session,
        writer,
        peer,
        registry_name=registry_name,
        registry=registry,
        peer_index=peer_index,
        listen_port=listen_port,
    )
    if ctx is not None:
        ctx.touch()
    return ctx


async def start_video_if_needed(session: SessionState, hdr, writer):
    if session.video_started or not AUTO_START_VIDEO_ON_AUTH or not AUTO_START_VIDEO_CHANNELS:
        return
    if not session.authenticated:
        logger.info(f"[VIDEO] Se omite start para phone={hdr['phone_str']} porque aun no termino auth")
        return
    if AUTO_START_VIDEO_WAIT_FOR_POSITION and not session.position_seen:
        logger.info(f"[VIDEO] Esperando 0x0200 para phone={hdr['phone_str']} antes de iniciar video")
        return

    session.video_started = True
    phone_str = hdr["phone_str"]
    logger.info(
        f"[VIDEO] Autoarranque habilitado para phone={phone_str} canales={AUTO_START_VIDEO_CHANNELS} "
        f"position_seen={session.position_seen}"
    )
    ctx = session.control_context
    if ctx is not None and not ctx.closed:
        try:
            await ctx.enqueue_command(
                "video-start-auto",
                build_video_command_frames(ctx, AUTO_START_VIDEO_CHANNELS, start_stream=True),
            )
            return
        except Exception as exc:
            session.video_started = False
            logger.exception(
                f"[VIDEO] Error iniciando video por cola serial phone={phone_str}: {exc}"
            )
            return

    for ch in AUTO_START_VIDEO_CHANNELS:
        flow_9101 = session.next_flow()
        pkt_9101 = build_0x9101(
            hdr["phone_bcd"],
            flow_9101,
            ip=VIDEO_TARGET_IP,
            tcp_port=VIDEO_TCP_PORT,
            udp_port=VIDEO_UDP_PORT,
            logical_channel=ch,
            data_type=VIDEO_DATA_TYPE,
            frame_type=VIDEO_FRAME_TYPE,
        )
        logger.info(f"[TX] phone={phone_str} msgId=0x9101 (StartAV ch={ch} -> {VIDEO_TARGET_IP}:{VIDEO_TCP_PORT})")
        writer.write(pkt_9101)
        await writer.drain()
        await asyncio.sleep(0.05)
        logger.info(
            f"[VIDEO] StartAV enviado para phone={phone_str} ch={ch}; "
            f"no se enviara 0x9102 automatico en autoarranque"
        )


def get_json_header(headers: dict, name: str):
    return headers.get(name.lower())


async def write_http_response(writer: asyncio.StreamWriter, status_code: int, payload: dict):
    reason = {
        200: "OK",
        201: "Created",
        400: "Bad Request",
        401: "Unauthorized",
        404: "Not Found",
        409: "Conflict",
        500: "Internal Server Error",
    }.get(status_code, "OK")
    body = json_bytes(payload)
    headers = [
        f"HTTP/1.1 {status_code} {reason}",
        "Content-Type: application/json; charset=utf-8",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "",
        "",
    ]
    writer.write("\r\n".join(headers).encode("ascii") + body)
    await writer.drain()


def authorize_http_request(headers: dict):
    if not COMMAND_API_TOKEN:
        return True
    auth_header = get_json_header(headers, "authorization") or ""
    return auth_header == f"Bearer {COMMAND_API_TOKEN}"


async def handle_command_http_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        raw_head = await reader.readuntil(b"\r\n\r\n")
        head_text = raw_head.decode("utf-8", errors="ignore")
        lines = head_text.split("\r\n")
        if not lines or not lines[0]:
            await write_http_response(writer, 400, {"error": "Solicitud invalida"})
            return

        request_line = lines[0]
        try:
            method, target, _ = request_line.split(" ", 2)
        except ValueError:
            await write_http_response(writer, 400, {"error": "Request line invalida"})
            return

        headers = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

        if not authorize_http_request(headers):
            await write_http_response(writer, 401, {"error": "Unauthorized"})
            return

        content_length = int(headers.get("content-length", "0") or "0")
        body = b""
        if content_length > 0:
            body = await reader.readexactly(content_length)

        parsed = urlparse(target)
        query = parse_qs(parsed.query)

        if method == "GET" and parsed.path == "/health":
            await write_http_response(
                    writer,
                    200,
                    {
                        "status": "ok",
                        "videoControlPort": VIDEO_CONTROL_PORT,
                        "commandControlPort": COMMAND_CONTROL_PORT,
                        "videoPort": VIDEO_TCP_PORT,
                        "commandHttpPort": COMMAND_HTTP_PORT,
                    },
                )
            return

        if method == "GET" and parsed.path == "/dvr-alerts":
            phone = query.get("phone", [None])[0]
            session_ctx = await get_control_session(phone, registry=COMMAND_CONTROL_SESSIONS)
            await write_http_response(writer, 200, build_catalog_response(phone, session_ctx))
            return

        if method == "POST" and parsed.path == "/video-streams/ensure":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                await write_http_response(writer, 400, {"error": "JSON invalido"})
                return

            phone = normalize_phone(payload.get("phone"))
            channels_raw = payload.get("channels")
            if channels_raw is None:
                channels_raw = [payload.get("channel")]
            elif not isinstance(channels_raw, list):
                channels_raw = [channels_raw]
            channels = [
                ch for ch in (
                    parse_intish(item, default=None)
                    for item in (channels_raw or [])
                )
                if ch is not None
            ]
            if not phone or not channels:
                await write_http_response(writer, 400, {"error": "phone y channel/channels son obligatorios"})
                return

            try:
                session_ctx, result = await ensure_video_channels(phone, channels)
                await write_http_response(
                    writer,
                    200,
                    {
                        "status": result.get("status", "sent"),
                        "phone": session_ctx.phone_str,
                        "channels": channels,
                        "connectedAt": session_ctx.created_at,
                        "lastSeenAt": session_ctx.last_seen_at,
                    },
                )
            except Exception as exc:
                await write_http_response(
                    writer,
                    409,
                    {
                        "status": "offline",
                        "phone": phone,
                        "channels": channels,
                        "error": str(exc),
                    },
                )
            return

        if method == "POST" and parsed.path == "/video-streams/stop":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                await write_http_response(writer, 400, {"error": "JSON invalido"})
                return

            phone = normalize_phone(payload.get("phone"))
            channels_raw = payload.get("channels")
            if channels_raw is None:
                channels_raw = [payload.get("channel")]
            elif not isinstance(channels_raw, list):
                channels_raw = [channels_raw]
            channels = [
                ch for ch in (
                    parse_intish(item, default=None)
                    for item in (channels_raw or [])
                )
                if ch is not None
            ]
            if not phone or not channels:
                await write_http_response(writer, 400, {"error": "phone y channel/channels son obligatorios"})
                return

            try:
                session_ctx, result = await stop_video_channels(phone, channels)
                await write_http_response(
                    writer,
                    200,
                    {
                        "status": result.get("status", "sent"),
                        "phone": session_ctx.phone_str,
                        "channels": channels,
                        "connectedAt": session_ctx.created_at,
                        "lastSeenAt": session_ctx.last_seen_at,
                    },
                )
            except Exception as exc:
                await write_http_response(
                    writer,
                    409,
                    {
                        "status": "offline",
                        "phone": phone,
                        "channels": channels,
                        "error": str(exc),
                    },
                )
            return

        if method == "POST" and parsed.path == "/dvr-alerts/execute":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                await write_http_response(writer, 400, {"error": "JSON invalido"})
                return

            phone = normalize_phone(payload.get("phone"))
            alert_code = payload.get("alertCode")
            subalert_code = payload.get("subalertCode")
            channel = payload.get("channel")
            duration_seconds = payload.get("durationSeconds")

            if not phone or not alert_code:
                await write_http_response(writer, 400, {"error": "phone y alertCode son obligatorios"})
                return

            session_ctx = await get_control_session(phone, registry=COMMAND_CONTROL_SESSIONS)
            if session_ctx is None:
                await write_http_response(
                    writer,
                    409,
                    {
                        "status": "offline",
                        "phone": phone,
                        "error": "DVR sin sesion de control activa",
                    },
                )
                return

            alert_def, sub_def, command = resolve_alert_definition(alert_code, subalert_code)
            if alert_def is None:
                await write_http_response(writer, 404, {"error": "Alerta no configurada"})
                return

            if command is None:
                await write_http_response(
                    writer,
                    400,
                    {
                        "error": "La alerta existe pero no tiene comando configurado en cameras",
                        "alertCode": alert_code,
                        "subalertCode": subalert_code,
                    },
                )
                return

            try:
                frames = build_command_frames(
                    session_ctx,
                    alert_code=alert_code,
                    subalert_code=subalert_code,
                    command=command,
                    channel=parse_intish(channel, default=None),
                    duration_seconds=parse_intish(duration_seconds, default=None),
                )
                result = await session_ctx.enqueue_command(alert_code if not subalert_code else f"{alert_code}:{subalert_code}", frames)
                await write_http_response(
                    writer,
                    200,
                    {
                        "status": result.get("status"),
                        "phone": phone,
                        "alertCode": alert_code,
                        "subalertCode": subalert_code,
                        "results": result.get("results", []),
                        "connectedAt": session_ctx.created_at,
                        "lastSeenAt": session_ctx.last_seen_at,
                        "resolvedAlert": {
                            "code": alert_def.get("code"),
                            "name": alert_def.get("name"),
                            "subalert": sub_def.get("code") if sub_def else None,
                        },
                    },
                )
            except Exception as exc:
                logger.exception(f"[CMD] Error ejecutando alerta DVR phone={phone}: {exc}")
                await write_http_response(
                    writer,
                    500,
                    {
                        "status": "error",
                        "phone": phone,
                        "alertCode": alert_code,
                        "subalertCode": subalert_code,
                        "error": str(exc),
                    },
                )
            return

        await write_http_response(writer, 404, {"error": "Ruta no encontrada"})
    except asyncio.IncompleteReadError:
        logger.warning(f"[HTTP] Conexion cerrada prematuramente desde {peer}")
    except Exception as exc:
        logger.exception(f"[HTTP] Error procesando solicitud desde {peer}: {exc}")
        try:
            await write_http_response(writer, 500, {"error": str(exc)})
        except Exception:
            pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def handle_control_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    registry_name: str,
    registry: dict,
    listen_port: int,
    start_video_on_auth: bool,
    peer_index: dict | None = None,
):
    sock = writer.get_extra_info("socket")
    if isinstance(sock, socket.socket):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

    peer = writer.get_extra_info("peername")
    logger.info(f"[CONN] Nueva conexion CONTROL registry={registry_name} puerto {listen_port} desde {peer}")
    session = SessionState()
    buf = b""

    dump_filename = None
    dump_file = None
    if ENABLE_CONTROL_RAW_DUMP:
        dump_filename = f"video808_ctrl_raw_{peer[0]}_{peer[1]}".replace(":", "_") + ".bin"
        try:
            dump_file = open(dump_filename, "ab")
        except Exception as exc:
            logger.warning(f"[FILE] No se pudo abrir {dump_filename}: {exc}")
            dump_file = None

    try:
        while not reader.at_eof():
            chunk = await reader.read(4096)
            if not chunk:
                break

            if dump_file is not None:
                try:
                    dump_file.write(chunk)
                    dump_file.flush()
                except Exception as exc:
                    logger.warning(f"[FILE] Error escribiendo en {dump_filename}: {exc}")

            buf += chunk

            while True:
                s = buf.find(START_END)
                if s == -1:
                    break
                e = buf.find(START_END, s + 1)
                if e == -1:
                    break

                frame = buf[s + 1:e]
                buf = buf[e + 1:]

                try:
                    payload = de_escape(frame)
                    if len(payload) < 13:
                        continue

                    calc = checksum(payload[:-1])
                    if calc != payload[-1]:
                        continue

                    hdr = parse_header(payload[:-1])
                    await bind_control_session(
                        session,
                        hdr,
                        writer,
                        peer,
                        registry_name=registry_name,
                        registry=registry,
                        peer_index=peer_index,
                        listen_port=listen_port,
                    )

                    body = payload[:-1][hdr["body_idx"]:hdr["body_idx"] + hdr["body_len"]]
                    hex_payload = binascii.hexlify(payload).decode()
                    raw_logger.info("RX peer=%s phone=%s msgId=0x%s hex=%s", peer, hdr["phone_str"], hdr["msg_id"].hex(), hex_payload)
                    logger.info(
                        f"[RX] msgId=0x{hdr['msg_id'].hex()} phone={hdr['phone_str']} "
                        f"body_len={hdr['body_len']} has_subpkg={hdr['has_subpkg']}"
                    )

                    if session.control_context is not None:
                        session.control_context.touch()

                    msg_id = hdr["msg_id"]
                    handler = MSG_HANDLERS.get(msg_id)
                    if handler:
                        resp = handler(session, hdr, body)
                        if resp:
                            logger.info(
                                f"[TX] registry={registry_name} port={listen_port} "
                                f"phone={hdr['phone_str']} resp_for=0x{hdr['msg_id'].hex()} "
                                f"flow={int.from_bytes(hdr['flow_id'], 'big')}"
                            )
                            writer.write(resp)
                            await writer.drain()

                        if msg_id == b"\x01\x02":
                            if start_video_on_auth:
                                logger.info(
                                    f"[VIDEO] Auth OK para phone={hdr['phone_str']}; "
                                    f"se esperara 0x0200 antes de iniciar video"
                                )
                            else:
                                logger.info(
                                    f"[CMD] Auth OK para phone={hdr['phone_str']} en registry={registry_name}; "
                                    f"este puerto no inicia video"
                                )
                        elif msg_id == b"\x02\x00" and start_video_on_auth:
                            logger.info(
                                f"[VIDEO] Posicion recibida para phone={hdr['phone_str']} en registry={registry_name}; "
                                f"evaluando inicio de video"
                            )
                            await start_video_if_needed(session, hdr, writer)
                    else:
                        logger.info(f"[RX] MsgId no manejado: 0x{msg_id.hex()} phone={hdr['phone_str']} len={hdr['body_len']}")
                        if ALWAYS_ACK_UNKNOWN:
                            resp = build_0x8001(
                                hdr["phone_bcd"],
                                session.next_flow(),
                                hdr["flow_id"],
                                hdr["msg_id"],
                                0,
                            )
                            logger.info(f"[TX] phone={hdr['phone_str']} msgId=0x8001 (Ack UNKNOWN 0x{hdr['msg_id'].hex()})")
                            writer.write(resp)
                            await writer.drain()

                except Exception as exc:
                    logger.exception(f"[ERR] Error manejando frame: {exc}")

    except Exception as exc:
        logger.exception(f"[ERR] Error en conexion CONTROL {peer}: {exc}")
    finally:
        try:
            if dump_file is not None:
                dump_file.close()
        except Exception:
            pass

        await unregister_control_session(
            session.phone_str,
            writer,
            registry_name=registry_name,
            registry=registry,
        )

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(f"[CONN] Conexion CONTROL cerrada registry={registry_name} puerto {listen_port} {peer}")


async def handle_video_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    started_monotonic = time.monotonic()
    announced_tcp_port, announced_udp_port = get_announced_media_ports()
    logger.info(
        f"[VID] Nueva conexion de VIDEO en puerto {VIDEO_TCP_PORT} desde {peer} "
        f"announced_media_ip={VIDEO_TARGET_IP} announced_media_tcp={announced_tcp_port} "
        f"announced_media_udp={announced_udp_port}"
    )
    session = SessionState()

    try:
        while not reader.at_eof():
            chunk = await reader.read(4096)
            if not chunk:
                break

            session.last_media_packet = time.monotonic()
            if not session.media_connected:
                session.media_connected = True
                logger.info(f"[MEDIA] Conexion de media ACTIVADA peer={peer}")
            session.feed_jt1078(chunk)

        elapsed_seconds = time.monotonic() - started_monotonic
        logger.info(
            f"[VID] Fin de lectura en puerto {VIDEO_TCP_PORT} peer={peer} "
            f"phone={session.phone_str} jt1078_packets={session.jt1078_packet_count} "
            f"elapsed={elapsed_seconds:.3f}s"
        )

    except Exception as exc:
        logger.exception(f"[VID] Error en conexion de video {peer}: {exc}")
    finally:
        elapsed_seconds = time.monotonic() - started_monotonic
        logger.info(
            f"[VID] Resumen sesion VIDEO peer={peer} phone={session.phone_str} "
            f"jt1078_packets={session.jt1078_packet_count} "
            f"first_chunk_logged={session.first_video_chunk_logged} "
            f"elapsed={elapsed_seconds:.3f}s "
            f"announced_media_ip={VIDEO_TARGET_IP} "
            f"announced_media_tcp={announced_tcp_port} "
            f"announced_media_udp={announced_udp_port}"
        )
        try:
            session.close_all_pipes()
        except Exception:
            pass

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(
            f"[VID] Conexion de VIDEO cerrada {peer} "
            f"(phone={session.phone_str}, elapsed={elapsed_seconds:.3f}s)"
        )


async def create_video_control_server():
    if not ENABLE_VIDEO_CONTROL:
        return None
    return await asyncio.start_server(
        lambda reader, writer: handle_control_client(
            reader,
            writer,
            registry_name="video-control",
            registry=VIDEO_CONTROL_SESSIONS,
            listen_port=VIDEO_CONTROL_PORT,
            start_video_on_auth=True,
            peer_index=PEER_PHONE_INDEX,
        ),
        HOST,
        VIDEO_CONTROL_PORT,
    )


async def create_command_control_server():
    if not ENABLE_COMMAND_CONTROL:
        return None
    return await asyncio.start_server(
        lambda reader, writer: handle_control_client(
            reader,
            writer,
            registry_name="command-control",
            registry=COMMAND_CONTROL_SESSIONS,
            listen_port=COMMAND_CONTROL_PORT,
            start_video_on_auth=False,
        ),
        HOST,
        COMMAND_CONTROL_PORT,
    )


async def create_video_stream_server():
    if not ENABLE_VIDEO_STREAM:
        return None
    return await asyncio.start_server(handle_video_stream, HOST, VIDEO_TCP_PORT)


async def create_command_http_server():
    if not ENABLE_COMMAND_HTTP:
        return None
    return await asyncio.start_server(handle_command_http_client, HOST, COMMAND_HTTP_PORT)


def log_server_status(name: str, server):
    if server is not None:
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        logger.info(f"[MAIN] {name} escuchando en {addrs}")
    else:
        logger.info(f"[MAIN] {name} deshabilitado")


async def main():
    reaper_task = asyncio.create_task(reap_idle_channels(), name="channel-reaper")
    video_control_server = await create_video_control_server()
    video_server = await create_video_stream_server()
    command_server = await create_command_http_server()

    log_server_status("Servidor CONTROL VIDEO JT808", video_control_server)
    log_server_status("Servidor VIDEO", video_server)
    log_server_status("API interna de video DVR", command_server)

    try:
        async with AsyncExitStack() as stack:
            tasks = [reaper_task]
            if video_control_server is not None:
                await stack.enter_async_context(video_control_server)
                tasks.append(video_control_server.serve_forever())
            if video_server is not None:
                await stack.enter_async_context(video_server)
                tasks.append(video_server.serve_forever())
            if command_server is not None:
                await stack.enter_async_context(command_server)
                tasks.append(command_server.serve_forever())
            await asyncio.gather(*tasks)
    finally:
        reaper_task.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[MAIN] Servidor detenido por teclado")

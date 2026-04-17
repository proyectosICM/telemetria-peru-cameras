#!/usr/bin/env python3
#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import binascii
import json
import logging
import os
import socket
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

"""
command_server.py

Servidor JT808 de comandos, independiente de video.py.

Incluye:
- Puerto TCP de control de comandos JT808
- Puerto HTTP interno para catálogo y ejecución de comandos DVR
- Sesiones en memoria por dvrPhone
- Cola serial de comandos por sesión
- Handlers mínimos:
  0x0001 Terminal General Response
  0x0002 Heartbeat
  0x0003 Logout
  0x0100 Register
  0x0102 Auth
  0x0200 Position
  0x0704 Batch positions
- ACK general 0x8001
- Register response 0x8100
- Set param 0x8103
- Text/TTS 0x8300
- AV control 0x9102
"""

# =========================================================
# Config
# =========================================================

HOST = os.getenv("HOST", "0.0.0.0")
COMMAND_CONTROL_PORT = int(os.getenv("COMMAND_CONTROL_PORT", "1009"))
COMMAND_HTTP_PORT = int(os.getenv("COMMAND_HTTP_PORT", "7302"))

ENABLE_COMMAND_CONTROL = os.getenv("ENABLE_COMMAND_CONTROL", "1") != "0"
ENABLE_COMMAND_HTTP = os.getenv("ENABLE_COMMAND_HTTP", "1") != "0"

ALWAYS_ACK_UNKNOWN = True
ENABLE_CONTROL_RAW_DUMP = os.getenv("ENABLE_CONTROL_RAW_DUMP", "0") == "1"

COMMAND_API_TOKEN = os.getenv("COMMAND_API_TOKEN", "").strip()
COMMAND_ACK_TIMEOUT_SECONDS = float(os.getenv("COMMAND_ACK_TIMEOUT_SECONDS", "5"))

DVR_GPS_API_URL = os.getenv(
    "DVR_GPS_API_URL",
    "http://telemetria-peru-api:7070/api/vehicle-snapshots/dvr",
).strip()
DVR_GPS_API_TOKEN = os.getenv("DVR_GPS_API_TOKEN", "").strip()
DVR_GPS_API_TIMEOUT_SECONDS = float(os.getenv("DVR_GPS_API_TIMEOUT_SECONDS", "2.5"))

JT808_AUTH_CODE_PREFIX = os.getenv("JT808_AUTH_CODE_PREFIX", "83")
JT808_AUTH_CODE_TRIM_DIGITS = max(0, int(os.getenv("JT808_AUTH_CODE_TRIM_DIGITS", "1")))
ALARM_PARAM_ID = int(os.getenv("ALARM_PARAM_ID", "0x00FF0001"), 0)

# =========================================================
# Logging
# =========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("command808")
raw_logger = logging.getLogger("command808.raw")

# =========================================================
# Catálogo de alertas
# =========================================================

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

# =========================================================
# Helpers básicos
# =========================================================

START_END = b"\x7e"
ESC = b"\x7d"
ESC_MAP = {b"\x02": b"\x7e", b"\x01": b"\x7d"}
REVERSE_ESC_MAP = {b"\x7e": b"\x7d\x02", b"\x7d": b"\x7d\x01"}

COMMAND_CONTROL_SESSIONS: dict[str, "ControlSessionContext"] = {}
REGISTRY_LOCK = asyncio.Lock()
ISSUED_AUTH_CODES: dict[str, str] = {}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def normalize_phone(raw_phone: str | None) -> str | None:
    return normalize_phone_loose(raw_phone)


def build_auth_code_for_phone(phone_str: str) -> str:
    normalized_phone = normalize_phone_loose(phone_str)
    if not normalized_phone:
        return ""
    base = normalized_phone
    if JT808_AUTH_CODE_TRIM_DIGITS > 0 and len(base) > JT808_AUTH_CODE_TRIM_DIGITS:
        base = base[:-JT808_AUTH_CODE_TRIM_DIGITS]
    return f"{JT808_AUTH_CODE_PREFIX}{base}"


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

# =========================================================
# HTTP GPS snapshot
# =========================================================

def should_push_dvr_gps(session: "SessionState") -> bool:
    ctx = session.control_context
    return bool(DVR_GPS_API_URL) and ctx is not None and not ctx.closed


def _post_dvr_gps_snapshot(payload: dict):
    if not DVR_GPS_API_URL:
        return
    body = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    headers = {"Content-Type": "application/json"}
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
            f"[GPS-DVR] Snapshot enviado phone={phone_str} "
            f"lat={payload['latitude']} lon={payload['longitude']} speed={payload['speed']}"
        )
    except Exception as exc:
        logger.warning(f"[GPS-DVR] No se pudo enviar snapshot DVR phone={phone_str}: {exc}")

# =========================================================
# JT808 framing
# =========================================================

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


def build_props(body_len: int, subpkg: bool = False, encrypt: int = 0):
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


def build_0x9102(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    logical_channel: int,
    control_cmd: int = 1,
    close_av_type: int = 0,
    switch_stream_type: int = 0,
):
    body = bytearray()
    body.append(logical_channel & 0xFF)
    body.append(control_cmd & 0xFF)
    body += close_av_type.to_bytes(2, "big")
    body += switch_stream_type.to_bytes(2, "big")
    return build_downlink(b"\x91\x02", phone_bcd, flow_id_platform, bytes(body))

# =========================================================
# Estado sesión / cola de comandos
# =========================================================

class SessionState:
    def __init__(self):
        self.flow = Flow()
        self.authenticated = False
        self.position_seen = False
        self.phone_str: str | None = None
        self.phone_bcd: bytes | None = None
        self.control_context: ControlSessionContext | None = None

    def next_flow(self) -> bytes:
        return self.flow.next()


class ControlSessionContext:
    def __init__(
        self,
        phone_str: str,
        phone_bcd: bytes,
        session: SessionState,
        writer: asyncio.StreamWriter,
        peer,
    ):
        self.phone_str = phone_str
        self.phone_bcd = phone_bcd
        self.session = session
        self.writer = writer
        self.peer = peer
        self.created_at = utc_now_iso()
        self.last_seen_at = self.created_at
        self.pending_acks: dict[tuple[int, str], asyncio.Future] = {}
        self.command_queue: asyncio.Queue = asyncio.Queue()
        self.closed = False
        self.worker_task = asyncio.create_task(
            self._command_worker(),
            name=f"dvr-command-{phone_str}",
        )

    def touch(self):
        self.last_seen_at = utc_now_iso()

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

        self.writer.write(frame)
        await self.writer.drain()

        logger.info(
            f"[CMD] phone={self.phone_str} msgId=0x{msg_id_hex} flow={flow_id_int} bytes={len(frame)}"
        )

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
            raise TimeoutError(
                f"Timeout esperando ACK de phone={self.phone_str} msgId=0x{msg_id_hex}"
            ) from exc

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

# =========================================================
# Registro de sesiones
# =========================================================

async def register_control_session(
    phone_str: str,
    phone_bcd: bytes,
    session: SessionState,
    writer: asyncio.StreamWriter,
    peer,
):
    normalized_phone = normalize_phone(phone_str)
    if not normalized_phone:
        return None

    async with REGISTRY_LOCK:
        existing = COMMAND_CONTROL_SESSIONS.get(normalized_phone)
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
            )
            COMMAND_CONTROL_SESSIONS[normalized_phone] = ctx

        session.phone_str = normalized_phone
        session.phone_bcd = phone_bcd
        session.control_context = ctx

        logger.info(f"[REGISTRY] phone={normalized_phone} peer={peer}")
        return ctx


async def unregister_control_session(phone_str: str | None, writer: asyncio.StreamWriter):
    normalized_phone = normalize_phone(phone_str)
    if not normalized_phone:
        return

    async with REGISTRY_LOCK:
        ctx = COMMAND_CONTROL_SESSIONS.get(normalized_phone)
        if ctx is not None and ctx.writer is writer:
            ctx.close("conexion cerrada")
            COMMAND_CONTROL_SESSIONS.pop(normalized_phone, None)
            logger.info(f"[REGISTRY] Session removida phone={normalized_phone}")


async def get_control_session(phone_str: str | None):
    normalized_phone = normalize_phone(phone_str)
    if not normalized_phone:
        return None
    async with REGISTRY_LOCK:
        return COMMAND_CONTROL_SESSIONS.get(normalized_phone)

# =========================================================
# Catálogo / comandos
# =========================================================

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


def build_command_frames(
    session_ctx: ControlSessionContext,
    *,
    alert_code: str,
    subalert_code: str | None,
    command: dict,
    channel: int | None,
    duration_seconds: int | None,
):
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

        effective_duration = duration_seconds if duration_seconds is not None else parse_intish(
            command.get("durationSeconds"),
            default=None,
        )
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
        switch_stream_type = parse_intish(command.get("switchStreamType"), default=0)
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

# =========================================================
# Handlers JT808
# =========================================================

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
    if session.control_context is not None:
        session.control_context.resolve_terminal_ack(resp_flow, resp_msg_id, result)
    return None


def handle_0002_heartbeat(session, hdr, body):
    logger.info(f"[0002] Heartbeat desde phone={hdr['phone_str']}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


def handle_0003_logout(session, hdr, body):
    session.authenticated = False
    session.position_seen = False
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
            f"manu={manu!r} model={model!r} term_id={term_id!r} plate_color={plate_color} plate={plate!r}"
        )
    except Exception as exc:
        logger.exception(f"Error parseando 0x0100: {exc}")

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
            f"[0102] Auth phone={hdr['phone_str']} token={token!r} esperado={expected_token!r}"
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
        if len(body) < 3:
            logger.warning(f"[0704] body demasiado corto: len={len(body)} phone={hdr['phone_str']}")
            return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)

        count = int.from_bytes(body[0:2], "big")
        batch_type = body[2]
        idx = 3
        logger.info(f"[0704] phone={hdr['phone_str']} count={count} type={batch_type}")

        for item_index in range(count):
            if idx + 2 > len(body):
                break
            item_len = int.from_bytes(body[idx:idx + 2], "big")
            idx += 2
            if idx + item_len > len(body):
                break

            item_payload = body[idx:idx + item_len]
            idx += item_len

            if len(item_payload) >= 28:
                alarm = int.from_bytes(item_payload[0:4], "big")
                status = int.from_bytes(item_payload[4:8], "big")
                lat = parse_coord_u32(item_payload[8:12])
                lon = parse_coord_u32(item_payload[12:16])
                alt = int.from_bytes(item_payload[16:18], "big", signed=False)
                speed = int.from_bytes(item_payload[18:20], "big", signed=False) / 10.0
                course = int.from_bytes(item_payload[20:22], "big", signed=False)
                dt = parse_time_bcd6(item_payload[22:28])

                logger.info(
                    f"[0704] item[{item_index}] phone={hdr['phone_str']} "
                    f"alarm={alarm} status={status} lat={lat:.6f} lon={lon:.6f} "
                    f"alt={alt}m speed={speed:.1f}km/h course={course} time={dt.isoformat()}"
                )
    except Exception as exc:
        logger.exception(f"Error parseando 0x0704: {exc}")

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

# =========================================================
# TCP handler
# =========================================================

async def handle_control_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    sock = writer.get_extra_info("socket")
    if isinstance(sock, socket.socket):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

    peer = writer.get_extra_info("peername")
    session = SessionState()
    buf = b""

    logger.info(f"[CONN] Conexion CONTROL abierta {peer}")

    try:
        while not reader.at_eof():
            chunk = await reader.read(4096)
            if not chunk:
                break
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
                        logger.warning("[RX] Checksum invalido, descartando frame")
                        continue

                    hdr = parse_header(payload[:-1])
                    body = payload[:-1][hdr["body_idx"]: hdr["body_idx"] + hdr["body_len"]]

                    await register_control_session(
                        hdr["phone_str"],
                        hdr["phone_bcd"],
                        session,
                        writer,
                        peer,
                    )
                    if session.control_context is not None:
                        session.control_context.touch()

                    if ENABLE_CONTROL_RAW_DUMP:
                        raw_logger.info(
                            "RX term->srv phone=%s msgId=0x%s %s",
                            hdr["phone_str"],
                            hdr["msg_id"].hex(),
                            binascii.hexlify(payload).decode(),
                        )

                    logger.info(
                        f"[RX] msgId=0x{hdr['msg_id'].hex()} phone={hdr['phone_str']} "
                        f"body_len={hdr['body_len']} has_subpkg={hdr['has_subpkg']}"
                    )

                    handler = MSG_HANDLERS.get(hdr["msg_id"])
                    if handler:
                        resp = handler(session, hdr, body)
                        if resp:
                            logger.info(
                                f"[TX] phone={hdr['phone_str']} resp_for=0x{hdr['msg_id'].hex()} "
                                f"flow={int.from_bytes(hdr['flow_id'], 'big')}"
                            )
                            writer.write(resp)
                            await writer.drain()
                    else:
                        logger.info(
                            f"[RX] MsgId no manejado 0x{hdr['msg_id'].hex()} phone={hdr['phone_str']}"
                        )
                        if ALWAYS_ACK_UNKNOWN:
                            resp = build_0x8001(
                                hdr["phone_bcd"],
                                session.next_flow(),
                                hdr["flow_id"],
                                hdr["msg_id"],
                                0,
                            )
                            writer.write(resp)
                            await writer.drain()

                except Exception as frame_exc:
                    logger.exception(f"[ERR] Error manejando frame CONTROL {peer}: {frame_exc}")

    except ConnectionResetError as exc:
        logger.info(f"[CONN] Peer reseteo conexion CONTROL {peer}: {exc}")
    except Exception as exc:
        logger.exception(f"[ERR] Error en conexion CONTROL {peer}: {exc}")
    finally:
        await unregister_control_session(session.phone_str, writer)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(f"[CONN] Conexion CONTROL cerrada {peer}")

# =========================================================
# HTTP API
# =========================================================

def _http_response(
    status: str,
    body: bytes,
    *,
    content_type: str = "application/json; charset=utf-8",
) -> bytes:
    reason = {
        "200": "OK",
        "400": "Bad Request",
        "401": "Unauthorized",
        "404": "Not Found",
        "405": "Method Not Allowed",
        "500": "Internal Server Error",
    }.get(status, "OK")
    headers = [
        f"HTTP/1.1 {status} {reason}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(headers).encode("utf-8") + body


def _http_json(status: str, payload: dict) -> bytes:
    return _http_response(status, json_bytes(payload))


def _check_http_auth(headers: dict[str, str]) -> bool:
    if not COMMAND_API_TOKEN:
        return True
    auth = headers.get("authorization", "")
    return auth == f"Bearer {COMMAND_API_TOKEN}"


async def _read_http_request(reader: asyncio.StreamReader):
    raw = await reader.readuntil(b"\r\n\r\n")
    header_text = raw.decode("utf-8", errors="ignore")
    lines = header_text.split("\r\n")
    request_line = lines[0]
    parts = request_line.split(" ", 2)
    if len(parts) != 3:
        raise ValueError("Request line invalida")

    method, target, _ = parts
    headers = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip().lower()] = v.strip()

    content_length = int(headers.get("content-length", "0") or "0")
    body = b""
    if content_length > 0:
        body = await reader.readexactly(content_length)

    return method, target, headers, body


async def handle_command_http_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        method, target, headers, body = await _read_http_request(reader)

        if not _check_http_auth(headers):
            writer.write(_http_json("401", {"error": "unauthorized"}))
            await writer.drain()
            return

        parsed = urlparse(target)
        path = parsed.path
        query = parse_qs(parsed.query)

        if method == "GET" and path == "/health":
            writer.write(_http_json("200", {"ok": True, "service": "command-http"}))
            await writer.drain()
            return

        if method == "GET" and path in ("/catalog", "/dvr-alerts"):
            phone = (query.get("phone") or [None])[0]
            session_ctx = await get_control_session(phone)
            writer.write(_http_json("200", build_catalog_response(phone, session_ctx)))
            await writer.drain()
            return

        if method == "GET" and path == "/sessions":
            async with REGISTRY_LOCK:
                payload = {
                    "count": len(COMMAND_CONTROL_SESSIONS),
                    "items": [
                        {
                            "phone": phone,
                            "connectedAt": ctx.created_at,
                            "lastSeenAt": ctx.last_seen_at,
                            "peer": str(ctx.peer),
                            "closed": ctx.closed,
                        }
                        for phone, ctx in COMMAND_CONTROL_SESSIONS.items()
                    ],
                }
            writer.write(_http_json("200", payload))
            await writer.drain()
            return

        if method == "POST" and path in ("/command", "/dvr-alerts/execute"):
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                writer.write(_http_json("400", {"error": "JSON invalido"}))
                await writer.drain()
                return

            phone = normalize_phone(payload.get("phone"))
            alert_code = payload.get("alertCode")
            subalert_code = payload.get("subalertCode")
            channel = payload.get("channel")
            duration_seconds = payload.get("durationSeconds")

            if not phone or not alert_code:
                writer.write(_http_json("400", {"error": "phone y alertCode son obligatorios"}))
                await writer.drain()
                return

            session_ctx = await get_control_session(phone)
            if session_ctx is None or session_ctx.closed:
                writer.write(_http_json("409", {
                    "status": "offline",
                    "phone": phone,
                    "error": "DVR sin sesion de control activa",
                }))
                await writer.drain()
                return

            alert_def, subalert_def, command = resolve_alert_definition(alert_code, subalert_code)
            if alert_def is None:
                writer.write(_http_json("404", {"error": "Alerta no configurada"}))
                await writer.drain()
                return
            if subalert_code and subalert_def is None:
                writer.write(_http_json("404", {"error": "Subalerta no configurada"}))
                await writer.drain()
                return
            if command is None:
                writer.write(_http_json("400", {
                    "error": "La alerta existe pero no tiene comando configurado en cameras",
                    "alertCode": alert_code,
                    "subalertCode": subalert_code,
                }))
                await writer.drain()
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
                result = await session_ctx.enqueue_command(
                    f"{alert_code}:{subalert_code or 'default'}",
                    frames,
                )
                response = {
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
                        "subalert": subalert_def.get("code") if subalert_def else None,
                    },
                }
                writer.write(_http_json("200", response))
                await writer.drain()
                return
            except Exception as exc:
                logger.exception(f"[HTTP] Error ejecutando comando phone={phone}: {exc}")
                writer.write(_http_json("500", {
                    "status": "error",
                    "phone": phone,
                    "alertCode": alert_code,
                    "subalertCode": subalert_code,
                    "error": str(exc),
                }))
                await writer.drain()
                return

        writer.write(_http_json("404", {"error": "not_found", "path": path}))
        await writer.drain()

    except asyncio.IncompleteReadError:
        pass
    except Exception as exc:
        logger.exception(f"[HTTP] Error en cliente HTTP {peer}: {exc}")
        try:
            writer.write(_http_json("500", {"error": "internal_error", "detail": str(exc)}))
            await writer.drain()
        except Exception:
            pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

# =========================================================
# Server creators
# =========================================================

async def create_command_control_server():
    if not ENABLE_COMMAND_CONTROL:
        logger.info("[MAIN] COMMAND_CONTROL deshabilitado por env")
        return None
    server = await asyncio.start_server(handle_control_client, HOST, COMMAND_CONTROL_PORT)
    return server


async def create_command_http_server():
    if not ENABLE_COMMAND_HTTP:
        logger.info("[MAIN] COMMAND_HTTP deshabilitado por env")
        return None
    server = await asyncio.start_server(handle_command_http_client, HOST, COMMAND_HTTP_PORT)
    return server


def log_server_status(name: str, server):
    if server is None:
        logger.info(f"[MAIN] {name}: deshabilitado")
        return
    addrs = ", ".join(str(sock.getsockname()) for sock in (server.sockets or []))
    logger.info(f"[MAIN] {name} escuchando en {addrs}")

# =========================================================
# Main
# =========================================================

async def main():
    command_control_server = await create_command_control_server()
    command_server = await create_command_http_server()

    log_server_status("Servidor CONTROL COMANDOS JT808", command_control_server)
    log_server_status("API interna de comandos DVR", command_server)

    tasks = []
    if command_control_server is not None:
        tasks.append(command_control_server.serve_forever())
    if command_server is not None:
        tasks.append(command_server.serve_forever())

    if not tasks:
        logger.warning("[MAIN] No hay servidores habilitados")
        return

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[MAIN] Servidor de comandos detenido por teclado")
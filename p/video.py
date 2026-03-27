#!/usr/bin/env python3
"""
video.py - Servidor JT808/JT1078 con:

- Puerto 7200 (CONTROL JT808)
- Puerto 7201 (VIDEO JT1078)
- Puerto HTTP interno para catalogo/ejecucion de comandos DVR

El objetivo es aislar cada DVR por su propia sesion de control y enviar
comandos de forma serial por dvrPhone, evitando cruces entre equipos.
"""

import asyncio
import binascii
import json
import logging
import os
import socket
import stat
import subprocess
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse

# ========== Config basica ==========

HOST = "0.0.0.0"
CONTROL_PORT = 7200
VIDEO_TCP_PORT = 7201
VIDEO_UDP_PORT = 7201
COMMAND_HTTP_PORT = int(os.getenv("COMMAND_HTTP_PORT", "7302"))

ALWAYS_ACK_UNKNOWN = True
ENABLE_CONTROL_RAW_DUMP = os.getenv("ENABLE_CONTROL_RAW_DUMP") == "1"
COMMAND_API_TOKEN = os.getenv("COMMAND_API_TOKEN", "").strip()
COMMAND_ACK_TIMEOUT_SECONDS = float(os.getenv("COMMAND_ACK_TIMEOUT_SECONDS", "5"))

# Fallback para asociar video por peer si todavia no hay mapping mejor.
CURRENT_PHONE = None

# ========== Config de video / AV (JT/T 1078) ==========

VIDEO_TARGET_IP = os.getenv("VIDEO_TARGET_IP", "38.43.134.172")
VIDEO_DATA_TYPE = 1
VIDEO_FRAME_TYPE = 0
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

H264_PIPE_DIR = "/tmp"
HLS_OUTPUT_DIR = "/var/www/video"
FFMPEG_BIN = "/usr/bin/ffmpeg"

# Un ffmpeg por phone+canal
FFMPEG_PROCS = {}

# ========== Catalogo configurable de alertas DVR ==========

DEFAULT_DVR_ALERTS = [
    {
        "code": "manual_emergency",
        "name": "Emergencia manual",
        "description": "Pulso manual de alarma del DVR.",
        "durationSecondsDefault": 3,
        "requiresChannel": False,
        "command": None,
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
                "command": None,
            },
            {
                "code": "distraction",
                "name": "Distraccion",
                "command": None,
            },
            {
                "code": "lane_departure",
                "name": "Cambio de carril",
                "command": None,
            },
            {
                "code": "collision_warning",
                "name": "Colision frontal",
                "command": None,
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
                "command": None,
            },
            {
                "code": "phone_use",
                "name": "Uso de celular",
                "command": None,
            },
            {
                "code": "camera_blocked",
                "name": "Camara bloqueada",
                "command": None,
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

# ========== Framing / escape JT808 ==========

START_END = b"\x7e"
ESC = b"\x7d"
ESC_MAP = {b"\x02": b"\x7e", b"\x01": b"\x7d"}
REVERSE_ESC_MAP = {b"\x7e": b"\x7d\x02", b"\x7d": b"\x7d\x01"}

# ========== Cabecera JT/T 1078 stream ==========

JT1078_MAGIC = b"\x30\x31\x63\x64"
JT1078_HEADER_MIN = 30
JT1078_LOGICAL_CHANNEL_OFFSET = 14
JT1078_DATA_TYPE_OFFSET = 15
JT1078_BODY_LEN_OFFSET = 28


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


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("video808")
raw_logger = logging.getLogger("video808.raw")


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
    body = bytearray()
    body.append(len(ip_bytes))
    body += ip_bytes
    body += tcp_port.to_bytes(2, "big")
    body += udp_port.to_bytes(2, "big")
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
    body = bytearray()
    body.append(logical_channel & 0xFF)
    body.append(control_cmd & 0xFF)
    body += close_av_type.to_bytes(2, "big")
    body += switch_stream_type.to_bytes(2, "big")
    return build_downlink(b"\x91\x02", phone_bcd, flow_id_platform, bytes(body))


class SessionState:
    def __init__(self):
        self.flow = Flow()
        self.video_started = False
        self.phone_str = None
        self.phone_bcd = None
        self.control_context = None
        self.jt1078_buf = b""
        self.channels = {}
        self.first_video_chunk_logged = False
        self.jt1078_packet_count = 0

    def next_flow(self) -> bytes:
        return self.flow.next()

    def ensure_phone_and_pipes(self, phone_str: str):
        if self.phone_str is not None:
            return

        self.phone_str = phone_str
        logger.info(f"[H264] Inicializando FIFOs para phone={phone_str}")

        for ch in VIDEO_CHANNELS:
            path = os.path.join(H264_PIPE_DIR, f"{phone_str}_{ch}.h264")
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

        logger.info(f"[H264] FIFOs preparados para phone={phone_str} canales {VIDEO_CHANNELS}")

    def get_channel_state(self, logical_channel: int):
        if not self.phone_str or logical_channel not in VIDEO_CHANNELS:
            return None
        state = self.channels.get(logical_channel)
        if state is None:
            state = ChannelState(self.phone_str, logical_channel)
            self.channels[logical_channel] = state
        return state

    def close_all_pipes(self):
        for st in self.channels.values():
            if st.h264_pipe is not None:
                try:
                    st.h264_pipe.close()
                except Exception:
                    pass

    def feed_jt1078(self, chunk: bytes):
        if not self.phone_str:
            return

        if not self.first_video_chunk_logged:
            self.first_video_chunk_logged = True
            logger.info(f"[VID-RAW] Primer chunk recibido en 7201 len={len(chunk)} hex={chunk[:64].hex()}")

        self.jt1078_buf += chunk

        while True:
            buf = self.jt1078_buf
            if len(buf) < 4:
                return

            if buf[0:4] != JT1078_MAGIC:
                idx = buf.find(JT1078_MAGIC, 1)
                if idx == -1:
                    logger.warning(f"[JT1078] No se encontro magic en {len(buf)} bytes, descartando todo menos ultimos 3.")
                    self.jt1078_buf = buf[-3:]
                    return
                logger.warning(f"[JT1078] Basura antes de magic, descartando {idx} bytes.")
                self.jt1078_buf = buf[idx:]
                buf = self.jt1078_buf

            if len(buf) < JT1078_HEADER_MIN:
                return

            logical_channel = buf[JT1078_LOGICAL_CHANNEL_OFFSET]
            data_type_and_sub = buf[JT1078_DATA_TYPE_OFFSET]
            data_type = (data_type_and_sub & 0xF0) >> 4
            sub_flag = data_type_and_sub & 0x0F
            body_len = int.from_bytes(
                buf[JT1078_BODY_LEN_OFFSET:JT1078_BODY_LEN_OFFSET + 2],
                "big",
                signed=False,
            )
            total_len = JT1078_HEADER_MIN + body_len
            if len(buf) < total_len:
                return

            body = buf[30:total_len]
            self.jt1078_buf = buf[total_len:]
            self.jt1078_packet_count += 1

            if self.jt1078_packet_count <= 5:
                logger.info(
                    f"[JT1078] pkt#{self.jt1078_packet_count} ch={logical_channel} "
                    f"data_type={data_type} sub_flag={sub_flag} body_len={body_len}"
                )

            if data_type in (0, 1, 2):
                ch_state = self.get_channel_state(logical_channel)
                if ch_state is not None:
                    ch_state.feed_h264(body)
            else:
                if self.jt1078_packet_count <= 5:
                    logger.info(
                        f"[JT1078] pkt#{self.jt1078_packet_count} tipo no-video "
                        f"(ch={logical_channel} data_type={data_type}), ignorado."
                    )


class ChannelState:
    def __init__(self, phone_str: str, channel: int):
        self.phone_str = phone_str
        self.channel = channel
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

    def _disable_h264_pipe(self):
        self.h264_pipe_failed = True
        if self.h264_pipe is not None:
            try:
                self.h264_pipe.close()
            except Exception:
                pass
        self.h264_pipe = None
        logger.warning(f"[H264] FIFO deshabilitado para phone={self.phone_str} ch={self.channel} (Broken pipe)")

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

    def feed_h264(self, chunk: bytes):
        if self.h264_pipe_failed:
            return

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
                break

            nalu = data[sc_pos:next_pos]
            if sc_pos + sc_len < len(data):
                nal_type = data[sc_pos + sc_len] & 0x1F
            else:
                nal_type = -1

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
                    if self.sps_seen and self.pps_seen:
                        self.idr_started = True
                        self.h264_started = True
                        logger.info(
                            f"[H264] Arrancando stream bueno para phone={self.phone_str} "
                            f"ch={self.channel} (SPS+PPS+IDR)"
                        )
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

        self.h264_buf = data[pos:]
        if not out:
            return

        try:
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
            self._disable_h264_pipe()
        except Exception as exc:
            logger.error(f"[H264] Error escribiendo en FIFO phone={self.phone_str} ch={self.channel}: {exc}")


def start_hls_for_phone(phone_str: str, channel: int):
    key = f"{phone_str}_{channel}"
    proc = FFMPEG_PROCS.get(key)
    if proc is not None and proc.poll() is None:
        return

    fifo_path = os.path.join(H264_PIPE_DIR, f"{phone_str}_{channel}.h264")
    m3u8_path = os.path.join(HLS_OUTPUT_DIR, f"{phone_str}_{channel}.m3u8")

    try:
        os.makedirs(HLS_OUTPUT_DIR, exist_ok=True)
    except Exception as exc:
        logger.warning(f"[HLS] No se pudo crear {HLS_OUTPUT_DIR}: {exc}")
        return

    cmd = [
        FFMPEG_BIN,
        "-loglevel", "warning",
        "-fflags", "+genpts",
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
        "-hls_flags", "delete_segments+append_list+independent_segments",
        m3u8_path,
    ]

    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
        FFMPEG_PROCS[key] = proc
        logger.info(f"[HLS] Lanzado ffmpeg para phone={phone_str} ch={channel}: {' '.join(cmd)}")
    except Exception as exc:
        logger.warning(f"[HLS] No se pudo lanzar ffmpeg para {key}: {exc}")


class ControlSessionContext:
    def __init__(self, phone_str: str, phone_bcd: bytes, session: SessionState, writer: asyncio.StreamWriter, peer):
        self.phone_str = phone_str
        self.phone_bcd = phone_bcd
        self.session = session
        self.writer = writer
        self.peer = peer
        self.created_at = utc_now_iso()
        self.last_seen_at = self.created_at
        self.pending_acks = {}
        self.command_queue = asyncio.Queue()
        self.closed = False
        self.worker_task = asyncio.create_task(self._command_worker(), name=f"dvr-cmd-{phone_str}")

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
            f"[CMD] phone={self.phone_str} msgId=0x{msg_id_hex} "
            f"flow={flow_id_int} bytes={len(frame)}"
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


CONTROL_SESSIONS = {}
PEER_PHONE_INDEX = {}
REGISTRY_LOCK = asyncio.Lock()


async def register_control_session(phone_str: str, phone_bcd: bytes, session: SessionState, writer: asyncio.StreamWriter, peer):
    global CURRENT_PHONE

    normalized_phone = normalize_phone(phone_str)
    if not normalized_phone:
        return None

    async with REGISTRY_LOCK:
        existing = CONTROL_SESSIONS.get(normalized_phone)
        if existing is not None and existing.writer is not writer:
            existing.close("sesion reemplazada por nueva conexion")

        if existing is not None and existing.writer is writer:
            existing.phone_bcd = phone_bcd
            existing.session = session
            existing.touch()
            ctx = existing
        else:
            ctx = ControlSessionContext(normalized_phone, phone_bcd, session, writer, peer)
            CONTROL_SESSIONS[normalized_phone] = ctx

        session.phone_str = normalized_phone
        session.phone_bcd = phone_bcd
        session.control_context = ctx
        CURRENT_PHONE = normalized_phone

        if peer and peer[0]:
            PEER_PHONE_INDEX[str(peer[0])] = normalized_phone

        logger.info(f"[REGISTRY] Session registrada phone={normalized_phone} peer={peer}")
        return ctx


async def unregister_control_session(phone_str: str | None, writer: asyncio.StreamWriter):
    if not phone_str:
        return
    normalized_phone = normalize_phone(phone_str)
    if not normalized_phone:
        return

    async with REGISTRY_LOCK:
        ctx = CONTROL_SESSIONS.get(normalized_phone)
        if ctx is not None and ctx.writer is writer:
            ctx.close("conexion cerrada")
            CONTROL_SESSIONS.pop(normalized_phone, None)
            logger.info(f"[REGISTRY] Session removida phone={normalized_phone}")


async def get_control_session(phone_str: str | None):
    normalized_phone = normalize_phone(phone_str)
    if not normalized_phone:
        return None
    async with REGISTRY_LOCK:
        return CONTROL_SESSIONS.get(normalized_phone)


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
    if session.control_context is not None:
        session.control_context.resolve_terminal_ack(resp_flow, resp_msg_id, result)
    return None


def handle_0002_heartbeat(session, hdr, body):
    logger.info(f"[0002] Heartbeat desde phone={hdr['phone_str']}")
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

    return build_0x8100(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], result=0, auth_code=b"")


def handle_0102_auth(session, hdr, body):
    try:
        token = body.decode(errors="ignore") if body else ""
    except Exception:
        token = body.hex()
    logger.info(f"[0102] Auth phone={hdr['phone_str']} token={token!r}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


def handle_0200_position(session, hdr, body):
    try:
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
    except Exception as exc:
        logger.exception(f"Error parseando 0x0200: {exc}")

    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


MSG_HANDLERS = {
    b"\x00\x01": handle_0001_terminal_general_resp,
    b"\x00\x02": handle_0002_heartbeat,
    b"\x01\x00": handle_0100_register,
    b"\x01\x02": handle_0102_auth,
    b"\x02\x00": handle_0200_position,
}


async def bind_control_session(session: SessionState, hdr, writer: asyncio.StreamWriter, peer):
    normalized_phone = normalize_phone(hdr["phone_str"])
    if not normalized_phone:
        return None
    ctx = await register_control_session(normalized_phone, hdr["phone_bcd"], session, writer, peer)
    if ctx is not None:
        ctx.touch()
    return ctx


async def start_video_if_needed(session: SessionState, hdr, writer):
    if session.video_started:
        return

    session.video_started = True
    phone_str = hdr["phone_str"]
    for ch in VIDEO_CHANNELS:
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

        flow_9102 = session.next_flow()
        pkt_9102 = build_0x9102(
            hdr["phone_bcd"],
            flow_9102,
            logical_channel=ch,
            control_cmd=1,
            close_av_type=0,
            switch_stream_type=VIDEO_FRAME_TYPE,
        )
        logger.info(f"[TX] phone={phone_str} msgId=0x9102 (AVControl START ch={ch})")
        writer.write(pkt_9102)
        await writer.drain()


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
                    "controlPort": CONTROL_PORT,
                    "videoPort": VIDEO_TCP_PORT,
                    "commandPort": COMMAND_HTTP_PORT,
                },
            )
            return

        if method == "GET" and parsed.path == "/dvr-alerts":
            phone = query.get("phone", [None])[0]
            session_ctx = await get_control_session(phone)
            await write_http_response(writer, 200, build_catalog_response(phone, session_ctx))
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

            session_ctx = await get_control_session(phone)
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


async def handle_control_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    sock = writer.get_extra_info("socket")
    if isinstance(sock, socket.socket):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

    peer = writer.get_extra_info("peername")
    logger.info(f"[CONN] Nueva conexion CONTROL en puerto {CONTROL_PORT} desde {peer}")
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
                    await bind_control_session(session, hdr, writer, peer)

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
                                f"[TX] phone={hdr['phone_str']} resp_for=0x{hdr['msg_id'].hex()} "
                                f"flow={int.from_bytes(hdr['flow_id'], 'big')}"
                            )
                            writer.write(resp)
                            await writer.drain()

                        if msg_id == b"\x01\x02":
                            logger.info(
                                f"[VIDEO] Auth OK para phone={hdr['phone_str']}, "
                                f"enviando 0x9101/0x9102 para canales {VIDEO_CHANNELS}"
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

        await unregister_control_session(session.phone_str, writer)

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(f"[CONN] Conexion CONTROL cerrada {peer}")


async def handle_video_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    logger.info(f"[VID] Nueva conexion de VIDEO en puerto {VIDEO_TCP_PORT} desde {peer}")
    session = SessionState()

    mapped_phone = await get_phone_for_peer(peer)
    if mapped_phone:
        session.ensure_phone_and_pipes(mapped_phone)
    else:
        logger.warning("[VID] No hay phone asociado al peer; se descartan paquetes hasta que CONTROL registre el DVR.")

    try:
        while not reader.at_eof():
            chunk = await reader.read(4096)
            if not chunk:
                break

            if not session.phone_str:
                mapped_phone = await get_phone_for_peer(peer)
                if mapped_phone:
                    session.ensure_phone_and_pipes(mapped_phone)

            session.feed_jt1078(chunk)

    except Exception as exc:
        logger.exception(f"[VID] Error en conexion de video {peer}: {exc}")
    finally:
        try:
            session.close_all_pipes()
        except Exception:
            pass

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(f"[VID] Conexion de VIDEO cerrada {peer} (phone={session.phone_str})")


async def main():
    control_server = await asyncio.start_server(handle_control_client, HOST, CONTROL_PORT)
    video_server = await asyncio.start_server(handle_video_stream, HOST, VIDEO_TCP_PORT)
    command_server = await asyncio.start_server(handle_command_http_client, HOST, COMMAND_HTTP_PORT)

    addrs = ", ".join(str(s.getsockname()) for s in control_server.sockets)
    logger.info(f"[MAIN] Servidor CONTROL JT808 escuchando en {addrs}")

    v_addrs = ", ".join(str(s.getsockname()) for s in video_server.sockets)
    logger.info(f"[MAIN] Servidor VIDEO escuchando en {v_addrs}")

    c_addrs = ", ".join(str(s.getsockname()) for s in command_server.sockets)
    logger.info(f"[MAIN] API interna de comandos DVR escuchando en {c_addrs}")

    async with control_server, video_server, command_server:
        await asyncio.gather(
            control_server.serve_forever(),
            video_server.serve_forever(),
            command_server.serve_forever(),
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[MAIN] Servidor detenido por teclado")

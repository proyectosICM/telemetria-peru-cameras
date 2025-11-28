#!/usr/bin/env python3
"""
video.py - Servidor JT808 mínimo + socket separado solo para video

Hace esto:

- Puerto 7200 (CONTROL):
    * Acepta conexiones TCP JT808
    * Parsear frames JT808 (0x7E ... 0x7E)
    * Manejar:
        - 0x0100 Registro  -> responde 0x8100 (OK)
        - 0x0102 Auth      -> responde 0x8001 (OK) y envía 0x9101 + 0x9102
        - 0x0002 Heartbeat -> responde 0x8001 (OK)
        - 0x0200 Posición  -> log + 0x8001 (OK)
    * Guarda el "phone" real globalmente

- Puerto 7201 (VIDEO):
    * Acepta conexiones TCP solo de video
    * NO parsea JT808
    * Cualquier chunk que llega se manda a SessionState.feed_h264()
      usando el phone conocido para crear FIFO y lanzar ffmpeg.

- FIFO H264:       /tmp/<phone>_1.h264
- HLS de salida:   /var/www/video/<phone>_1.m3u8
"""

import asyncio
import binascii
import logging
import socket
import os
import stat
import subprocess
from datetime import datetime

# ========== Config básica ==========

HOST = "0.0.0.0"

# Puerto JT808 (control)
CONTROL_PORT = 7200

# Puerto solo de video (según 0x9101)
VIDEO_TCP_PORT = 7201
VIDEO_UDP_PORT = 7201

ALWAYS_ACK_UNKNOWN = True  # responde 0x8001 a mensajes no manejados

# "Phone" global detectado en el puerto de control
CURRENT_PHONE = None  # se setea cuando llega un 0100/0102/0200 con phone razonable

# ========== Config de video / AV (JT/T 1078) ==========

VIDEO_TARGET_IP = "38.43.134.172"  # tu IP pública
VIDEO_CHANNEL = 1                  # canal lógico
VIDEO_DATA_TYPE = 1                # 0=a+v, 1=solo video
VIDEO_FRAME_TYPE = 0               # 0=main, 1=sub

# Directorio base para los FIFOs de video
H264_PIPE_DIR = "/tmp"

# Directorio donde se escribirán los .m3u8 y segmentos HLS
HLS_OUTPUT_DIR = "/var/www/video"
FFMPEG_BIN = "/usr/bin/ffmpeg"  # ajusta si tu ffmpeg está en otra ruta

# Un ffmpeg por phone+canal
FFMPEG_PROCS = {}  # key: f"{phone}_{canal}" -> subprocess.Popen

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
logger = logging.getLogger("video808")
raw_logger = logging.getLogger("video808.raw")

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
    body = orig_flow_id + bytes([result]) + auth_code
    return build_downlink(b"\x81\x00", phone_bcd, flow_id_platform, body)


# ========== Comandos de video JT/T 1078 (0x9101 / 0x9102) ==========

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
    body.append(len(ip_bytes))                # IP length
    body += ip_bytes                          # IP
    body += tcp_port.to_bytes(2, "big")       # TCP port
    body += udp_port.to_bytes(2, "big")       # UDP port
    body.append(logical_channel & 0xFF)       # logical channel
    body.append(data_type & 0xFF)             # data type
    body.append(frame_type & 0xFF)            # frame type
    return build_downlink(b"\x91\x01", phone_bcd, flow_id_platform, bytes(body))


def build_0x9102(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    logical_channel: int,
    control_cmd: int = 1,   # 0=stop, 1=start/switch
    close_av_type: int = 0,
    switch_stream_type: int = 0,
):
    body = bytearray()
    body.append(logical_channel & 0xFF)            # logical channel
    body.append(control_cmd & 0xFF)                # control cmd
    body += close_av_type.to_bytes(2, "big")       # close AV type
    body += switch_stream_type.to_bytes(2, "big")  # stream type
    return build_downlink(b"\x91\x02", phone_bcd, flow_id_platform, bytes(body))


# ========== Handlers uplink mínimos (CONTROL) ==========

def handle_0001_terminal_general_resp(session, hdr, body):
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
    return None


def handle_0002_heartbeat(session, hdr, body):
    logger.info(f"[0002] Heartbeat desde phone={hdr['phone_str']}")
    return build_0x8001(
        hdr["phone_bcd"],
        session.next_flow(),
        hdr["flow_id"],
        hdr["msg_id"],
        0,
    )


def _update_current_phone(hdr):
    global CURRENT_PHONE
    # Si el teléfono parece medianamente razonable (solo dígitos y tamaño decente)
    if hdr["phone_str"].isdigit() and len(hdr["phone_str"]) >= 6:
        CURRENT_PHONE = hdr["phone_str"]
        logger.info(f"[GLOBAL] CURRENT_PHONE actualizado a {CURRENT_PHONE}")


def handle_0100_register(session, hdr, body):
    _update_current_phone(hdr)
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

    return build_0x8100(
        hdr["phone_bcd"],
        session.next_flow(),
        hdr["flow_id"],
        result=0,
        auth_code=b"",
    )


def handle_0102_auth(session, hdr, body):
    _update_current_phone(hdr)
    try:
        token = body.decode(errors="ignore") if body else ""
    except Exception:
        token = body.hex()
    logger.info(f"[0102] Auth phone={hdr['phone_str']} token={token!r}")
    return build_0x8001(
        hdr["phone_bcd"],
        session.next_flow(),
        hdr["flow_id"],
        hdr["msg_id"],
        0,
    )


def handle_0200_position(session, hdr, body):
    _update_current_phone(hdr)
    try:
        if len(body) < 28:
            logger.warning(
                f"[0200] body demasiado corto: len={len(body)}"
                f" phone={hdr['phone_str']}"
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
    b"\x02\x00": handle_0200_position,
}


# ========== Lanzar ffmpeg -> HLS por teléfono/canal ==========

def start_hls_for_phone(phone_str: str, channel: int = VIDEO_CHANNEL):
    key = f"{phone_str}_{channel}"

    proc = FFMPEG_PROCS.get(key)
    if proc is not None and proc.poll() is None:
        return

    fifo_path = os.path.join(H264_PIPE_DIR, f"{phone_str}_{channel}.h264")
    m3u8_path = os.path.join(HLS_OUTPUT_DIR, f"{phone_str}_{channel}.m3u8")

    try:
        os.makedirs(HLS_OUTPUT_DIR, exist_ok=True)
    except Exception as e:
        logger.warning(f"[HLS] No se pudo crear {HLS_OUTPUT_DIR}: {e}")
        return

    cmd = [
        FFMPEG_BIN,
        "-loglevel", "warning",
        "-fflags", "+genpts+nobuffer",
        "-flags", "low_delay",
        "-thread_queue_size", "4096",
        "-i", fifo_path,
        "-c:v", "libx264",
        "-preset", "veryfast",
        "-tune", "zerolatency",
        "-f", "hls",
        "-hls_time", "2",
        "-hls_list_size", "5",
        "-hls_flags", "delete_segments+append_list",
        m3u8_path,
    ]

    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL)
        FFMPEG_PROCS[key] = proc
        logger.info(
            f"[HLS] Lanzado ffmpeg para phone={phone_str} ch={channel}: "
            f"{' '.join(cmd)}"
        )
    except Exception as e:
        logger.warning(f"[HLS] No se pudo lanzar ffmpeg para {key}: {e}")


# ========== Estado de sesión (compartido) ==========

class SessionState:
    def __init__(self):
        self.flow = Flow()
        self.video_started = False

        self.phone_str = None
        self.pipe_path = None

        # Estado H.264
        self.h264_started = False          # stream "bueno" ya arrancó
        self.h264_pipe = None
        self.h264_pipe_failed = False
        self.h264_buf = b""

        # Tracking de SPS / PPS / IDR
        self.sps_seen = False
        self.pps_seen = False
        self.idr_started = False
        self.last_sps = None
        self.last_pps = None

    def next_flow(self) -> bytes:
        return self.flow.next()

    # --- manejo de FIFOs por dispositivo ---

    def ensure_phone_and_pipes(self, phone_str: str):
        if self.phone_str is not None:
            return

        self.phone_str = phone_str
        logger.info(f"[H264] Inicializando FIFOs para phone={phone_str}")

        for ch in range(1, 9):
            path = os.path.join(H264_PIPE_DIR, f"{phone_str}_{ch}.h264")
            try:
                st = os.stat(path)
                if stat.S_ISFIFO(st.st_mode):
                    logger.info(f"[H264] FIFO ya existía: {path}")
                else:
                    logger.warning(
                        f"[H264] {path} existe y no es FIFO, se deja tal cual"
                    )
            except FileNotFoundError:
                try:
                    os.mkfifo(path, 0o666)
                    logger.info(f"[H264] FIFO creado: {path}")
                except FileExistsError:
                    logger.info(f"[H264] FIFO ya existía (race): {path}")
                except Exception as e:
                    logger.warning(f"[H264] No se pudo crear FIFO {path}: {e}")

        self.pipe_path = os.path.join(
            H264_PIPE_DIR, f"{phone_str}_{VIDEO_CHANNEL}.h264"
        )
        logger.info(f"[H264] Canal de video principal: {self.pipe_path}")

        start_hls_for_phone(phone_str, VIDEO_CHANNEL)

    def _disable_h264_pipe(self):
        self.h264_pipe_failed = True
        if self.h264_pipe is not None:
            try:
                self.h264_pipe.close()
            except Exception:
                pass
        self.h264_pipe = None
        logger.warning("[H264] FIFO deshabilitado para esta sesión (Broken pipe)")

    def ensure_h264_pipe(self):
        if self.h264_pipe_failed:
            return None
        if self.pipe_path is None:
            return None

        if self.h264_pipe is None:
            try:
                self.h264_pipe = open(self.pipe_path, "wb", buffering=0)
                logger.info(f"[H264] FIFO abierto para escritura: {self.pipe_path}")
            except Exception as e:
                logger.warning(f"[H264] No se pudo abrir FIFO {self.pipe_path}: {e}")
                self.h264_pipe_failed = True
                self.h264_pipe = None
        return self.h264_pipe

    # ---------- detección de start-codes y limpieza de NALUs ----------

    def _find_start_code(self, data: bytes, start: int = 0):
        n = len(data)
        i = start
        while i + 3 <= n:
            if data[i] == 0 and data[i+1] == 0 and data[i+2] == 1:
                return i, 3
            if (
                i + 4 <= n and
                data[i] == 0 and data[i+1] == 0 and data[i+2] == 0 and data[i+3] == 1
            ):
                return i, 4
            i += 1
        return -1, 0

    def feed_h264(self, chunk: bytes):
        """
        Extrae NALUs H.264 válidos y los escribe en el FIFO:

        - Espera a ver SPS (7) y PPS (8).
        - Luego espera un IDR (5).
        - Recién ahí arranca el stream "bueno" escribiendo:
            SPS + PPS + IDR
        - A partir de entonces sólo deja pasar nal_type en 1..23.
        """
        if self.pipe_path is None or self.h264_pipe_failed:
            return

        # Acumula en buffer
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
                # No tenemos aún el siguiente NAL completo
                break

            nalu = data[sc_pos:next_pos]

            # nal header inmediatamente después del start-code
            if sc_pos + sc_len < len(data):
                nal_header = data[sc_pos + sc_len]
                nal_type = nal_header & 0x1F
            else:
                nal_type = -1

            if not self.idr_started:
                # Antes de arrancar, coleccionamos SPS/PPS y esperamos IDR
                if nal_type == 7:  # SPS
                    self.sps_seen = True
                    self.last_sps = nalu
                elif nal_type == 8:  # PPS
                    self.pps_seen = True
                    self.last_pps = nalu
                elif nal_type == 5:  # IDR
                    # Sólo arrancamos si ya tenemos SPS+PPS
                    if self.sps_seen and self.pps_seen:
                        self.idr_started = True
                        self.h264_started = True
                        # Metemos SPS + PPS + este IDR al output
                        if self.last_sps:
                            out += self.last_sps
                        if self.last_pps:
                            out += self.last_pps
                        out += nalu
                # Cualquier otra cosa antes del primer IDR limpio se tira
            else:
                # Stream ya arrancado: sólo tipos válidos 1..23
                if 1 <= nal_type <= 23:
                    out += nalu
                else:
                    # NAL raro (0, 24–31), lo ignoramos
                    pass

            pos = next_pos

        # Guardar resto (NAL incompleto)
        self.h264_buf = data[pos:]

        if out:
            try:
                pipe = self.ensure_h264_pipe()
                if pipe is not None:
                    pipe.write(out)
            except BrokenPipeError as e:
                logger.warning(
                    f"[H264] Broken pipe al escribir en {self.pipe_path}: {e}"
                )
                self._disable_h264_pipe()
            except Exception as e:
                logger.warning(
                    f"[H264] Error escribiendo en {self.pipe_path}: {e}"
                )


async def start_video_if_needed(session: SessionState, hdr, writer):
    if session.video_started:
        return

    session.video_started = True

    pkt_9101 = build_0x9101(
        hdr["phone_bcd"],
        session.next_flow(),
        ip=VIDEO_TARGET_IP,
        tcp_port=VIDEO_TCP_PORT,
        udp_port=VIDEO_UDP_PORT,
        logical_channel=VIDEO_CHANNEL,
        data_type=VIDEO_DATA_TYPE,
        frame_type=VIDEO_FRAME_TYPE,
    )
    logger.info(
        f"[TX] phone={hdr['phone_str']} msgId=0x9101 "
        f"(StartAV ch={VIDEO_CHANNEL} -> {VIDEO_TARGET_IP}:{VIDEO_TCP_PORT})"
    )
    writer.write(pkt_9101)
    await writer.drain()

    pkt_9102 = build_0x9102(
        hdr["phone_bcd"],
        session.next_flow(),
        logical_channel=VIDEO_CHANNEL,
        control_cmd=1,
        close_av_type=0,
        switch_stream_type=VIDEO_FRAME_TYPE,
    )
    logger.info(
        f"[TX] phone={hdr['phone_str']} msgId=0x9102 "
        f"(AVControl START ch={VIDEO_CHANNEL})"
    )
    writer.write(pkt_9102)
    await writer.drain()


# ========== Loop por conexión TCP (CONTROL 808) ==========

async def handle_control_client(reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter):
    sock = writer.get_extra_info("socket")
    if isinstance(sock, socket.socket):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

    peer = writer.get_extra_info("peername")
    logger.info(f"[CONN] Nueva conexión CONTROL en puerto {CONTROL_PORT} desde {peer}")
    session = SessionState()
    buf = b""

    dump_filename = f"video808_ctrl_raw_{peer[0]}_{peer[1]}.bin".replace(":", "_")
    try:
        dump_file = open(dump_filename, "ab")
    except Exception as e:
        logger.warning(f"[FILE] No se pudo abrir {dump_filename}: {e}")
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
                except Exception as e:
                    logger.warning(f"[FILE] Error escribiendo en {dump_filename}: {e}")

            buf += chunk

            while True:
                s = buf.find(START_END)
                if s == -1:
                    break
                e = buf.find(START_END, s + 1)
                if e == -1:
                    break

                frame = buf[s + 1: e]
                buf = buf[e + 1:]

                try:
                    payload = de_escape(frame)
                    if len(payload) < 13:
                        continue

                    calc = checksum(payload[:-1])
                    if calc != payload[-1]:
                        continue

                    hdr = parse_header(payload[:-1])

                    body = payload[:-1][
                        hdr["body_idx"]: hdr["body_idx"] + hdr["body_len"]
                    ]

                    hex_payload = binascii.hexlify(payload).decode()
                    raw_logger.info(
                        "RX peer=%s phone=%s msgId=0x%s hex=%s",
                        peer,
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

                        if msg_id == b"\x01\x02":
                            logger.info(
                                f"[VIDEO] Auth OK para phone={hdr['phone_str']}, "
                                f"enviando 0x9101/0x9102 para iniciar stream"
                            )
                            await start_video_if_needed(session, hdr, writer)
                    else:
                        logger.info(
                            f"[RX] MsgId no manejado: 0x{msg_id.hex()} "
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
                    logger.exception(f"[ERR] Error manejando frame: {ex}")

            # IMPORTANTE: en el socket de CONTROL NO llamamos feed_h264()

    except Exception as e:
        logger.exception(f"[ERR] Error en conexión CONTROL {peer}: {e}")
    finally:
        try:
            if dump_file is not None:
                dump_file.close()
        except Exception:
            pass

        try:
            if session.h264_pipe is not None:
                session.h264_pipe.close()
        except Exception:
            pass

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(f"[CONN] Conexión CONTROL cerrada {peer}")


# ========== Loop por conexión TCP (VIDEO PURO) ==========

async def handle_video_stream(reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter):
    global CURRENT_PHONE

    peer = writer.get_extra_info("peername")
    logger.info(f"[VID] Nueva conexión de VIDEO en puerto {VIDEO_TCP_PORT} desde {peer}")
    session = SessionState()

    # Si ya conocemos el phone por el puerto de control, lo usamos
    if CURRENT_PHONE:
        session.ensure_phone_and_pipes(CURRENT_PHONE)
    else:
        logger.warning(
            "[VID] CURRENT_PHONE aún es None, se abrirán FIFOs cuando se conozca."
        )

    try:
        while not reader.at_eof():
            chunk = await reader.read(4096)
            if not chunk:
                break

            # Si se conoce phone pero aún no se inicializó para esta sesión
            if not session.phone_str and CURRENT_PHONE:
                session.ensure_phone_and_pipes(CURRENT_PHONE)

            # Mandamos TODOS los bytes al extractor H264.
            session.feed_h264(chunk)

    except Exception as e:
        logger.exception(f"[VID] Error en conexión de video {peer}: {e}")
    finally:
        try:
            if session.h264_pipe is not None:
                session.h264_pipe.close()
        except Exception:
            pass

        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(f"[VID] Conexión de VIDEO cerrada {peer}")


# ========== main: ambos servidores en el mismo archivo ==========

async def main():
    control_server = await asyncio.start_server(
        handle_control_client, HOST, CONTROL_PORT
    )
    video_server = await asyncio.start_server(
        handle_video_stream, HOST, VIDEO_TCP_PORT
    )

    addrs = ", ".join(str(s.getsockname()) for s in control_server.sockets)
    logger.info(f"[MAIN] Servidor CONTROL JT808 escuchando en {addrs}")

    v_addrs = ", ".join(str(s.getsockname()) for s in video_server.sockets)
    logger.info(f"[MAIN] Servidor VIDEO escuchando en {v_addrs}")

    async with control_server, video_server:
        await asyncio.gather(
            control_server.serve_forever(),
            video_server.serve_forever(),
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[MAIN] Servidor detenido por teclado")

#!/usr/bin/env python3
"""
video.py - Servidor JT808 mínimo + socket separado solo para video (JT/T 1078)

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
    * Acepta conexiones TCP solo de video (stream JT/T 1078)
    * NO parsea JT808
    * Parseamos paquetes JT1078 (cabecera 0x30 0x31 0x63 0x64 + header)
      y de cada paquete sacamos SOLO el cuerpo H.264 y lo mandamos
      al canal lógico correcto (1..8) -> FIFO /tmp/<phone>_<ch>.h264

- FIFOs H264:      /tmp/<phone>_<ch>.h264  (ch = 1..8)
- HLS de salida:   /var/www/video/<phone>_<ch>.m3u8
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
VIDEO_DATA_TYPE = 1                # 0=a+v, 1=solo video
VIDEO_FRAME_TYPE = 0               # 0=main, 1=sub

# Vamos a pedir hasta 8 canales lógicos
MAX_LOGICAL_CHANNEL = 8
CHANNELS_TO_REQUEST = list(range(1, MAX_LOGICAL_CHANNEL + 1))

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

# ========== Cabecera JT/T 1078 stream (Tabla 19) ==========

JT1078_MAGIC = b"\x30\x31\x63\x64"   # 0x30 0x31 0x63 0x64
JT1078_HEADER_MIN = 30               # bytes hasta message body (header completo)

# ⚠️ Offset aproximado del canal lógico dentro del header JT1078.
# En muchos MDVR suele estar hacia el comienzo del header.
# Si ves canales raros en los logs, ajusta este valor.
LOGICAL_CHANNEL_OFFSET = 7


# ========== Helpers JT808 ==========

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

def start_hls_for_phone(phone_str: str, channel: int):
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
        # Generar PTS nuevos y sin buffer gordo
        "-fflags", "+genpts+nobuffer",
        # Cola de entrada grande para el FIFO
        "-thread_queue_size", "4096",
        # Asumimos que el H.264 viene ~25fps
        "-framerate", "25",
        "-i", fifo_path,
        # Solo video, sin audio
        "-an",
        # Reencodear para tener timing limpio y compatible
        "-c:v", "libx264",
        "-preset", "veryfast",
        "-tune", "zerolatency",
        # Forzamos salida CFR a 25 fps
        "-r", "25",
        "-f", "hls",
        # Bajamos latencia: segmentos cortos y pocos en lista
        "-hls_time", "1",
        "-hls_list_size", "3",
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


# ========== Estado H.264 por canal ==========

class H264ChannelState:
    def __init__(self, phone_str: str, channel: int):
        self.phone_str = phone_str
        self.channel = channel

        self.pipe_path = os.path.join(H264_PIPE_DIR, f"{phone_str}_{channel}.h264")
        self.h264_pipe = None
        self.h264_pipe_failed = False

        # Estado de parsing H.264
        self.h264_buf = b""
        self.sps_seen = False
        self.pps_seen = False
        self.idr_started = False
        self.last_sps = None
        self.last_pps = None
        self.h264_started = False
        self.has_logged_start = False

        # Asegurar FIFO
        try:
            st = os.stat(self.pipe_path)
            if not stat.S_ISFIFO(st.st_mode):
                logger.warning(
                    f"[H264] {self.pipe_path} existe y no es FIFO, se deja tal cual"
                )
        except FileNotFoundError:
            try:
                os.mkfifo(self.pipe_path, 0o666)
                logger.info(f"[H264] FIFO creado: {self.pipe_path}")
            except FileExistsError:
                logger.info(f"[H264] FIFO ya existía (race): {self.pipe_path}")
            except Exception as e:
                logger.warning(f"[H264] No se pudo crear FIFO {self.pipe_path}: {e}")

        # Lanzar ffmpeg para este canal
        start_hls_for_phone(phone_str, channel)

    # ---------- detección de start-codes ----------

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

    def ensure_h264_pipe(self):
        if self.h264_pipe_failed:
            return None
        if self.h264_pipe is None:
            try:
                self.h264_pipe = open(self.pipe_path, "wb", buffering=0)
                logger.info(
                    f"[H264] FIFO abierto para escritura: "
                    f"phone={self.phone_str} ch={self.channel} path={self.pipe_path}"
                )
            except Exception as e:
                logger.error(
                    f"[H264] No se pudo abrir FIFO {self.pipe_path} "
                    f"phone={self.phone_str} ch={self.channel}: {e}"
                )
                self.h264_pipe_failed = True
                self.h264_pipe = None
        return self.h264_pipe

    def feed_h264(self, chunk: bytes):
        """
        Extrae NALUs H.264 válidos y los escribe en el FIFO de ESTE canal:

        - Espera a ver SPS (7) y PPS (8).
        - Luego espera un IDR (5).
        - Recién ahí arranca el stream "bueno" escribiendo:
            SPS + PPS + IDR
        - A partir de entonces sólo deja pasar nal_type en 1..23.
        """
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
                # No tenemos aún el siguiente NAL completo
                break

            nalu = data[sc_pos:next_pos]

            if sc_pos + sc_len < len(data):
                nal_header = data[sc_pos + sc_len]
                nal_type = nal_header & 0x1F
            else:
                nal_type = -1

            if not self.idr_started:
                if nal_type == 7:  # SPS
                    self.sps_seen = True
                    self.last_sps = nalu
                elif nal_type == 8:  # PPS
                    self.pps_seen = True
                    self.last_pps = nalu
                elif nal_type == 5:  # IDR
                    if self.sps_seen and self.pps_seen:
                        self.idr_started = True
                        self.h264_started = True
                        if not self.has_logged_start:
                            self.has_logged_start = True
                            logger.info(
                                f"[H264] Iniciando transmisión para "
                                f"phone={self.phone_str} ch={self.channel} "
                                f"FIFO={self.pipe_path}"
                            )
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

        if out:
            try:
                pipe = self.ensure_h264_pipe()
                if pipe is not None:
                    pipe.write(out)
            except BrokenPipeError as e:
                logger.error(
                    f"[H264] Broken pipe escribiendo en FIFO "
                    f"phone={self.phone_str} ch={self.channel}: {e}"
                )
                self.h264_pipe_failed = True
                try:
                    if self.h264_pipe:
                        self.h264_pipe.close()
                except Exception:
                    pass
                self.h264_pipe = None
            except Exception as e:
                logger.error(
                    f"[H264] Error escribiendo en FIFO "
                    f"phone={self.phone_str} ch={self.channel}: {e}"
                )

    def close(self):
        try:
            if self.h264_pipe:
                self.h264_pipe.close()
        except Exception:
            pass


# ========== Estado de sesión (compartido) ==========

class SessionState:
    def __init__(self):
        self.flow = Flow()
        self.video_started = False

        self.phone_str = None

        # Buffer de paquetes JT/T 1078 en el socket de video
        self.jt1078_buf = b""

        # Flags de debug
        self.first_video_chunk_logged = False
        self.jt1078_packet_count = 0

        # Un estado H264 por canal lógico
        self.channels = {}  # logical_channel -> H264ChannelState

    def next_flow(self) -> bytes:
        return self.flow.next()

    # --- manejo de FIFOs por dispositivo (pre-crea) ---

    def ensure_phone_and_pipes(self, phone_str: str):
        if self.phone_str is not None:
            return

        self.phone_str = phone_str
        logger.info(
            f"[SESSION] Asociando phone={phone_str} a sesión de VIDEO "
            f"(se precrean FIFOs 1..{MAX_LOGICAL_CHANNEL})"
        )

        for ch in CHANNELS_TO_REQUEST:
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

    # ---------- parser de paquetes JT/T 1078 en el socket de VIDEO ----------

    def feed_jt1078(self, chunk: bytes):
        """
        Acumula datos del socket de video (puerto 7201), extrae paquetes JT/T 1078
        y de cada paquete entrega SOLO el cuerpo H.264 al canal correspondiente.
        """
        global CURRENT_PHONE

        # Loguear solo el primer chunk que entra por 7201
        if not self.first_video_chunk_logged:
            self.first_video_chunk_logged = True
            logger.info(
                f"[VID-RAW] Primer chunk recibido en 7201 len={len(chunk)} "
                f"hex={chunk[:64].hex()}"
            )

        self.jt1078_buf += chunk

        while True:
            buf = self.jt1078_buf

            # Necesitamos al menos la magic
            if len(buf) < 4:
                return

            if buf[0:4] != JT1078_MAGIC:
                # No empieza por magic, intentar resync
                idx = buf.find(JT1078_MAGIC, 1)
                if idx == -1:
                    # conserva solo los últimos 3 bytes por si la magic cae cortada ahí
                    logger.warning(
                        f"[JT1078] No se encontró magic en {len(buf)} bytes, "
                        f"descartando todo menos últimos 3."
                    )
                    self.jt1078_buf = buf[-3:]
                    return
                else:
                    logger.warning(
                        f"[JT1078] Basura antes de magic, descartando {idx} bytes."
                    )
                    self.jt1078_buf = buf[idx:]
                    buf = self.jt1078_buf

            # Header mínimo
            if len(buf) < JT1078_HEADER_MIN:
                return

            # data_type (alto nibble) + subpackage (bajo nibble) en offset 15
            data_type_and_sub = buf[15]
            data_type = (data_type_and_sub & 0xF0) >> 4      # 0=I,1=P,2=B,3=audio,4=data...
            sub_flag = data_type_and_sub & 0x0F              # 0=sin subpaquete, 1=first,2=last,3=middle

            # Longitud del cuerpo (message body length) en offset 28-29
            body_len = int.from_bytes(buf[28:30], "big", signed=False)
            total_len = JT1078_HEADER_MIN + body_len

            if len(buf) < total_len:
                # paquete incompleto todavía
                return

            # Canal lógico (offset aproximado, ver LOGICAL_CHANNEL_OFFSET)
            logical_channel = buf[LOGICAL_CHANNEL_OFFSET]

            body = buf[30:total_len]

            # Avanzar buffer
            self.jt1078_buf = buf[total_len:]
            self.jt1078_packet_count += 1

            if self.jt1078_packet_count <= 5:
                logger.info(
                    f"[JT1078] pkt#{self.jt1078_packet_count} "
                    f"ch={logical_channel} data_type={data_type} "
                    f"sub_flag={sub_flag} body_len={body_len}"
                )

            # Solo nos interesan frames de video (I/P/B)
            if data_type in (0, 1, 2):
                # Aseguramos phone y FIFOs
                if self.phone_str is None:
                    if CURRENT_PHONE:
                        self.ensure_phone_and_pipes(CURRENT_PHONE)
                    else:
                        # Aún no sabemos phone, no sabemos nombre de FIFO -> descartamos
                        continue

                # Obtenemos/creamos estado H264 para este canal
                ch_state = self.channels.get(logical_channel)
                if ch_state is None:
                    ch_state = H264ChannelState(self.phone_str, logical_channel)
                    self.channels[logical_channel] = ch_state

                # Mandamos el cuerpo H.264 a ese canal
                ch_state.feed_h264(body)
            else:
                # audio u otros -> por ahora ignoramos
                if self.jt1078_packet_count <= 5:
                    logger.info(
                        f"[JT1078] pkt#{self.jt1078_packet_count} tipo no-video "
                        f"(data_type={data_type}), ignorado."
                    )
                continue


# ========== Comandos de inicio de video (para TODOS los canales 1..8) ==========

async def start_video_if_needed(session: SessionState, hdr, writer):
    if session.video_started:
        return

    session.video_started = True

    for ch in CHANNELS_TO_REQUEST:
        # 0x9101 - avisar IP/puerto y canal lógico
        pkt_9101 = build_0x9101(
            hdr["phone_bcd"],
            session.next_flow(),
            ip=VIDEO_TARGET_IP,
            tcp_port=VIDEO_TCP_PORT,
            udp_port=VIDEO_UDP_PORT,
            logical_channel=ch,
            data_type=VIDEO_DATA_TYPE,
            frame_type=VIDEO_FRAME_TYPE,
        )
        logger.info(
            f"[TX] phone={hdr['phone_str']} msgId=0x9101 "
            f"(StartAV ch={ch} -> {VIDEO_TARGET_IP}:{VIDEO_TCP_PORT})"
        )
        writer.write(pkt_9101)
        await writer.drain()

        # 0x9102 - control start para ese canal
        pkt_9102 = build_0x9102(
            hdr["phone_bcd"],
            session.next_flow(),
            logical_channel=ch,
            control_cmd=1,
            close_av_type=0,
            switch_stream_type=VIDEO_FRAME_TYPE,
        )
        logger.info(
            f"[TX] phone={hdr['phone_str']} msgId=0x9102 "
            f"(AVControl START ch={ch})"
        )
        writer.write(pkt_9102)
        await writer.drain()

    logger.info(
        f"[VIDEO] Se enviaron comandos 0x9101/0x9102 para canales "
        f"{CHANNELS_TO_REQUEST} del dispositivo {hdr['phone_str']}. "
        f"Si algún canal no existe en el DVR, simplemente no enviará video."
    )


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
                                f"enviando 0x9101/0x9102 para iniciar stream "
                                f"en canales {CHANNELS_TO_REQUEST}"
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

        # En CONTROL ya no hay pipes H264 que cerrar
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

    # Si ya conocemos el phone por el puerto de control, precreamos FIFOs
    if CURRENT_PHONE:
        session.ensure_phone_and_pipes(CURRENT_PHONE)
    else:
        logger.warning(
            "[VID] CURRENT_PHONE aún es None, se crearán FIFOs "
            "cuando se conozca el phone en esta sesión."
        )

    try:
        while not reader.at_eof():
            chunk = await reader.read(4096)
            if not chunk:
                break

            # Si se conoce phone pero aún no se inicializó para esta sesión
            if not session.phone_str and CURRENT_PHONE:
                session.ensure_phone_and_pipes(CURRENT_PHONE)

            # Mandamos todos los bytes al parser JT/T 1078,
            # que a su vez reparte por canal
            session.feed_jt1078(chunk)

    except Exception as e:
        logger.exception(f"[VID] Error en conexión de video {peer}: {e}")
    finally:
        # Cerrar todos los FIFOs de canales usados en esta sesión
        try:
            for ch, ch_state in session.channels.items():
                ch_state.close()
                logger.info(
                    f"[VID] Canal ch={ch} para phone={session.phone_str} cerrado."
                )
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

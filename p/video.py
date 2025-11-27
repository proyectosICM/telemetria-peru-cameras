#!/usr/bin/env python3
"""
video.py - Servidor TCP "video service" en puerto 7200 que habla JT/T 808 mínimo

Hace esto:
  - Acepta conexiones TCP en 0.0.0.0:7200
  - Parsear frames JT808 (0x7E ... 0x7E)
  - Manejar:
      * Registro (0x0100) -> responde 0x8100 (registro OK)
      * Auth (0x0102)     -> responde 0x8001 (ACK OK) y envía 0x9101 + 0x9102
      * Heartbeat (0x0002)-> responde 0x8001 (ACK OK)
      * Posición (0x0200) -> log + 0x8001 (ACK OK)
  - Envía 0x9101 + 0x9102 por la MISMA conexión/puerto 7200 para pedir video
  - Loguea TODO en hex (logger normal + logger.raw)
  - Guarda TODO el stream crudo (login + video) en archivo por conexión
  - Además, extrae el H.264 (Annex B) del stream y lo envía a un FIFO:
        /tmp/<phone>_<canal>.h264
    y lanza automáticamente un ffmpeg que lo transforma a HLS:
        /var/www/video/<phone>_<canal>.m3u8
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
PORT = 7200

ALWAYS_ACK_UNKNOWN = True  # responde 0x8001 a mensajes no manejados

# ========== Config de video / AV (JT/T 1078) ==========
# Le pedimos al terminal que envíe el video a ESTA IP/puerto.
VIDEO_TARGET_IP = "38.43.134.172"  # tu IP pública
VIDEO_TCP_PORT = 7200              # mismo puerto 7200
VIDEO_UDP_PORT = 7200              # si usa UDP, también 7200
VIDEO_CHANNEL = 1                  # canal lógico por defecto que usaremos
VIDEO_DATA_TYPE = 1                # 0=a+v, 1=solo video
VIDEO_FRAME_TYPE = 0               # 0=main, 1=sub

# Directorio base para los FIFOs de video
H264_PIPE_DIR = "/tmp"

# Directorio donde se escribirán los .m3u8 y segmentos HLS
HLS_OUTPUT_DIR = "/var/www/video"
FFMPEG_BIN = "/usr/bin/ffmpeg"  # ajusta si tu ffmpeg está en otra ruta

# Un ffmpeg por phone+canal
# key: f"{phone}_{canal}" -> subprocess.Popen
FFMPEG_PROCS = {}

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

# ========== Cache de phone por IP ==========
# Idea: en la conexión "de señal" (donde llegan 0x0100 / 0x0102) aprendemos
# que la IP X corresponde al phone Y (p.ej., 000012345678).
# Luego, cualquier otra conexión desde esa IP usará ese mismo phone Y
# para nombrar FIFOs, en lugar de interpretaciones raras de headers basura.
LAST_PHONE_BY_IP = {}


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


# ========== Comandos de video JT/T 1078 (0x9101 / 0x9102) ==========
def build_0x9101(
    phone_bcd: bytes,
    flow_id_platform: bytes,
    ip: str,
    tcp_port: int,
    udp_port: int,
    logical_channel: int,
    data_type: int = 1,   # 0=a+v, 1=solo video
    frame_type: int = 0,  # 0=main, 1=sub
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
    b"\x02\x00": handle_0200_position,
}


# ========== Lanzar ffmpeg -> HLS por teléfono/canal ==========
def start_hls_for_phone(phone_str: str, channel: int = VIDEO_CHANNEL):
    """
    Lanza (si no está ya lanzado) un ffmpeg que lee del FIFO /tmp/<phone>_<ch>.h264
    y genera HLS en /var/www/video/<phone>_<ch>.m3u8
    """
    key = f"{phone_str}_{channel}"

    # Si ya tenemos un ffmpeg vivo para este phone/canal, no hacemos nada
    proc = FFMPEG_PROCS.get(key)
    if proc is not None and proc.poll() is None:
        return

    fifo_path = os.path.join(H264_PIPE_DIR, f"{phone_str}_{channel}.h264")
    m3u8_path = os.path.join(HLS_OUTPUT_DIR, f"{phone_str}_{channel}.m3u8")

    # Asegurarnos de que existe el directorio HLS
    try:
        os.makedirs(HLS_OUTPUT_DIR, exist_ok=True)
    except Exception as e:
        logger.warning(f"[HLS] No se pudo crear {HLS_OUTPUT_DIR}: {e}")
        return

    cmd = [
        FFMPEG_BIN,
        "-loglevel", "info",
        "-re",
        "-i", fifo_path,
        "-c:v", "copy",
        "-f", "hls",
        "-hls_time", "2",
        "-hls_list_size", "5",
        "-hls_flags", "delete_segments",
        m3u8_path,
    ]

    try:
        proc = subprocess.Popen(cmd)
        FFMPEG_PROCS[key] = proc
        logger.info(
            f"[HLS] Lanzado ffmpeg para phone={phone_str} ch={channel}: "
            f"{' '.join(cmd)}"
        )
    except Exception as e:
        logger.warning(f"[HLS] No se pudo lanzar ffmpeg para {key}: {e}")


# ========== Estado de sesión ==========
class SessionState:
    def __init__(self):
        self.flow = Flow()
        self.video_started = False  # para no mandar 9101/9102 más de una vez

        # Datos para H.264 -> FIFO
        self.phone_str = None
        self.pipe_path = None
        self.h264_started = False       # ya encontré el primer SPS (00 00 01 67)
        self.h264_pipe = None
        self.h264_pipe_failed = False   # si falla escribir, no reintentar en bucle
        self._tail3 = b""               # últimas 3 bytes para capturar patrones en bordes

    def next_flow(self) -> bytes:
        return self.flow.next()

    # --- manejo de FIFOs por dispositivo ---
    def ensure_phone_and_pipes(self, phone_str: str):
        """
        Se llama cuando ya conocemos el phone_str del terminal.
        Crea los FIFOs /tmp/<phone>_1.h264 ... /tmp/<phone>_8.h264 solo una vez.
        """
        if self.phone_str is not None:
            return  # ya inicializado

        self.phone_str = phone_str
        logger.info(f"[H264] Inicializando FIFOs para phone={phone_str}")

        # Crear 8 canales
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

        # Usamos por ahora un solo canal de video (VIDEO_CHANNEL)
        self.pipe_path = os.path.join(
            H264_PIPE_DIR, f"{phone_str}_{VIDEO_CHANNEL}.h264"
        )
        logger.info(f"[H264] Canal de video principal: {self.pipe_path}")

        # Lanzar ffmpeg -> HLS para este phone/canal (si no está ya corriendo)
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
        """
        Abre el FIFO H.264 si aún no está abierto.
        No hace nada si aún no tenemos phone_str/pipe_path
        o si ya marcamos h264_pipe_failed.
        """
        if self.h264_pipe_failed:
            return None
        if self.pipe_path is None:
            return None

        if self.h264_pipe is None:
            try:
                # Ojo: esto puede bloquear si no hay lector (ffmpeg)
                self.h264_pipe = open(self.pipe_path, "wb", buffering=0)
                logger.info(f"[H264] FIFO abierto para escritura: {self.pipe_path}")
            except Exception as e:
                logger.warning(f"[H264] No se pudo abrir FIFO {self.pipe_path}: {e}")
                self.h264_pipe_failed = True
                self.h264_pipe = None
        return self.h264_pipe

    def feed_h264(self, chunk: bytes):
        """
        Busca el primer 00 00 01 67 (SPS de H.264) en el stream
        y a partir de ahí manda todo al FIFO como elementary stream H.264 Annex B.

        IMPORTANTE:
        - No interpreta JT1078 todavía, solo busca el patrón H.264 en bruto.
        - Asume que el MDVR está mandando H.264 dentro del stream.
        - Si aún no tenemos phone_str/pipe_path, no hace nada.
        """
        if self.pipe_path is None or self.h264_pipe_failed:
            return

        data = self._tail3 + chunk

        try:
            # Si aún no encontramos el primer SPS, lo buscamos
            if not self.h264_started:
                idx = data.find(b"\x00\x00\x01\x67")
                if idx != -1:
                    self.h264_started = True
                    pipe = self.ensure_h264_pipe()
                    if pipe is not None:
                        pipe.write(data[idx:])
            else:
                # Ya estamos en modo “H.264 streaming”: mandar chunk tal cual
                pipe = self.ensure_h264_pipe()
                if pipe is not None:
                    pipe.write(chunk)
        except BrokenPipeError as e:
            logger.warning(
                f"[H264] Error Broken pipe en FIFO {self.pipe_path}: {e}"
            )
            self._disable_h264_pipe()
        except Exception as e:
            logger.warning(f"[H264] Error escribiendo en FIFO {self.pipe_path}: {e}")

        # Guardar últimas 3 bytes para concatenarlas con el siguiente chunk
        if len(data) >= 3:
            self._tail3 = data[-3:]
        else:
            self._tail3 = data

    # --- fin manejo FIFOs ---


async def start_video_if_needed(session: SessionState, hdr, writer):
    """
    Envía 0x9101 + 0x9102 por la MISMA conexión/puerto 7200.
    No abre otro socket, no redirige nada en Python.
    Solo le dice al terminal que mande su stream a VIDEO_TARGET_IP:7200.
    """
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


# ========== Loop por conexión TCP ==========
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    # Activar TCP keepalive
    sock = writer.get_extra_info("socket")
    if isinstance(sock, socket.socket):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

    peer = writer.get_extra_info("peername")
    logger.info(f"[CONN] Nueva conexión en puerto {PORT} desde {peer}")
    session = SessionState()
    buf = b""

    # dump de stream CRUDO por conexión (todo, incluido video)
    dump_filename = f"video808_raw_{peer[0]}_{peer[1]}.bin".replace(":", "_")
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

            # Guardar TODO el stream crudo (login + data + video)
            if dump_file is not None:
                try:
                    dump_file.write(chunk)
                    dump_file.flush()
                except Exception as e:
                    logger.warning(f"[FILE] Error escribiendo en {dump_filename}: {e}")

            # OJO: NO llamamos feed_h264 aquí hasta conocer el phone_str
            buf += chunk

            # buscar frames 0x7E ... 0x7E (solo para JT808)
            while True:
                s = buf.find(START_END)
                if s == -1:
                    break
                e = buf.find(START_END, s + 1)
                if e == -1:
                    break

                frame = buf[s + 1: e]  # sin 0x7E
                buf = buf[e + 1:]

                try:
                    payload = de_escape(frame)
                    if len(payload) < 13:
                        continue

                    # Checksum: si falla, no spameamos WARNING, solo ignoramos
                    calc = checksum(payload[:-1])
                    if calc != payload[-1]:
                        # logger.debug("[CHK] Checksum inválido, descartando frame")
                        continue

                    hdr = parse_header(payload[:-1])

                    # --- Asignar phone a la sesión usando cache por IP ---
                    peer_ip = None
                    if isinstance(peer, tuple) and len(peer) >= 1:
                        peer_ip = peer[0]

                    # Si este mensaje es un REGISTRO o AUTH real, aprendemos el phone para esa IP
                    if hdr["msg_id"] in (b"\x01\x00", b"\x01\x02") and peer_ip:
                        LAST_PHONE_BY_IP[peer_ip] = hdr["phone_str"]
                        logger.info(
                            f"[PHONE] Aprendido phone={hdr['phone_str']} para IP={peer_ip}"
                        )

                    # Si la sesión aún no tiene phone, pero ya tenemos uno cacheado para la IP,
                    # inicializamos los FIFOs con ese phone (p.ej. 000012345678)
                    if session.phone_str is None and peer_ip and peer_ip in LAST_PHONE_BY_IP:
                        session.ensure_phone_and_pipes(LAST_PHONE_BY_IP[peer_ip])

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

                        # Después de AUTH (0x0102), pedimos video 1 sola vez
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

            # Ahora que probablemente ya tenemos phone_str/pipe_path,
            # alimentamos el extractor H.264 con el chunk crudo
            try:
                session.feed_h264(chunk)
            except Exception as e:
                logger.warning(f"[H264] Error en feed_h264: {e}")

    except Exception as e:
        logger.exception(f"[ERR] Error en conexión {peer}: {e}")
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
        logger.info(f"[CONN] Conexión cerrada {peer}")


# ========== main: servidor TCP 7200 ==========
async def main():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info(f"[MAIN] Servidor video808 (JT808 mínimo) escuchando en {addr}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[MAIN] Servidor detenido por teclado")

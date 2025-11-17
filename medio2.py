#!/usr/bin/env python3
# jt1078_media_server.py

import asyncio
import os
import logging
import signal
import pathlib
import subprocess
import binascii
import threading
import sys
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

LOG = logging.getLogger("jt1078")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MEDIA_ROOT = pathlib.Path("./www")      # aquí quedarán los .m3u8 y .ts por SIM_CANAL/
PIPE_ROOT  = pathlib.Path("./pipes")    # named pipes para ffmpeg
MEDIA_ROOT.mkdir(parents=True, exist_ok=True)
PIPE_ROOT.mkdir(parents=True, exist_ok=True)

# Ruta al binario de ffmpeg (puedes sobreescribirla con la variable de entorno FFMPEG_BIN)
FFMPEG_BIN = os.getenv("FFMPEG_BIN", "/usr/bin/ffmpeg")

# Puertos configurables
MEDIA_UDP_PORT  = 7200   # donde el MDVR puede enviar paquetes JT1078 (UDP)
MEDIA_TCP_PORT  = 7200   # donde el MDVR puede enviar paquetes JT1078 (TCP)
MEDIA_HTTP_PORT = 2000   # donde exponemos HLS (HTTP)

# Data types JT1078 (nibble alto de typ_sub)
# Muchos vendors usan:
# 0 = I-frame vídeo
# 1 = P-frame vídeo
# 2 = audio
# 3,4,... = otros tipos de vídeo / metadata
# Para no perder SPS/PPS, aceptamos todo menos audio.
def is_video_datatype(dt: int) -> bool:
    return dt != 2  # sólo excluir audio


# --- Cabecera 1078 (tabla 19): magic 0x30 0x31 0x63 0x64; luego campos tipo RTP+extras
# [0:4]  magic
# [4]    V/P/X/CC
# [5]    M/PT
# [6:8]  SN (WORD)
# [8:14] SIM (BCD[6])
# [14]   logical_channel (BYTE)
# [15]   nibble alto: data_type (I/P/B/Audio/TransData); nibble bajo: subpkg (first/last/mid/original)
# ... (campos opcionales) ... | bodyLen(2) | body[n]


def bcd6_to_str(b: bytes) -> str:
    out = []
    for x in b:
        out.append(f"{(x >> 4) & 0xF}{x & 0xF}")
    return "".join(out)


class StreamProc:
    """ Gestiona un ffmpeg por clave (sim,chan) con input por pipe """
    def __init__(self, key: str):
        self.key = key
        self.pipe_path = PIPE_ROOT / f"{key}.ps.pipe"
        self.out_dir   = MEDIA_ROOT / key
        self.ff = None

    def ensure(self):
        # Crear carpeta de salida y pipe si no existen
        self.out_dir.mkdir(parents=True, exist_ok=True)
        if not self.pipe_path.exists():
            try:
                os.mkfifo(self.pipe_path)
                LOG.info(f"[{self.key}] Creado named pipe {self.pipe_path}")
            except FileExistsError:
                pass

        # Levantar ffmpeg si no está corriendo
        if self.ff is None or self.ff.poll() is not None:
            cmd = [
                FFMPEG_BIN,
                "-hide_banner", "-loglevel", "warning",
                "-nostats",
                "-fflags", "nobuffer",
                "-thread_queue_size", "512",

                # Darle más margen para detectar el stream
                "-probesize", "5000000",
                "-analyzeduration", "5000000",

                # La entrada es H.264 crudo
                "-f", "h264",
                "-i", str(self.pipe_path),

                # Sólo vídeo
                "-map", "0:v:0?",
                "-c:v", "copy",

                "-f", "hls",
                "-hls_time", "2",
                "-hls_list_size", "10",
                "-hls_flags", "delete_segments+split_by_time",
                "-master_pl_name", "master.m3u8",
                str(self.out_dir / "index.m3u8"),
            ]
            LOG.info(f"[{self.key}] starting ffmpeg: {' '.join(cmd)}")
            try:
                self.ff = subprocess.Popen(cmd)
            except FileNotFoundError as e:
                LOG.error(f"[{self.key}] No se encontró ffmpeg en '{FFMPEG_BIN}': {e}")
                self.ff = None
            except Exception as e:
                LOG.exception(f"[{self.key}] Error lanzando ffmpeg: {e}")
                self.ff = None

    def write(self, data: bytes):
        self.ensure()
        if self.ff is None:
            # Si ffmpeg no levantó, no tiene sentido escribir en la pipe
            return
        # abrir en modo sin buffer para named pipe
        with open(self.pipe_path, "ab", buffering=0) as f:
            f.write(data)


class Reassembler:
    """ Ensambla por subpaquetes (first/mid/last). Si no hay subpack, pasa directo. """
    def __init__(self):
        self.buffers = {}  # key -> bytearray

    def feed(self, key: str, subflag: int, payload: bytes):
        # subflag: 0=original, 1=first, 2=last, 3=middle
        if subflag == 0:
            return payload
        buf = self.buffers.setdefault(key, bytearray())
        if subflag == 1:     # first
            buf.clear()
            buf += payload
            return None
        elif subflag == 3:   # middle
            buf += payload
            return None
        elif subflag == 2:   # last
            buf += payload
            out = bytes(buf)
            buf.clear()
            return out
        else:
            return payload


class JT1078Handler:
    """
    Lógica común de parseo JT1078.
    La usan tanto el listener UDP como el server TCP.
    """
    def __init__(self):
        self.streams = {}       # key -> StreamProc
        self.reasm   = Reassembler()

    def process_packet(self, data: bytes, addr):
        try:
            if len(data) < 32:
                # demasiado corto para ser 1078
                return

            # Log mínimo del encabezado para depuración
            head_hex = binascii.hexlify(data[:16]).decode()
            LOG.debug(f"pkt from {addr}, len={len(data)}, head={head_hex}")

            # magic 0x30 0x31 0x63 0x64
            if data[0:4] != b"\x30\x31\x63\x64":
                # no parece 1078, lo ignoramos
                return

            sim_bcd = data[8:14]
            sim = bcd6_to_str(sim_bcd)
            chan = data[14]
            typ_sub = data[15]
            data_type = (typ_sub >> 4) & 0x0F
            subflag   = typ_sub & 0x0F

            # 🔹 Sólo ignorar audio (data_type == 2). Todo lo demás lo tratamos como vídeo/útil.
            if not is_video_datatype(data_type):
                # LOG.debug(f"[{sim}_{chan}] paquete audio data_type={data_type}, ignorado")
                return

            # Heurística para hallar body (payload H.264)
            body = None
            for body_len_off in (28, 30):
                if len(data) >= body_len_off + 2:
                    body_len = int.from_bytes(data[body_len_off:body_len_off+2], 'big')
                    body_off = body_len_off + 2
                    if len(data) >= body_off + body_len and body_len > 0:
                        body = data[body_off:body_off+body_len]
                        break
            if body is None:
                # fallback grosero
                body = data[30:]

            key = f"{sim}_{chan}"
            out = self.reasm.feed(key, subflag, body)
            if out:
                sp = self.streams.get(key)
                if sp is None:
                    sp = self.streams.setdefault(key, StreamProc(key))
                sp.write(out)

                # Log sencillo si es I-frame (data_type==0)
                if data_type == 0x0:
                    LOG.info(f"[{key}] I-frame ({len(out)} B) from {addr}")

        except Exception as e:
            LOG.exception(f"Error parseando 1078 pkt de {addr}: {e}")


class JT1078UDP(asyncio.DatagramProtocol):
    """ Listener UDP JT1078 que delega en JT1078Handler """
    def __init__(self, handler: JT1078Handler):
        super().__init__()
        self.handler = handler

    def connection_made(self, transport):
        self.transport = transport
        addr = transport.get_extra_info('sockname')
        LOG.info(f"JT1078 UDP escuchando en {addr}")

    def datagram_received(self, data, addr):
        self.handler.process_packet(data, addr)


class JT1078TCPServer:
    """ Server TCP JT1078 que delega en JT1078Handler """
    def __init__(self, handler: JT1078Handler):
        self.handler = handler

    async def handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        LOG.info(f"JT1078 TCP conexión desde {addr}")
        try:
            while True:
                data = await reader.read(65535)
                if not data:
                    break
                self.handler.process_packet(data, addr)
        except Exception as e:
            LOG.exception(f"Error en conexión JT1078 TCP {addr}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            LOG.info(f"JT1078 TCP conexión cerrada {addr}")


# ---------- HTTP embebido "silencioso" ----------
class QuietHTTPServer(ThreadingHTTPServer):
    # Evita tracebacks por clientes que cortan (Reset/Broken pipe/Timeout)
    def handle_error(self, request, client_address):
        exc_type, exc, tb = sys.exc_info()
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, TimeoutError)):
            LOG.info(f"HTTP peer closed/reset: {client_address}")
            return
        return super().handle_error(request, client_address)


class RootedHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(MEDIA_ROOT.resolve()), **kwargs)

    # Baja el ruido de logs
    def log_message(self, format, *args):
        try:
            code = int(args[1])
        except Exception:
            code = None
        msg = "%s - - [%s] %s" % (
            self.address_string(),
            self.log_date_time_string(),
            format % args,
        )
        if code in (200, 206, 304, 404):
            LOG.info(msg)
        else:
            LOG.warning(msg)


def start_http_server():
    httpd = QuietHTTPServer(("0.0.0.0", MEDIA_HTTP_PORT), RootedHandler)
    httpd.daemon_threads = True
    LOG.info(f"HTTP sirviendo HLS en http://0.0.0.0:{MEDIA_HTTP_PORT}/")
    httpd.serve_forever()


# --------------- main ----------------
async def main():
    # 1) Levanta HTTP en hilo
    t = threading.Thread(target=start_http_server, daemon=True)
    t.start()

    loop = asyncio.get_running_loop()
    handler = JT1078Handler()

    # 2) UDP para recibir video (por si el MDVR usa UDP)
    transport_udp, protocol_udp = await loop.create_datagram_endpoint(
        lambda: JT1078UDP(handler),
        local_addr=("0.0.0.0", MEDIA_UDP_PORT),
        reuse_port=True,
    )

    # 3) TCP para recibir video (lo que tu equipo probablemente está usando)
    tcp_server = JT1078TCPServer(handler)
    server_tcp = await asyncio.start_server(
        tcp_server.handle_conn,
        "0.0.0.0",
        MEDIA_TCP_PORT,
    )
    tcp_addrs = ", ".join(str(s.getsockname()) for s in server_tcp.sockets)
    LOG.info(f"JT1078 TCP escuchando en {tcp_addrs}")

    LOG.info("Servidor de medios listo. Presiona Ctrl+C para detener.")
    LOG.info(
        f"Ejemplo de URL por canal: "
        f"http://telemetriaperu.com:{MEDIA_HTTP_PORT}/000012345678_1/index.m3u8"
    )

    try:
        # Tarea que nunca termina, hasta que el loop se cancele (Ctrl+C)
        await asyncio.Future()
    finally:
        LOG.info("Cerrando sockets JT1078...")
        transport_udp.close()
        server_tcp.close()
        await server_tcp.wait_closed()
        LOG.info("Servidor de medios cerrado.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        LOG.info("Servidor detenido por teclado (Ctrl+C)")

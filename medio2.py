#!/usr/bin/env python3
# jt1078_media_server.py

import asyncio
import os
import logging
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

# Offsets según documentación JT1078
DATA_BODY_LEN_OFFSET = 28   # 2 bytes
DATA_BODY_OFFSET     = 30   # inicio del body

# Data types JT1078 (nibble alto de typ_sub)
# 0 = I-frame vídeo
# 1 = P-frame vídeo
# 2 = audio
# 3,4,... = otros tipos de vídeo / metadata
def is_video_datatype(dt: int) -> bool:
    # sólo excluir audio
    return dt != 2


def bcd6_to_str(b: bytes) -> str:
    out = []
    for x in b:
        out.append(f"{(x >> 4) & 0xF}{x & 0xF}")
    return "".join(out)


def extract_h264_frame(payload: bytes) -> bytes | None:
    """
    Busca el primer start code H.264 dentro del payload (0x00000001 o 0x000001)
    y devuelve desde ahí. Si no encuentra ninguno, devuelve None.
    Esto limpia la cabecera propia de JT1078 y deja solo H.264 Annex-B.
    """
    if not payload:
        return None

    idx = payload.find(b"\x00\x00\x00\x01")
    if idx == -1:
        idx = payload.find(b"\x00\x00\x01")

    if idx == -1:
        # No hay start code, este frame está contaminado o incompleto
        return None

    return payload[idx:]


class StreamProc:
    """
    Gestiona un ffmpeg por clave (sim,chan) con input por pipe.

    IMPORTANTE:
    - Mantiene la FIFO ABIERTA (self.fh) mientras ffmpeg esté vivo.
    - No abrimos/cerramos por cada frame, porque eso mata ffmpeg (EOF).
    """
    def __init__(self, key: str):
        self.key = key
        self.pipe_path = PIPE_ROOT / f"{key}.ps.pipe"
        self.out_dir   = MEDIA_ROOT / key
        self.ff: subprocess.Popen | None = None
        self.fh = None  # file handle del FIFO para escritura

    def _ensure_fifo(self):
        # Crear carpeta de salida
        self.out_dir.mkdir(parents=True, exist_ok=True)

        # Crear FIFO si no existe
        if not self.pipe_path.exists():
            try:
                os.mkfifo(self.pipe_path)
                LOG.info(f"[{self.key}] Creado named pipe {self.pipe_path}")
            except FileExistsError:
                pass

    def _ensure_ffmpeg(self):
        # Levantar ffmpeg si no está corriendo
        if self.ff is None or self.ff.poll() is not None:
            cmd = [
                FFMPEG_BIN,
                "-hide_banner", "-loglevel", "info",
                "-nostats",
                "-fflags", "nobuffer",
                "-thread_queue_size", "512",

                "-probesize", "5000000",
                "-analyzeduration", "5000000",

                # Forzamos formato de entrada como H.264 crudo
                "-f", "h264",
                "-i", str(self.pipe_path),

                # Sólo vídeo
                "-map", "0:v:0?",
                "-an",
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

    def _ensure_writer(self):
        # Abrir la FIFO para escritura y mantenerla abierta
        if self.fh is None or self.fh.closed:
            try:
                # 'wb' en vez de 'ab', sin buffer
                self.fh = open(self.pipe_path, "wb", buffering=0)
                LOG.info(f"[{self.key}] FIFO abierta para escritura")
            except FileNotFoundError:
                # Si por alguna razón aún no existe, recrear y reintentar
                self._ensure_fifo()
                self.fh = open(self.pipe_path, "wb", buffering=0)
                LOG.info(f"[{self.key}] FIFO re-creada y abierta para escritura")

    def ensure(self):
        # Orden: FIFO -> ffmpeg -> writer
        self._ensure_fifo()
        self._ensure_ffmpeg()
        if self.ff is not None:
            self._ensure_writer()

    def write(self, data: bytes):
        # Asegurar todo antes de escribir
        self.ensure()
        if self.ff is None or self.fh is None:
            return

        try:
            self.fh.write(data)
        except BrokenPipeError:
            LOG.error(f"[{self.key}] Broken pipe escribiendo, reiniciando ffmpeg y FIFO")
            # Cerrar writer, matar ffmpeg y recrear en siguiente frame
            try:
                if self.fh and not self.fh.closed:
                    self.fh.close()
            except Exception:
                pass
            self.fh = None

            if self.ff is not None:
                try:
                    self.ff.kill()
                except Exception:
                    pass
            self.ff = None


class Reassembler:
    """
    Ensambla por subpaquetes (first/mid/last) según la spec:

      subflag (SubpackageType):
        0 = paquete completo (no fragmentado)
        1 = primer subpaquete
        2 = subpaquete intermedio
        3 = último subpaquete
    """
    def __init__(self):
        self.buffers = {}  # key -> bytearray

    def feed(self, key: str, subflag: int, payload: bytes):
        # 0 = paquete completo
        if subflag == 0:
            return payload

        buf = self.buffers.setdefault(key, bytearray())

        if subflag == 1:     # first
            buf.clear()
            buf += payload
            return None
        elif subflag == 2:   # middle
            buf += payload
            return None
        elif subflag == 3:   # last
            buf += payload
            out = bytes(buf)
            buf.clear()
            return out
        else:
            # valor desconocido, devolvemos tal cual
            return payload


class JT1078Handler:
    """
    Lógica común de parseo JT1078.
    La usan tanto el listener UDP como el server TCP.
    """
    def __init__(self):
        self.streams = {}       # key -> StreamProc
        self.reasm   = Reassembler()
        self.dumped_debug = set()  # para volcar un frame de depuración opcional

    def process_packet(self, data: bytes, addr):
        try:
            if len(data) < DATA_BODY_OFFSET:
                return

            head_hex = binascii.hexlify(data[:16]).decode()
            LOG.debug(f"pkt from {addr}, len={len(data)}, head={head_hex}")

            # magic 0x30 0x31 0x63 0x64
            if data[0:4] != b"\x30\x31\x63\x64":
                return

            sim_bcd = data[8:14]
            sim = bcd6_to_str(sim_bcd)
            chan = data[14]
            typ_sub = data[15]
            data_type = (typ_sub >> 4) & 0x0F
            subflag   = typ_sub & 0x0F

            # ignorar audio
            if not is_video_datatype(data_type):
                return

            if len(data) < DATA_BODY_LEN_OFFSET + 2:
                return

            body_len = int.from_bytes(
                data[DATA_BODY_LEN_OFFSET:DATA_BODY_LEN_OFFSET + 2], "big"
            )
            body_off = DATA_BODY_OFFSET

            if body_len <= 0 or len(data) < body_off + body_len:
                LOG.debug(
                    f"[{sim}_{chan}] body_len inválido ({body_len}) o paquete corto len={len(data)}"
                )
                return

            body = data[body_off:body_off + body_len]

            key = f"{sim}_{chan}"
            out = self.reasm.feed(key, subflag, body)
            if out:
                # Volcar sólo el primer frame reensamblado (para debug offline)
                if key not in self.dumped_debug:
                    debug_path = MEDIA_ROOT / f"debug_{key}.bin"
                    with open(debug_path, "wb") as dbg:
                        dbg.write(out)
                    LOG.info(f"[{key}] Frame de depuración volcado a {debug_path}")
                    self.dumped_debug.add(key)

                # Extraer únicamente la parte H.264 pura (desde el primer start code)
                h264_frame = extract_h264_frame(out)
                if not h264_frame:
                    LOG.debug(f"[{key}] frame sin start code válido, len={len(out)} -> descartado")
                    return

                sp = self.streams.get(key)
                if sp is None:
                    sp = self.streams.setdefault(key, StreamProc(key))
                sp.write(h264_frame)

                if data_type == 0x0:
                    LOG.info(f"[{key}] I-frame ({len(h264_frame)} B) from {addr}")

        except Exception as e:
            LOG.exception(f"Error parseando 1078 pkt de {addr}: {e}")


class JT1078UDP(asyncio.DatagramProtocol):
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
    def handle_error(self, request, client_address):
        exc_type, exc, tb = sys.exc_info()
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, TimeoutError)):
            LOG.info(f"HTTP peer closed/reset: {client_address}")
            return
        return super().handle_error(request, client_address)


class RootedHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(MEDIA_ROOT.resolve()), **kwargs)

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

    # 2) UDP por si acaso
    transport_udp, protocol_udp = await loop.create_datagram_endpoint(
        lambda: JT1078UDP(handler),
        local_addr=("0.0.0.0", MEDIA_UDP_PORT),
        reuse_port=True,
    )

    # 3) TCP
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

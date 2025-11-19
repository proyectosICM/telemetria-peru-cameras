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
import shutil
import argparse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

LOG = logging.getLogger("jt1078")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Rutas base
MEDIA_ROOT = pathlib.Path("./www")      # .m3u8 y .ts por SIM_CANAL/
PIPE_ROOT  = pathlib.Path("./pipes")    # named pipes para ffmpeg
RAW_ROOT   = pathlib.Path("./raw")      # dumps crudos / payloads

# Offsets JT1078
DATA_BODY_LEN_OFFSET = 28
DATA_BODY_OFFSET     = 30

FFMPEG_BIN = os.getenv("FFMPEG_BIN", "/usr/bin/ffmpeg")

MEDIA_UDP_PORT  = 7200
MEDIA_TCP_PORT  = 7200
MEDIA_HTTP_PORT = 2000


# ----------------- utilidades comunes -----------------

def bcd6_to_str(b: bytes) -> str:
    out = []
    for x in b:
        out.append(f"{(x >> 4) & 0xF}{x & 0xF}")
    return "".join(out)


def clean_start():
    """
    Limpia pipes/, www/ y raw/ al arrancar el SERVIDOR.
    (NO se usa en modo --scan.)
    """
    # 1) pipes
    if PIPE_ROOT.exists():
        for p in PIPE_ROOT.iterdir():
            try:
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
            except FileNotFoundError:
                pass
            except Exception as e:
                LOG.warning(f"Error limpiando pipe {p}: {e}")

    # 2) HLS viejo
    if MEDIA_ROOT.exists():
        for child in MEDIA_ROOT.iterdir():
            try:
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    if child.suffix in (".m3u8", ".ts"):
                        child.unlink()
            except FileNotFoundError:
                pass
            except Exception as e:
                LOG.warning(f"Error limpiando media {child}: {e}")

    # 3) dumps viejos
    if RAW_ROOT.exists():
        for child in RAW_ROOT.iterdir():
            try:
                if child.is_file():
                    child.unlink()
                else:
                    shutil.rmtree(child)
            except Exception:
                pass

    LOG.info("Limpieza inicial de pipes/, www/ y raw/ completada")


# ----------------- ffmpeg / HLS -----------------

class StreamProc:
    def __init__(self, key: str):
        self.key = key
        self.pipe_path = PIPE_ROOT / f"{key}.ps.pipe"
        self.out_dir   = MEDIA_ROOT / key
        self.ff: subprocess.Popen | None = None
        self.fh = None

    def _ensure_fifo(self):
        self.out_dir.mkdir(parents=True, exist_ok=True)
        if not self.pipe_path.exists():
            try:
                os.mkfifo(self.pipe_path)
                LOG.info(f"[{self.key}] Creado named pipe {self.pipe_path}")
            except FileExistsError:
                pass

    def _ensure_ffmpeg(self):
        if self.ff is None or self.ff.poll() is not None:
            cmd = [
                FFMPEG_BIN,
                "-hide_banner",
                "-loglevel", "warning",
                "-nostats",
                "-fflags", "+genpts+nobuffer",
                "-use_wallclock_as_timestamps", "1",
                "-thread_queue_size", "1024",
                "-probesize", "5000000",
                "-analyzeduration", "5000000",
                "-i", str(self.pipe_path),
                "-map", "0:v:0?",
                "-an",
                "-c:v", "libx264",
                "-preset", "veryfast",
                "-tune", "zerolatency",
                "-g", "50",
                "-keyint_min", "25",
                "-sc_threshold", "0",
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
        if self.fh is None or self.fh.closed:
            try:
                self.fh = open(self.pipe_path, "wb", buffering=0)
                LOG.info(f"[{self.key}] FIFO abierta para escritura")
            except FileNotFoundError:
                self._ensure_fifo()
                self.fh = open(self.pipe_path, "wb", buffering=0)
                LOG.info(f"[{self.key}] FIFO re-creada y abierta para escritura")

    def ensure(self):
        self._ensure_fifo()
        self._ensure_ffmpeg()
        if self.ff is not None:
            self._ensure_writer()

    def write(self, data: bytes):
        self.ensure()
        if self.ff is None or self.fh is None:
            return
        try:
            self.fh.write(data)
        except BrokenPipeError:
            LOG.error(f"[{self.key}] Broken pipe escribiendo, reiniciando ffmpeg y FIFO")
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


# ----------------- reensamblado subpaquetes JT1078 -----------------

class Reassembler:
    def __init__(self):
        self.buffers = {}

    def feed(self, key: str, subflag: int, payload: bytes):
        # 0 = paquete completo
        if subflag == 0:
            return payload
        buf = self.buffers.setdefault(key, bytearray())
        if subflag == 1:
            buf.clear()
            buf += payload
            return None
        elif subflag == 2:
            buf += payload
            return None
        elif subflag == 3:
            buf += payload
            out = bytes(buf)
            buf.clear()
            return out
        else:
            return payload


# ----------------- handler JT1078 (server) -----------------

class JT1078Handler:
    def __init__(self):
        self.streams = {}
        self.reasm   = Reassembler()
        self.dumped_debug = set()
        self.raw_counts = {}  # key -> cuántos paquetes crudos hemos dumpado

    def _dump_raw_packet(self, key: str, data: bytes, body: bytes):
        """
        Guarda los primeros ~50 paquetes crudos + body en raw/ para inspección.
        """
        count = self.raw_counts.get(key, 0)
        if count >= 50:
            return

        RAW_ROOT.mkdir(parents=True, exist_ok=True)

        raw_pkt_path = RAW_ROOT / f"{key}_pkt_{count:04d}.bin"
        raw_body_path = RAW_ROOT / f"{key}_body_{count:04d}.bin"

        try:
            with open(raw_pkt_path, "wb") as f:
                f.write(data)
            with open(raw_body_path, "wb") as f:
                f.write(body)
            LOG.info(
                f"[{key}] dump raw packet #{count} len={len(data)}, "
                f"body_len={len(body)} -> {raw_pkt_path}, {raw_body_path}"
            )
        except Exception as e:
            LOG.warning(f"[{key}] No se pudo dumpear raw packet #{count}: {e}")

        self.raw_counts[key] = count + 1

    def process_packet(self, data: bytes, addr):
        try:
            if len(data) < DATA_BODY_OFFSET:
                return

            # magic 0x30 0x31 0x63 0x64
            if data[0:4] != b"\x30\x31\x63\x64":
                return

            sim_bcd = data[8:14]
            sim = bcd6_to_str(sim_bcd)
            chan = data[14]
            typ_sub = data[15]
            data_type = (typ_sub >> 4) & 0x0F
            subflag   = typ_sub & 0x0F

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

            # dump raw
            self._dump_raw_packet(key, data, body)

            out = self.reasm.feed(key, subflag, body)
            if out:
                # Volcar sólo el primer frame reensamblado completo
                if key not in self.dumped_debug:
                    debug_path = MEDIA_ROOT / f"debug_{key}.bin"
                    with open(debug_path, "wb") as dbg:
                        dbg.write(out)
                    LOG.info(f"[{key}] Frame reensamblado volcado a {debug_path}")
                    self.dumped_debug.add(key)

                sp = self.streams.get(key)
                if sp is None:
                    sp = self.streams.setdefault(key, StreamProc(key))
                sp.write(out)

                if data_type == 0x0:
                    LOG.info(
                        f"[{key}] I-frame chunk ({len(out)} B) "
                        f"subflag={subflag} from {addr}"
                    )

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


# ----------------- HTTP embebido -----------------

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


# ----------------- SCAN SPS/PPS/IDR -----------------

def scan_h264_file(path: pathlib.Path):
    if not path.exists():
        print(f"[SCAN] {path} no existe")
        return

    data = path.read_bytes()
    size = len(data)

    sps = pps = idr = non_idr = 0
    total_nalus = 0

    i = 0
    while i < size - 4:
        # buscar start code 00 00 01 o 00 00 00 01
        if data[i] == 0x00 and data[i+1] == 0x00 and data[i+2] == 0x01:
            start = i
            j = i + 3
        elif data[i] == 0x00 and data[i+1] == 0x00 and data[i+2] == 0x00 and data[i+3] == 0x01:
            start = i
            j = i + 4
        else:
            i += 1
            continue

        if j >= size:
            break

        nal_header = data[j]
        nal_type = nal_header & 0x1F
        total_nalus += 1

        if nal_type == 7:
            sps += 1
        elif nal_type == 8:
            pps += 1
        elif nal_type == 5:
            idr += 1
        elif nal_type == 1:
            non_idr += 1

        # avanzar al siguiente posible start code
        i = j + 1

    print(f"\n[SCAN] {path}")
    print(f"  size bytes : {size}")
    print(f"  NALUs tot  : {total_nalus}")
    print(f"  SPS (7)    : {sps}")
    print(f"  PPS (8)    : {pps}")
    print(f"  IDR  (5)   : {idr}")
    print(f"  non-IDR(1) : {non_idr}")
    if sps == 0 or pps == 0:
        print("  ⚠ Parece que NO hay SPS/PPS completos o están muy fragmentados.")
    else:
        print("  ✅ Se ven SPS/PPS → cabeceras H.264 presentes.")


def scan_mode(paths: list[str]):
    """
    Modo: --scan archivo1 archivo2 ...
    """
    if not paths:
        print("[SCAN] Debes pasar al menos un archivo, ej:")
        print("       python jt1078_media_server.py --scan raw/000012345678_1_body_0000.bin")
        return

    for p in paths:
        scan_h264_file(pathlib.Path(p))


# ----------------- main server (async) -----------------

async def run_server():
    # limpiar sólo en modo servidor
    clean_start()

    # asegurar directorios
    MEDIA_ROOT.mkdir(parents=True, exist_ok=True)
    PIPE_ROOT.mkdir(parents=True, exist_ok=True)
    RAW_ROOT.mkdir(parents=True, exist_ok=True)

    # lanzar HTTP
    t = threading.Thread(target=start_http_server, daemon=True)
    t.start()

    loop = asyncio.get_running_loop()
    handler = JT1078Handler()

    transport_udp, protocol_udp = await loop.create_datagram_endpoint(
        lambda: JT1078UDP(handler),
        local_addr=("0.0.0.0", MEDIA_UDP_PORT),
        reuse_port=True,
    )

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


# ----------------- entrypoint -----------------

def main():
    parser = argparse.ArgumentParser(description="JT1078 media server + H264 scanner")
    parser.add_argument(
        "--scan",
        nargs="+",
        help="Analizar uno o más ficheros .bin/.h264 y contar SPS/PPS/IDR",
    )

    args = parser.parse_args()

    if args.scan:
        # MODO SCAN: NO limpiar, NO levantar server
        scan_mode(args.scan)
        return

    # MODO SERVER
    try:
        asyncio.run(run_server())
    except KeyboardInterrupt:
        LOG.info("Servidor detenido por teclado")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# jt1078_media_server.py
import asyncio, os, struct, logging, signal, pathlib, subprocess
import datetime, binascii, threading, sys
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

LOG = logging.getLogger("jt1078")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MEDIA_ROOT = pathlib.Path("./www")      # aquí quedarán los .m3u8 y .ts por SIM_CANAL/
PIPE_ROOT  = pathlib.Path("./pipes")    # named pipes para ffmpeg
MEDIA_ROOT.mkdir(parents=True, exist_ok=True)
PIPE_ROOT.mkdir(parents=True, exist_ok=True)

# Puertos configurables
MEDIA_UDP_PORT  = 7200   # donde el MDVR enviará los paquetes JT1078 (UDP)
MEDIA_HTTP_PORT = 2000   # donde exponemos HLS (HTTP)

# --- 1078 header (tabla 19): magic 0x30 0x31 0x63 0x64; luego campos tipo RTP+extras
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
        out.append(f"{(x>>4)&0xF}{x&0xF}")
    return "".join(out)

class StreamProc:
    """ Gestiona un ffmpeg por clave (sim,chan) con input por pipe """
    def __init__(self, key: str):
        self.key = key
        self.pipe_path = PIPE_ROOT / f"{key}.ps.pipe"
        self.out_dir   = MEDIA_ROOT / key
        self.ff = None

    def ensure(self):
        self.out_dir.mkdir(parents=True, exist_ok=True)
        if not self.pipe_path.exists():
            try:
                os.mkfifo(self.pipe_path)
            except FileExistsError:
                pass
        if self.ff is None or self.ff.poll() is not None:
            # Si necesitas reencode, cambia -c:v copy por -c:v libx264
            cmd = [
                "ffmpeg",
                "-hide_banner", "-loglevel", "warning",
                "-nostats",
                "-fflags", "nobuffer",
                "-thread_queue_size", "512",
                "-i", str(self.pipe_path),
                "-map", "0:v:0?",
                "-map", "0:a:0?",
                "-c:v", "copy",
                "-c:a", "aac", "-ar", "44100", "-b:a", "128k",
                "-f", "hls",
                "-hls_time", "2",
                "-hls_list_size", "10",
                "-hls_flags", "delete_segments+split_by_time",
                "-master_pl_name", "master.m3u8",
                str(self.out_dir / "index.m3u8")
            ]
            LOG.info(f"[{self.key}] starting ffmpeg: {' '.join(cmd)}")
            self.ff = subprocess.Popen(cmd)

    def write(self, data: bytes):
        self.ensure()
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

class JT1078UDP(asyncio.DatagramProtocol):
    def __init__(self):
        super().__init__()
        self.streams = {}       # key -> StreamProc
        self.reasm   = Reassembler()

    def connection_made(self, transport):
        self.transport = transport
        addr = transport.get_extra_info('sockname')
        LOG.info(f"JT1078 UDP escuchando en {addr}")

    def datagram_received(self, data, addr):
        try:
            if len(data) < 32:
                return
            if data[0:4] != b"\x30\x31\x63\x64":
                return  # no es 1078
            sim_bcd = data[8:14]
            sim = bcd6_to_str(sim_bcd)
            chan = data[14]
            typ_sub = data[15]
            data_type = (typ_sub >> 4) & 0x0F
            subflag   = typ_sub & 0x0F

            # Heurística para hallar body
            for body_len_off in (28, 30):
                if len(data) >= body_len_off+2:
                    body_len = int.from_bytes(data[body_len_off:body_len_off+2], 'big')
                    body_off = body_len_off + 2
                    if len(data) >= body_off + body_len:
                        body = data[body_off:body_off+body_len]
                        break
            else:
                body = data[30:]

            key = f"{sim}_{chan}"
            out = self.reasm.feed(key, subflag, body)
            if out:
                sp = self.streams.get(key)
                if sp is None:
                    sp = self.streams.setdefault(key, StreamProc(key))
                sp.write(out)

            # Log sencillo (I-frame)
            if data_type == 0x0:
                LOG.info(f"[{key}] I-frame ({len(body)} B) from {addr}")

        except Exception as e:
            LOG.exception(f"Error parseando 1078 pkt de {addr}: {e}")

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

    # 2) UDP para recibir video
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: JT1078UDP(),
        local_addr=("0.0.0.0", MEDIA_UDP_PORT),
        reuse_port=True,
    )
    LOG.info("Servidor de medios listo.")
    LOG.info(f"Ejemplo de URL por canal: http://telemetriaperu.com:{MEDIA_HTTP_PORT}/000012345678_1/index.m3u8")

    # Mantener proceso
    stop = asyncio.Future()
    for s in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(s, stop.cancel)
    try:
        await stop
    except asyncio.CancelledError:
        pass
    transport.close()

if __name__ == "__main__":
    asyncio.run(main())

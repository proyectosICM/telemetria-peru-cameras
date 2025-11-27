#!/usr/bin/env python3
"""
video.py - Servidor TCP "video service" en puerto 7200

Objetivo inicial:
  - Aceptar conexiones TCP en 0.0.0.0:7200
  - Recibir y loguear en hex TODOS los paquetes
  - Marcar en logs:
      * Primer paquete = "LOGIN / REGISTER (supuesto)"
      * Segundo paquete = "AUTH (supuesto)"
  - No se hace ningún parseo JT808 aquí.
  - No se envían respuestas automáticas (para no romper nada hasta
    entender el protocolo real del fabricante).
"""

import asyncio
import binascii
import logging
import socket
from datetime import datetime

# ========== Config básica ==========
HOST = "0.0.0.0"
PORT = 7200

# Si quieres más/menos verboso, cambia a DEBUG / WARNING
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("video-service")
raw_logger = logging.getLogger("video-service.raw")


# ========== Loop por conexión TCP ==========
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    # Activar TCP keepalive (por si el equipo mantiene la sesión abierta)
    sock = writer.get_extra_info("socket")
    if isinstance(sock, socket.socket):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

    peer = writer.get_extra_info("peername")
    logger.info(f"[CONN] Nueva conexión en puerto {PORT} desde {peer}")
    pkt_count = 0

    # Opcional: dumpear todo a un archivo para análisis offline
    # OJO: se abre por conexión, así que el nombre incluye IP/puerto
    dump_filename = f"video_raw_{peer[0]}_{peer[1]}.bin".replace(":", "_")
    try:
        dump_file = open(dump_filename, "ab")
    except Exception as e:
        logger.warning(f"[FILE] No se pudo abrir {dump_filename} para escribir: {e}")
        dump_file = None

    try:
        while not reader.at_eof():
            data = await reader.read(4096)
            if not data:
                break
            pkt_count += 1

            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            hex_payload = binascii.hexlify(data).decode()

            # Mensaje “amigable” en los logs
            if pkt_count == 1:
                tipo = "LOGIN/REGISTER (supuesto)"
            elif pkt_count == 2:
                tipo = "AUTH (supuesto)"
            else:
                tipo = f"DATA pkt#{pkt_count}"

            logger.info(
                f"[RX] {tipo} from {peer} len={len(data)} bytes "
                f"hex={hex_payload[:64]}{'...' if len(hex_payload) > 64 else ''}"
            )

            # Log “crudo” completo
            raw_logger.info(
                "RX peer=%s pkt#=%d len=%d hex=%s",
                peer,
                pkt_count,
                len(data),
                hex_payload,
            )

            # Guardar en archivo si se pudo abrir
            if dump_file is not None:
                try:
                    dump_file.write(data)
                    dump_file.flush()
                except Exception as e:
                    logger.warning(f"[FILE] Error escribiendo en {dump_filename}: {e}")

            # IMPORTANTE:
            # Por ahora NO respondemos nada. Algunos protocolos esperan
            # un ACK; otros no. Hasta ver el tráfico real (desde app o MDVR),
            # mejor observar solamente.
            #
            # Si más adelante ves en capturas que el servidor debe mandar algo fijo,
            # aquí podemos hacer algo como:
            #
            #   if pkt_count == 1:
            #       writer.write(b"...respuesta_login...")
            #       await writer.drain()

    except Exception as e:
        logger.exception(f"[ERR] Error en conexión {peer}: {e}")
    finally:
        try:
            if dump_file is not None:
                dump_file.close()
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
    logger.info(f"[MAIN] Servidor video-service escuchando en {addr}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[MAIN] Servidor detenido por teclado")

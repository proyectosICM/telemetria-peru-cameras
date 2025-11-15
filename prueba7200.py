#!/usr/bin/env python3
import asyncio
import datetime
import binascii
import logging

LOG = logging.getLogger("tcp_dump")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

TCP_PORT = 7200

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    LOG.info(f"Cliente conectado desde {addr}")

    try:
        while True:
            data = await reader.read(65535)  # lee hasta 64KB
            if not data:
                LOG.info(f"Cliente {addr} cerró la conexión")
                break

            now = datetime.datetime.now().isoformat(timespec="seconds")
            LOG.info(f"[{now}] Recibidos {len(data)} bytes de {addr}")
            print(binascii.hexlify(data).decode("ascii"))
            # Si quieres ver el raw:
            # print(data)

    except Exception as e:
        LOG.exception(f"Error con cliente {addr}: {e}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        LOG.info(f"Conexión cerrada con {addr}")


async def main():
    server = await asyncio.start_server(
        handle_client,
        host="0.0.0.0",
        port=TCP_PORT,
    )

    addr_list = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    LOG.info(f"Escuchando TCP en {addr_list}")

    # Esto se queda atendiendo clientes hasta que llegue Ctrl+C
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        LOG.info("Servidor detenido por Ctrl+C")

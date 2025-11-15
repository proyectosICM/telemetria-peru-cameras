#!/usr/bin/env python3
import asyncio
import datetime
import binascii
import logging
import signal

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
                # conexión cerrada por el cliente
                LOG.info(f"Cliente {addr} cerró la conexión")
                break

            now = datetime.datetime.now().isoformat(timespec="seconds")
            LOG.info(f"[{now}] Recibidos {len(data)} bytes de {addr}")
            # imprime en hex
            print(binascii.hexlify(data).decode("ascii"))
            # si quieres también texto crudo (comenta si molesta):
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
    loop = asyncio.get_running_loop()

    server = await asyncio.start_server(
        handle_client,
        host="0.0.0.0",
        port=TCP_PORT,
        reuse_port=True,  # quita esto si tu Python no lo soporta
    )

    addr_list = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    LOG.info(f"Escuchando TCP en {addr_list}")

    stop = asyncio.Future()
    for s in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(s, stop.cancel)

    async with server:
        try:
            await stop
        except asyncio.CancelledError:
            pass

        LOG.info("Cerrando servidor TCP...")
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())

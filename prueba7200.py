#!/usr/bin/env python3
import asyncio
import datetime
import binascii
import logging
import signal

LOG = logging.getLogger("udp_dump")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

UDP_PORT = 7200

class DumpUDP(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        addr = transport.get_extra_info("sockname")
        LOG.info(f"Escuchando UDP en {addr}")

    def datagram_received(self, data, addr):
        now = datetime.datetime.now().isoformat(timespec="seconds")
        LOG.info(f"[{now}] Paquete desde {addr}, {len(data)} bytes")
        print(binascii.hexlify(data).decode("ascii"))

async def main():
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DumpUDP(),
        local_addr=("0.0.0.0", UDP_PORT),
        reuse_port=True,
    )

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

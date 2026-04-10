#!/usr/bin/env python3
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack

from commands_http_server import start_commands_http_server
from control_commands_server import start_control_commands_server
from video import log_server_status
from command import logger


async def main():
    command_control_server = await start_control_commands_server()
    command_server = await start_commands_http_server()

    log_server_status("Servidor CONTROL COMANDOS JT808", command_control_server)
    log_server_status("API interna de comandos DVR", command_server)

    try:
        async with AsyncExitStack() as stack:
            tasks = []
            if command_control_server is not None:
                await stack.enter_async_context(command_control_server)
                tasks.append(command_control_server.serve_forever())
            if command_server is not None:
                await stack.enter_async_context(command_server)
                tasks.append(command_server.serve_forever())
            await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        raise


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[MAIN] Servidor de comandos detenido por teclado")

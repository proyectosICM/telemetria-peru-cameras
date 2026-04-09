#!/usr/bin/env python3
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack

from commands_http_server import start_commands_http_server
from control_commands_server import start_control_commands_server
from control_video_server import start_control_video_server
from video import log_server_status, logger, reap_idle_channels
from video_stream_server import start_video_stream_server


async def main():
    reaper_task = asyncio.create_task(reap_idle_channels(), name="channel-reaper")
    video_control_server = await start_control_video_server()
    video_server = await start_video_stream_server()
    command_control_server = await start_control_commands_server()
    command_server = await start_commands_http_server()

    log_server_status("Servidor CONTROL VIDEO JT808", video_control_server)
    log_server_status("Servidor CONTROL COMANDOS JT808", command_control_server)
    log_server_status("Servidor VIDEO", video_server)
    log_server_status("API interna de comandos DVR", command_server)

    try:
        async with AsyncExitStack() as stack:
            tasks = [reaper_task]
            if video_control_server is not None:
                await stack.enter_async_context(video_control_server)
                tasks.append(video_control_server.serve_forever())
            if video_server is not None:
                await stack.enter_async_context(video_server)
                tasks.append(video_server.serve_forever())
            if command_control_server is not None:
                await stack.enter_async_context(command_control_server)
                tasks.append(command_control_server.serve_forever())
            if command_server is not None:
                await stack.enter_async_context(command_server)
                tasks.append(command_server.serve_forever())
            await asyncio.gather(*tasks)
    finally:
        reaper_task.cancel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[MAIN] Servidor detenido por teclado")

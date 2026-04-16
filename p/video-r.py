#!/usr/bin/env python3
from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack

from video import (
    create_command_http_server,
    create_video_control_server,
    create_video_stream_server,
    log_server_status,
    logger,
    reap_idle_channels,
)


async def main():
    reaper_task = asyncio.create_task(reap_idle_channels(), name="channel-reaper")
    video_control_server = await create_video_control_server()
    video_server = await create_video_stream_server()
    command_server = await create_command_http_server()

    log_server_status("Servidor CONTROL VIDEO JT808", video_control_server)
    log_server_status("Servidor VIDEO", video_server)
    log_server_status("API interna de video DVR", command_server)

    try:
        async with AsyncExitStack() as stack:
            tasks = [reaper_task]
            if video_control_server is not None:
                await stack.enter_async_context(video_control_server)
                tasks.append(video_control_server.serve_forever())
            if video_server is not None:
                await stack.enter_async_context(video_server)
                tasks.append(video_server.serve_forever())
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
        logger.info("[MAIN] Servidor de video detenido por teclado")

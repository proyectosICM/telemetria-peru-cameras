from __future__ import annotations

from command import create_command_http_server


async def start_commands_http_server():
    return await create_command_http_server()

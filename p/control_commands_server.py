from __future__ import annotations

from video import create_command_control_server


async def start_control_commands_server():
    # 6808 queda reservado para comandos JT808. No debe iniciar video.
    return await create_command_control_server()

from __future__ import annotations

from command import create_command_control_server, get_command_control_registry


async def start_control_commands_server():
    return await create_command_control_server()

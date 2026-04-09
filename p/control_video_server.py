from __future__ import annotations

from video import create_video_control_server


async def start_control_video_server():
    return await create_video_control_server()

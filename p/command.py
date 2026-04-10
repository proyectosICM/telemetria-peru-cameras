from __future__ import annotations

import asyncio
import binascii
import logging
import socket

from video import (
    ALWAYS_ACK_UNKNOWN,
    COMMAND_CONTROL_PORT,
    COMMAND_HTTP_PORT,
    ENABLE_COMMAND_CONTROL,
    ENABLE_COMMAND_HTTP,
    ENABLE_CONTROL_RAW_DUMP,
    HOST,
    ISSUED_AUTH_CODES,
    MSG_HANDLERS as _VIDEO_MSG_HANDLERS_UNUSED,
    Request,
    build_0x8001,
    build_0x8100,
    build_auth_code_for_phone,
    build_catalog_response,
    build_command_frames,
    de_escape,
    do_escape,
    get_json_header,
    handle_0001_terminal_general_resp,
    json,
    logger,
    normalize_phone,
    parse_coord_u32,
    parse_header,
    parse_intish,
    parse_qs,
    parse_time_bcd6,
    proxy_video_http_request,
    register_control_session,
    resolve_alert_definition,
    should_push_dvr_gps,
    push_dvr_gps_snapshot,
    status_acc_on,
    unregister_control_session,
    urlparse,
    write_http_response,
)
from video import get_control_session as _get_control_session_shared
from video import SessionState


raw_logger = logging.getLogger("video808.raw")

COMMAND_CONTROL_SESSIONS = {}


def get_command_control_registry():
    return COMMAND_CONTROL_SESSIONS


async def get_command_control_session(phone_str: str | None):
    return await _get_control_session_shared(phone_str, registry=COMMAND_CONTROL_SESSIONS)


def handle_0002_heartbeat(session, hdr, body):
    logger.info(f"[0002] Heartbeat desde phone={hdr['phone_str']}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


def handle_0003_logout(session, hdr, body):
    session.authenticated = False
    session.position_seen = False
    session.video_started = False
    logger.info(f"[0003] Logout terminal phone={hdr['phone_str']}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


def handle_0100_register(session, hdr, body):
    try:
        prov = int.from_bytes(body[0:2], "big")
        city = int.from_bytes(body[2:4], "big")
        manu = body[4:9].decode("ascii", errors="ignore").strip()
        model = body[9:29].decode("ascii", errors="ignore").strip()
        term_id = body[29:36].decode("ascii", errors="ignore").strip()
        plate_color = body[36] if len(body) > 36 else None
        plate = body[37:].decode("ascii", errors="ignore").strip() if len(body) > 37 else ""
        logger.info(
            f"[0100] Registro terminal phone={hdr['phone_str']} prov={prov} city={city} "
            f"manu={manu!r} model={model!r} term_id={term_id!r} "
            f"plate_color={plate_color} plate={plate!r}"
        )
    except Exception as exc:
        logger.exception(f"Error parseando 0x0100: {exc}")
        logger.info(f"[0100] Registro terminal phone={hdr['phone_str']} (body_len={len(body)})")

    auth_code = build_auth_code_for_phone(hdr["phone_str"])
    ISSUED_AUTH_CODES[hdr["phone_str"]] = auth_code
    logger.info(f"[0100] Auth code emitido para phone={hdr['phone_str']}: {auth_code!r}")
    return build_0x8100(
        hdr["phone_bcd"],
        session.next_flow(),
        hdr["flow_id"],
        result=0,
        auth_code=auth_code.encode("ascii", errors="ignore"),
    )


def handle_0102_auth(session, hdr, body):
    try:
        token = body.decode(errors="ignore") if body else ""
    except Exception:
        token = body.hex()
    expected_token = ISSUED_AUTH_CODES.get(hdr["phone_str"], "")
    session.authenticated = True
    if expected_token and token != expected_token:
        logger.warning(
            f"[0102] Auth phone={hdr['phone_str']} token={token!r} "
            f"esperado={expected_token!r}"
        )
    else:
        logger.info(f"[0102] Auth phone={hdr['phone_str']} token={token!r}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


def handle_0200_position(session, hdr, body):
    try:
        session.position_seen = True
        if len(body) < 28:
            logger.warning(f"[0200] body demasiado corto: len={len(body)} phone={hdr['phone_str']}")
        else:
            alarm = int.from_bytes(body[0:4], "big")
            status = int.from_bytes(body[4:8], "big")
            lat = parse_coord_u32(body[8:12])
            lon = parse_coord_u32(body[12:16])
            alt = int.from_bytes(body[16:18], "big", signed=False)
            speed = int.from_bytes(body[18:20], "big", signed=False) / 10.0
            course = int.from_bytes(body[20:22], "big", signed=False)
            dt = parse_time_bcd6(body[22:28])
            logger.info(
                f"[0200] phone={hdr['phone_str']} alarm={alarm} status={status} "
                f"lat={lat:.6f} lon={lon:.6f} alt={alt}m speed={speed:.1f}km/h "
                f"course={course} time={dt.isoformat()}"
            )
            if should_push_dvr_gps(session):
                asyncio.create_task(
                    push_dvr_gps_snapshot(
                        session,
                        hdr["phone_str"],
                        latitude=lat,
                        longitude=lon,
                        speed_kmh=speed,
                        ignition_status=status_acc_on(status),
                        alarm_status=alarm != 0,
                        timestamp_iso=dt.isoformat(),
                    )
                )
    except Exception as exc:
        logger.exception(f"Error parseando 0x0200: {exc}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


def handle_0704_batch_positions(session, hdr, body):
    try:
        session.position_seen = True
        if session.control_context is not None:
            session.control_context.mark_batch_positions()
        if len(body) < 3:
            logger.warning(f"[0704] body demasiado corto: len={len(body)} phone={hdr['phone_str']}")
            return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)

        count = int.from_bytes(body[0:2], "big")
        batch_type = body[2]
        idx = 3
        last_position_payload = None
        logger.info(f"[0704] phone={hdr['phone_str']} count={count} type={batch_type}")

        for i in range(count):
            if idx + 2 > len(body):
                logger.warning(f"[0704] sin espacio para data_len en registro {i} phone={hdr['phone_str']}")
                break
            data_len = int.from_bytes(body[idx:idx + 2], "big")
            idx += 2
            if idx + data_len > len(body):
                logger.warning(
                    f"[0704] data_len={data_len} excede body_len en registro {i} phone={hdr['phone_str']}"
                )
                break
            data = body[idx:idx + data_len]
            idx += data_len
            if len(data) < 28:
                logger.warning(f"[0704] item[{i}] demasiado corto len={len(data)} phone={hdr['phone_str']}")
                continue
            try:
                alarm = int.from_bytes(data[0:4], "big")
                status = int.from_bytes(data[4:8], "big")
                lat = parse_coord_u32(data[8:12])
                lon = parse_coord_u32(data[12:16])
                alt = int.from_bytes(data[16:18], "big", signed=False)
                speed = int.from_bytes(data[18:20], "big", signed=False) / 10.0
                course = int.from_bytes(data[20:22], "big", signed=False)
                dt = parse_time_bcd6(data[22:28])
                logger.info(
                    f"[0704] item[{i}] phone={hdr['phone_str']} type={batch_type} "
                    f"alarm={alarm} status={status} lat={lat:.6f} lon={lon:.6f} "
                    f"alt={alt}m speed={speed:.1f}km/h course={course} time={dt.isoformat()}"
                )
                last_position_payload = {
                    "latitude": lat,
                    "longitude": lon,
                    "speed_kmh": speed,
                    "ignition_status": status_acc_on(status),
                    "alarm_status": alarm != 0,
                    "timestamp_iso": dt.isoformat(),
                }
            except Exception as exc:
                logger.exception(f"[0704] Error parseando item[{i}] phone={hdr['phone_str']}: {exc}")
        if should_push_dvr_gps(session) and last_position_payload is not None:
            asyncio.create_task(push_dvr_gps_snapshot(session, hdr["phone_str"], **last_position_payload))
    except Exception as exc:
        logger.exception(f"[0704] Error manejando batch phone={hdr['phone_str']}: {exc}")
    return build_0x8001(hdr["phone_bcd"], session.next_flow(), hdr["flow_id"], hdr["msg_id"], 0)


COMMAND_MSG_HANDLERS = {
    b"\x00\x01": handle_0001_terminal_general_resp,
    b"\x00\x02": handle_0002_heartbeat,
    b"\x00\x03": handle_0003_logout,
    b"\x01\x00": handle_0100_register,
    b"\x01\x02": handle_0102_auth,
    b"\x02\x00": handle_0200_position,
    b"\x07\x04": handle_0704_batch_positions,
}


async def bind_command_session(session: SessionState, hdr, writer, peer):
    normalized_phone = normalize_phone(hdr["phone_str"])
    if not normalized_phone:
        return None
    ctx = await register_control_session(
        normalized_phone,
        hdr["phone_bcd"],
        session,
        writer,
        peer,
        registry_name="command-control",
        registry=COMMAND_CONTROL_SESSIONS,
        listen_port=COMMAND_CONTROL_PORT,
    )
    if ctx is not None:
        ctx.touch()
    return ctx


async def handle_command_control_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    sock = writer.get_extra_info("socket")
    if isinstance(sock, socket.socket):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass

    peer = writer.get_extra_info("peername")
    logger.info(f"[CONN] Nueva conexion CONTROL registry=command-control puerto {COMMAND_CONTROL_PORT} desde {peer}")
    session = SessionState()
    buf = b""
    dump_filename = None
    dump_file = None

    if ENABLE_CONTROL_RAW_DUMP:
        dump_filename = f"video808_ctrl_raw_{peer[0]}_{peer[1]}".replace(':', '_') + ".bin"
        try:
            dump_file = open(dump_filename, "ab")
        except Exception as exc:
            logger.warning(f"[FILE] No se pudo abrir {dump_filename}: {exc}")
            dump_file = None

    try:
        while not reader.at_eof():
            chunk = await reader.read(4096)
            if not chunk:
                break
            if dump_file is not None:
                try:
                    dump_file.write(chunk)
                    dump_file.flush()
                except Exception as exc:
                    logger.warning(f"[FILE] Error escribiendo en {dump_filename}: {exc}")
            buf += chunk

            while True:
                s = buf.find(b"\x7e")
                if s == -1:
                    break
                e = buf.find(b"\x7e", s + 1)
                if e == -1:
                    break
                frame = buf[s + 1:e]
                buf = buf[e + 1:]

                try:
                    payload = de_escape(frame)
                    if len(payload) < 13:
                        continue
                    calc = 0
                    for b in payload[:-1]:
                        calc ^= b
                    if calc != payload[-1]:
                        continue

                    hdr = parse_header(payload[:-1])
                    await bind_command_session(session, hdr, writer, peer)
                    body = payload[:-1][hdr["body_idx"]:hdr["body_idx"] + hdr["body_len"]]
                    hex_payload = binascii.hexlify(payload).decode()
                    raw_logger.info("RX peer=%s phone=%s msgId=0x%s hex=%s", peer, hdr["phone_str"], hdr["msg_id"].hex(), hex_payload)
                    logger.info(
                        f"[RX] msgId=0x{hdr['msg_id'].hex()} phone={hdr['phone_str']} "
                        f"body_len={hdr['body_len']} has_subpkg={hdr['has_subpkg']}"
                    )

                    if session.control_context is not None:
                        session.control_context.touch()

                    msg_id = hdr["msg_id"]
                    handler = COMMAND_MSG_HANDLERS.get(msg_id)
                    if handler:
                        resp = handler(session, hdr, body)
                        if resp:
                            logger.info(
                                f"[TX] registry=command-control port={COMMAND_CONTROL_PORT} "
                                f"phone={hdr['phone_str']} resp_for=0x{hdr['msg_id'].hex()} "
                                f"flow={int.from_bytes(hdr['flow_id'], 'big')}"
                            )
                            writer.write(resp)
                            await writer.drain()

                        if msg_id == b"\x01\x02":
                            logger.info(
                                f"[CMD] Auth OK para phone={hdr['phone_str']} en registry=command-control; "
                                f"este puerto no inicia video"
                            )
                    else:
                        logger.info(f"[RX] MsgId no manejado: 0x{msg_id.hex()} phone={hdr['phone_str']} len={hdr['body_len']}")
                        if ALWAYS_ACK_UNKNOWN:
                            resp = build_0x8001(
                                hdr["phone_bcd"],
                                session.next_flow(),
                                hdr["flow_id"],
                                hdr["msg_id"],
                                0,
                            )
                            logger.info(f"[TX] phone={hdr['phone_str']} msgId=0x8001 (Ack UNKNOWN 0x{hdr['msg_id'].hex()})")
                            writer.write(resp)
                            await writer.drain()
                except Exception as exc:
                    logger.exception(f"[ERR] Error manejando frame: {exc}")
    except Exception as exc:
        logger.exception(f"[ERR] Error en conexion CONTROL {peer}: {exc}")
    finally:
        try:
            if dump_file is not None:
                dump_file.close()
        except Exception:
            pass
        await unregister_control_session(
            session.phone_str,
            writer,
            registry_name="command-control",
            registry=COMMAND_CONTROL_SESSIONS,
        )
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        logger.info(f"[CONN] Conexion CONTROL cerrada registry=command-control puerto {COMMAND_CONTROL_PORT} {peer}")


def authorize_http_request(headers: dict):
    from video import COMMAND_API_TOKEN

    if not COMMAND_API_TOKEN:
        return True
    auth_header = get_json_header(headers, "authorization") or ""
    return auth_header == f"Bearer {COMMAND_API_TOKEN}"


async def handle_command_http_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        raw_head = await reader.readuntil(b"\r\n\r\n")
        head_text = raw_head.decode("utf-8", errors="ignore")
        lines = head_text.split("\r\n")
        if not lines or not lines[0]:
            await write_http_response(writer, 400, {"error": "Solicitud invalida"})
            return
        try:
            method, target, _ = lines[0].split(" ", 2)
        except ValueError:
            await write_http_response(writer, 400, {"error": "Request line invalida"})
            return
        headers = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        if not authorize_http_request(headers):
            await write_http_response(writer, 401, {"error": "Unauthorized"})
            return
        content_length = int(headers.get("content-length", "0") or "0")
        body = await reader.readexactly(content_length) if content_length > 0 else b""
        parsed = urlparse(target)
        query = parse_qs(parsed.query)

        if method == "GET" and parsed.path == "/health":
            await write_http_response(
                writer,
                200,
                {
                    "status": "ok",
                    "commandControlPort": COMMAND_CONTROL_PORT,
                    "commandHttpPort": COMMAND_HTTP_PORT,
                },
            )
            return
        if method == "GET" and parsed.path == "/dvr-alerts":
            phone = query.get("phone", [None])[0]
            session_ctx = await get_command_control_session(phone)
            await write_http_response(writer, 200, build_catalog_response(phone, session_ctx))
            return
        if method == "POST" and parsed.path in {"/video-streams/ensure", "/video-streams/stop"}:
            await proxy_video_http_request(writer, method, parsed.path, body)
            return
        if method == "POST" and parsed.path == "/dvr-alerts/execute":
            try:
                payload = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                await write_http_response(writer, 400, {"error": "JSON invalido"})
                return
            phone = normalize_phone(payload.get("phone"))
            alert_code = payload.get("alertCode")
            subalert_code = payload.get("subalertCode")
            channel = payload.get("channel")
            duration_seconds = payload.get("durationSeconds")
            if not phone or not alert_code:
                await write_http_response(writer, 400, {"error": "phone y alertCode son obligatorios"})
                return
            session_ctx = await get_command_control_session(phone)
            if session_ctx is None:
                await write_http_response(writer, 409, {"status": "offline", "phone": phone, "error": "DVR sin sesion de control activa"})
                return
            alert_def, sub_def, command = resolve_alert_definition(alert_code, subalert_code)
            if alert_def is None:
                await write_http_response(writer, 404, {"error": "Alerta no configurada"})
                return
            if command is None:
                await write_http_response(writer, 400, {"error": "La alerta existe pero no tiene comando configurado en cameras", "alertCode": alert_code, "subalertCode": subalert_code})
                return
            resolved_channel = parse_intish(channel, default=None)
            resolved_duration = parse_intish(duration_seconds, default=None)
            try:
                frames = build_command_frames(
                    session_ctx,
                    alert_code=alert_code,
                    subalert_code=subalert_code,
                    command=command,
                    channel=resolved_channel,
                    duration_seconds=resolved_duration,
                )
                result = await session_ctx.enqueue_command("dvr-alert-execute", frames)
            except Exception as exc:
                await write_http_response(writer, 500, {"status": "error", "phone": phone, "error": str(exc)})
                return
            await write_http_response(
                writer,
                200,
                {
                    "status": result.get("status", "ack"),
                    "phone": phone,
                    "alertCode": alert_code,
                    "subalertCode": subalert_code,
                    "channel": resolved_channel,
                    "durationSeconds": resolved_duration,
                    "results": result.get("results", []),
                },
            )
            return
        await write_http_response(writer, 404, {"error": "Ruta no encontrada"})
    except Exception as exc:
        logger.exception(f"[HTTP] Error procesando solicitud de comandos: {exc}")
        try:
            await write_http_response(writer, 500, {"error": "Error interno"})
        except Exception:
            pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def create_command_control_server():
    if not ENABLE_COMMAND_CONTROL:
        return None
    return await asyncio.start_server(handle_command_control_client, HOST, COMMAND_CONTROL_PORT)


async def create_command_http_server():
    if not ENABLE_COMMAND_HTTP:
        return None
    return await asyncio.start_server(handle_command_http_client, HOST, COMMAND_HTTP_PORT)

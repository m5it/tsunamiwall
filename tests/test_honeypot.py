import asyncio

import pytest

from tsunamiwall.honeypot import HitEvent, HoneypotServer, jsonl_formatter


@pytest.mark.asyncio
async def test_honeypot_logs_hit():
    events = []

    def log_hit(event: HitEvent):
        events.append(event)

    server = HoneypotServer(54321, log_hit)
    await server.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 54321)
        data = await reader.read(1)
        assert data == b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        await asyncio.sleep(0.05)
        assert len(events) == 1
        evt = events[0]
        assert evt.dst_port == 54321
        assert evt.src_ip == "127.0.0.1"
        assert evt.proto == "tcp"
    finally:
        await server.stop()


def test_jsonl_formatter():
    evt = HitEvent(
        time="2026-10-11T12:00:00Z",
        src_ip="1.2.3.4",
        src_port=12345,
        dst_port=54321,
        proto="tcp",
    )
    line = jsonl_formatter(evt)
    assert '"src_ip":"1.2.3.4"' in line
    assert '"dst_port":54321' in line

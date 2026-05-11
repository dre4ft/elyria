"""
In-memory event broker for scan progress — SSE-friendly pub/sub.
Thread-safe: producers (scan thread) use queue.Queue, consumers (asyncio) poll via run_in_executor.
"""

import asyncio
import json
import queue
import time
from collections import defaultdict

# { campaign_id: [queue.Queue, queue.Queue, ...] }
_subscribers = defaultdict(list)
_heartbeats = {}
_last_events = {}
_done = {}

HEARTBEAT_TIMEOUT = 120


def publish(campaign_id: str, event_type: str, data: dict = None):
    """Thread-safe publish. No-op if campaign is done."""
    if _done.get(campaign_id):
        return
    payload = json.dumps({
        "type": event_type,
        "data": data or {},
        "ts": time.time(),
    })
    _last_events[campaign_id] = payload
    if event_type in ("round", "heartbeat", "progress", "finding", "log"):
        _heartbeats[campaign_id] = time.time()
    if event_type == "done":
        _done[campaign_id] = True
    dead = []
    for q in _subscribers.get(campaign_id, []):
        try:
            q.put_nowait(payload)
        except queue.Full:
            dead.append(q)
    for q in dead:
        try:
            _subscribers[campaign_id].remove(q)
        except ValueError:
            pass


def heartbeat(campaign_id: str):
    _heartbeats[campaign_id] = time.time()
    publish(campaign_id, "heartbeat", {"ts": _heartbeats[campaign_id]})


def is_stuck(campaign_id: str) -> bool:
    last = _heartbeats.get(campaign_id)
    if not last:
        return False
    return (time.time() - last) > HEARTBEAT_TIMEOUT


async def subscribe(campaign_id: str):
    """Async generator yielding SSE events. Stops on done or disconnect."""
    q = queue.Queue(maxsize=100)
    _subscribers[campaign_id].append(q)
    loop = asyncio.get_running_loop()

    # Replay last event
    last = _last_events.get(campaign_id)
    if last:
        yield f"data: {last}\n\n"

    done_sent = _done.get(campaign_id, False)
    try:
        while not done_sent:
            try:
                msg = await asyncio.wait_for(
                    loop.run_in_executor(None, q.get), timeout=15
                )
                yield f"data: {msg}\n\n"
                try:
                    if json.loads(msg).get("type") == "done":
                        done_sent = True
                except Exception:
                    pass
            except asyncio.TimeoutError:
                if _done.get(campaign_id):
                    break
                yield f"data: {json.dumps({'type': 'keepalive', 'ts': time.time()})}\n\n"
    except asyncio.CancelledError:
        pass
    finally:
        try:
            _subscribers[campaign_id].remove(q)
        except ValueError:
            pass


def cleanup(campaign_id: str):
    _done[campaign_id] = True
    done_payload = json.dumps({"type": "done", "data": {"status": "cleaned"}, "ts": time.time()})
    for q in _subscribers.get(campaign_id, []):
        try:
            q.put_nowait(done_payload)
        except queue.Full:
            pass
    _subscribers.pop(campaign_id, None)
    _heartbeats.pop(campaign_id, None)
    _last_events.pop(campaign_id, None)

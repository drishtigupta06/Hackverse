import os
import json
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, Callable, Awaitable
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
SCAN_QUEUE_KEY = "scan:queue"
WORKER_TASK: Optional[asyncio.Task] = None

redis: Optional[Redis] = None
_redis_lock = asyncio.Lock()


async def get_redis() -> Redis:
    global redis
    if redis is None:
        async with _redis_lock:
            if redis is None:
                redis = Redis.from_url(REDIS_URL, decode_responses=True)
    return redis


async def close_redis():
    global redis
    if redis:
        await redis.close()
        redis = None


async def push_scan(scan_id: str, app_id: str, config: dict):
    r = await get_redis()
    payload = json.dumps({"scan_id": scan_id, "app_id": app_id, "config": config})
    await r.rpush(SCAN_QUEUE_KEY, payload)
    logger.info(f"Pushed scan {scan_id} to queue")


async def pop_scan() -> Optional[dict]:
    r = await get_redis()
    result = await r.blpop(SCAN_QUEUE_KEY, timeout=1)
    if result:
        _, payload = result
        return json.loads(payload)
    return None


async def publish_log(scan_id: str, level: str, message: str):
    r = await get_redis()
    payload = json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": message,
    })
    await r.publish(f"scan:{scan_id}:logs", payload)


async def publish_event(scan_id: str, event: str, data: dict):
    r = await get_redis()
    payload = json.dumps({"event": event, **data})
    await r.publish(f"scan:{scan_id}:logs", payload)


async def subscribe_logs(scan_id: str) -> Redis:
    r = await get_redis()
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan:{scan_id}:logs")
    return pubsub


def start_worker(handler: Callable[[str, str, dict], Awaitable[None]]):
    global WORKER_TASK

    async def _worker_loop():
        logger.info("Scan queue worker started")
        retry_count = 0
        while True:
            try:
                task = await pop_scan()
                if task:
                    retry_count = 0
                    logger.info(f"Worker picked up scan {task['scan_id']}")
                    try:
                        await handler(task["scan_id"], task["app_id"], task["config"])
                    except Exception as e:
                        logger.error(f"Scan {task['scan_id']} failed: {e}")
                else:
                    await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                logger.info("Worker shutting down")
                break
            except Exception as e:
                retry_count += 1
                backoff = min(2 ** retry_count, 60)
                logger.error(f"Worker error (attempt {retry_count}): {e}")
                await asyncio.sleep(backoff)

    WORKER_TASK = asyncio.create_task(_worker_loop())


async def stop_worker():
    global WORKER_TASK
    if WORKER_TASK:
        WORKER_TASK.cancel()
        try:
            await WORKER_TASK
        except asyncio.CancelledError:
            pass
        WORKER_TASK = None

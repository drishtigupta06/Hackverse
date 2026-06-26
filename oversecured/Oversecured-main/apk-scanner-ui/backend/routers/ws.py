import json
import asyncio
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from services.db import async_session
from services.queue import subscribe_logs
from models.scan import Scan
from models.scan_log import ScanLog

logger = logging.getLogger(__name__)
router = APIRouter()


@router.websocket("/ws/scans/{scan_id}/logs")
async def scan_logs_websocket(websocket: WebSocket, scan_id: str):
    await websocket.accept()

    pubsub = None
    try:
        async with async_session() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                await websocket.send_json({"event": "error", "message": "Scan not found"})
                await websocket.close()
                return

            log_result = await db.execute(
                select(ScanLog)
                .where(ScanLog.scan_id == scan_id)
                .order_by(ScanLog.id.desc())
                .limit(100)
            )
            recent_logs = list(reversed(log_result.scalars().all()))
            for log_entry in recent_logs:
                await websocket.send_json({
                    "ts": log_entry.ts.isoformat() if log_entry.ts else "",
                    "level": log_entry.level,
                    "message": log_entry.message,
                })

        pubsub = await subscribe_logs(scan_id)

        async def listen_pubsub():
            async for message in pubsub.listen():
                if message["type"] == "message":
                    data = json.loads(message["data"])
                    await websocket.send_json(data)
                    if data.get("event") == "scan_complete":
                        break

        await asyncio.wait_for(listen_pubsub(), timeout=3600)

    except asyncio.TimeoutError:
        logger.warning(f"WebSocket timeout for scan {scan_id}")
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for scan {scan_id}")
    except Exception as e:
        logger.error(f"WebSocket error for scan {scan_id}: {e}")
    finally:
        if pubsub:
            try:
                await pubsub.unsubscribe()
                await pubsub.close()
            except Exception as e:
                logger.warning(f"Failed to close pubsub: {e}")
        try:
            await websocket.close()
        except Exception:
            pass

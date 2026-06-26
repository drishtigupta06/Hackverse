import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from services.db import init_db
from services.queue import start_worker, close_redis, stop_worker
from services.scanner_runner import run_scan
from services.emulator_service import ensure_emulator, stop_emulator
from routers import apps, scans, findings, reports, ws, health, settings, cve

EMULATOR_AVD = os.getenv("EMULATOR_AVD", "Pixel_6_API_33")
EMULATOR_RAM = int(os.getenv("EMULATOR_RAM", "2048"))
EMULATOR_ENABLED = os.getenv("EMULATOR_ENABLED", "true").lower() == "true"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up...")
    await init_db()
    start_worker(run_scan)
    if EMULATOR_ENABLED:
        status = await ensure_emulator(avd_name=EMULATOR_AVD, ram=EMULATOR_RAM)
        logger.info("Emulator status: %s (serial=%s)", status.get("status"), status.get("serial"))
    yield
    logger.info("Shutting down...")
    await stop_emulator()
    await stop_worker()
    await close_redis()


origins = ALLOWED_ORIGINS.split(",") if ALLOWED_ORIGINS != "*" else ["*"]
app = FastAPI(
    title="APK Scanner UI",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials="*" not in origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(apps.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(ws.router)
app.include_router(settings.router)
app.include_router(cve.router)

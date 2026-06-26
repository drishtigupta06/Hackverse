#!/usr/bin/env python3
"""CyberGuard — FastAPI main application (optimized)."""
import asyncio, uuid, logging, json
from datetime import datetime
from typing import Optional, List

import shutil
import os
import hashlib
from fastapi import FastAPI, HTTPException, Depends, status, Response, WebSocket, WebSocketDisconnect, BackgroundTasks, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from motor.motor_asyncio import AsyncIOMotorClient

import config
import auth as auth_module
from models import UserRegister, TokenResponse, ScanRequest, ChatRequest, ChatResponse, ScanStatus, ReconRequest, LLMScanRequest

from pydantic import BaseModel
class NmapRequest(BaseModel):
    target: str
    ports: Optional[List[int]] = None

class GarakScanRequest(BaseModel):
    target: str
    probes: Optional[str] = "all"
    generations: Optional[int] = 5

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def strip_ansi(text):
    if not isinstance(text, str): return text
    import re
    return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)

# ─── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="CyberGuard API", description="AI-Assisted Cybersecurity Platform", version="1.1.0")
# Using regex to allow all local development origins on any port
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
# Ensure static/screenshots exists
os.makedirs("static/screenshots", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# ─── DB ────────────────────────────────────────────────────────────────────────
_mongo_client: Optional[AsyncIOMotorClient] = None

def get_db():
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = AsyncIOMotorClient(config.MONGO_URL, serverSelectionTimeoutMS=5000)
    return _mongo_client[config.MONGO_DB]

# ─── WebSocket Manager ─────────────────────────────────────────────────────────
class ScanProgressManager:
    def __init__(self):
        self.connections: dict[str, list[WebSocket]] = {}

    async def connect(self, scan_id: str, ws: WebSocket):
        await ws.accept()
        self.connections.setdefault(scan_id, []).append(ws)

    def disconnect(self, scan_id: str, ws: WebSocket):
        if scan_id in self.connections:
            self.connections[scan_id].discard(ws) if hasattr(self.connections[scan_id], 'discard') else None
            try:
                self.connections[scan_id].remove(ws)
            except ValueError:
                pass

    async def broadcast(self, scan_id: str, message: dict):
        dead = []
        for ws in self.connections.get(scan_id, []):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(scan_id, ws)

ws_manager = ScanProgressManager()

# ─── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    logger.info("CyberGuard API v1.1 starting up...")
    
    # RAG Sync
    try:
        import rag_engine, acunetix_scanner
        # Seed OWASP if empty
        if rag_engine.collection_count() == 0:
            rag_engine.ingest_owasp_basics()
            logger.info("[startup] OWASP docs seeded")
        
        # Sync Acunetix reports to RAG
        loop = asyncio.get_event_loop()
        ingested = await loop.run_in_executor(None, acunetix_scanner.sync_all_scans_to_rag)
        logger.info(f"[startup] Synced {ingested} historical Acunetix reports into RAG")
    except Exception as e:
        logger.warning(f"[startup] RAG/Acunetix sync failed: {e}")
    try:
        db = get_db()
        await db.scans.create_index("scan_id", unique=True)
        await db.scans.create_index("user")
        await db.vulnerabilities.create_index("scan_id")
        await db.vulnerabilities.create_index([("severity", 1)])
        await db.vulnerabilities.create_index("cve_id")
        await db.users.create_index("username", unique=True)
        await db.chats.create_index("user")
        logger.info("[startup] MongoDB indexes created")
    except Exception as e:
        logger.warning(f"[startup] Index error: {e}")

# ─── Health ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    db_ok = False
    try:
        db = get_db()
        await db.command("ping")
        db_ok = True
    except Exception:
        pass
    return {"status": "ok", "service": "CyberGuard API", "version": "1.1.0", "db": db_ok}

# ─── AUTH ──────────────────────────────────────────────────────────────────────
@app.post("/auth/register", status_code=201)
async def register(body: UserRegister):
    db = get_db()
    existing = await db.users.find_one({"username": body.username})
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    user_doc = {
        "username": body.username, "email": body.email,
        "password_hash": auth_module.hash_password(body.password),
        "created_at": datetime.utcnow().isoformat(), "role": "analyst",
    }
    await db.users.insert_one(user_doc)
    return {"message": "User registered successfully", "username": body.username}

@app.post("/auth/login", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    db = get_db()
    user = await db.users.find_one({"username": form_data.username})
    if not user or not auth_module.verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = auth_module.create_access_token({"sub": form_data.username})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/auth/me")
async def get_me(token: str = Depends(auth_module.oauth2_scheme)):
    payload = auth_module.decode_token(token)
    db = get_db()
    user = await db.users.find_one({"username": payload.get("sub")}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# ─── SCANS ─────────────────────────────────────────────────────────────────────
async def _run_scan_background(scan_id: str, target: str, scan_types: list, username: str):
    """Run scan async in background — non-blocking."""
    import nmap_scanner, vulnerability_normalizer, attack_graph
    db = get_db()

    async def log(msg: str, level="info"):
        await ws_manager.broadcast(scan_id, {"type": "log", "msg": msg, "level": level})
        status_detail = msg
        await db.scans.update_one({"scan_id": scan_id}, {"$set": {"status_detail": status_detail}})

    try:
        await db.scans.update_one({"scan_id": scan_id}, {"$set": {"status": "running", "started_at": datetime.utcnow().isoformat()}})
        await log(f"🎯 Scanning target: {target}")

        all_raw, all_vulns = [], []

        if "nmap" in scan_types:
            await log("📡 Running Nmap scan...")
            loop = asyncio.get_event_loop()
            raw = await loop.run_in_executor(None, lambda: nmap_scanner.run_nmap_scan(target))
            all_raw.extend(raw)
            await log(f"📡 Nmap found {len(raw)} service entries")

            vulns = vulnerability_normalizer.normalize_nmap_results(raw, scan_id)
            all_vulns.extend(vulns)
            await log(f"🐛 Normalized {len(vulns)} vulnerabilities from Nmap")

        if "acunetix" in scan_types:
            await log("🔍 Starting DAST scan (async)...")
            try:
                import acunetix_scanner
                ax_vulns = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: acunetix_scanner.run_acunetix_scan(target)
                )
                all_vulns.extend(ax_vulns)
                await log(f"🔍 DAST found {len(ax_vulns)} vulnerabilities")
            except Exception as e:
                await log(f"⚠️ DAST skipped: {e}", "warning")

        if all_vulns:
            await db.vulnerabilities.insert_many(all_vulns)

        # Ingest into RAG so AI can answer questions about this specific report
        await log("🧠 Syncing report with AI knowledge base...")
        try:
            import rag_engine
            rag_engine.ingest_scan_report(all_vulns, target=target, scan_label=scan_id[:8])
            # Also ingest CVEs specifically
            rag_engine.ingest_cve_records([v for v in all_vulns if v.get("cve_id")])
        except Exception as e:
            logger.error(f"[scan] RAG ingestion failed: {e}")

        # Store hosts
        if all_raw:
            hosts_map = {}
            for entry in all_raw:
                h = entry.get("host", "")
                hosts_map.setdefault(h, []).append({
                    "port": entry.get("port"), "protocol": entry.get("protocol"),
                    "state": entry.get("state"), "service": entry.get("service"), "version": entry.get("version"),
                })
            for host_ip, ports in hosts_map.items():
                await db.hosts.replace_one(
                    {"scan_id": scan_id, "host": host_ip},
                    {"scan_id": scan_id, "host": host_ip, "ports": ports, "discovered_at": datetime.utcnow().isoformat()},
                    upsert=True,
                )

        # Attack graph
        await log("🕸️ Building attack graph...")
        graph = attack_graph.build_attack_graph(scan_id, all_vulns)
        await db.graphs.replace_one({"scan_id": scan_id}, graph, upsert=True)

        await db.scans.update_one({"scan_id": scan_id}, {"$set": {
            "status": "completed",
            "status_detail": f"Done — {len(all_vulns)} vulnerabilities found",
            "completed_at": datetime.utcnow().isoformat(),
            "vuln_count": len(all_vulns),
            "host_count": len(set(v.get("host") for v in all_vulns)),
        }})
        await log(f"✅ Scan complete! {len(all_vulns)} vulnerabilities found.", "success")
        await ws_manager.broadcast(scan_id, {"type": "done", "vuln_count": len(all_vulns)})

    except Exception as e:
        logger.error(f"[scan] Background scan error: {e}", exc_info=True)
        await db.scans.update_one({"scan_id": scan_id}, {"$set": {"status": "failed", "error": str(e)}})
        await ws_manager.broadcast(scan_id, {"type": "error", "msg": str(e)})


@app.post("/scans", status_code=201)
async def create_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(auth_module.oauth2_scheme),
):
    payload = auth_module.decode_token(token)
    username = payload.get("sub")
    scan_id = str(uuid.uuid4())
    db = get_db()

    scan_doc = {
        "scan_id": scan_id, "user": username, "target": body.target,
        "description": body.description, "scan_types": body.scan_types,
        "status": "pending", "status_detail": "Queued",
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None, "completed_at": None,
        "vuln_count": 0, "host_count": 0, "error": None,
    }
    await db.scans.insert_one(scan_doc)

    # Try Celery first, fallback to background task
    queued_via_celery = False
    try:
        from celery_tasks import run_scan_task
        task = run_scan_task.delay(scan_id, body.target, body.scan_types)
        await db.scans.update_one({"scan_id": scan_id}, {"$set": {"celery_task_id": task.id}})
        queued_via_celery = True
        logger.info(f"[scan] {scan_id} queued via Celery: {task.id}")
    except Exception:
        background_tasks.add_task(_run_scan_background, scan_id, body.target, body.scan_types, username)
        logger.info(f"[scan] {scan_id} running via FastAPI background task")

    return {"scan_id": scan_id, "status": "pending", "mode": "celery" if queued_via_celery else "background"}


# ─── RECONNAISSANCE ───────────────────────────────────────────────────────────

@app.post("/recon/discovery", status_code=201)
async def create_recon(
    body: ReconRequest,
    token: str = Depends(auth_module.oauth2_scheme),
):
    payload = auth_module.decode_token(token)
    username = payload.get("sub")
    recon_id = str(uuid.uuid4())
    db = get_db()

    recon_doc = {
        "recon_id": recon_id, "user": username, "target_domain": body.target_domain,
        "description": body.description, "status": "pending",
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None, "completed_at": None, "asset_count": 0,
    }
    await db.recon_jobs.insert_one(recon_doc)

    try:
        from celery_tasks import run_recon_task
        task = run_recon_task.delay(recon_id, body.target_domain)
        await db.recon_jobs.update_one({"recon_id": recon_id}, {"$set": {"celery_task_id": task.id}})
        return {"recon_id": recon_id, "status": "pending", "task_id": task.id}
    except Exception as e:
        logger.error(f"[recon] Failed to queue recon: {e}")
        # Fallback to direct async call if Celery fails (not recommended but for robustness)
        import recon_scanner
        asyncio.create_task(recon_scanner.run_recon_job(recon_id, body.target_domain, db))
        return {"recon_id": recon_id, "status": "pending", "mode": "background"}

@app.get("/recon/jobs")
async def list_recon_jobs(token: str = Depends(auth_module.oauth2_scheme)):
    payload = auth_module.decode_token(token)
    db = get_db()
    jobs = await db.recon_jobs.find({"user": payload["sub"]}, {"_id": 0}).sort("created_at", -1).to_list(100)
    return {"jobs": jobs}

@app.get("/recon/results/{recon_id}")
async def get_recon_results(recon_id: str, current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    assets_cursor = db.recon_assets.find({"scan_id": recon_id})
    assets = await assets_cursor.to_list(length=1000)
    for a in assets:
        a["_id"] = str(a["_id"])
    return {"assets": assets}

# ─── Credential Leaks Endpoints ──────────────────────────────────────────────

@app.post("/recon/leaks/scan")
async def trigger_leak_scan(req: ReconRequest, background_tasks: BackgroundTasks, current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    from models import LeakReport
    report = LeakReport(target_domain=req.target_domain, status="running")
    await db.leak_reports.insert_one(report.dict())
    
    async def run_scan(scan_id: str, domain: str):
        try:
            import leak_scanner
            scanner = leak_scanner.LeakScanner(domain)
            findings = await scanner.execute_scan()
            await db.leak_reports.update_one(
                {"scan_id": scan_id},
                {"$set": {
                    "status": "completed", 
                    "findings": findings,
                    "completed_at": datetime.utcnow().isoformat()
                }}
            )
        except Exception as e:
            await db.leak_reports.update_one(
                {"scan_id": scan_id},
                {"$set": {"status": "failed", "error": str(e), "completed_at": datetime.utcnow().isoformat()}}
            )

    background_tasks.add_task(run_scan, report.scan_id, req.target_domain)
    return {"message": "Leak scan initiated", "scan_id": report.scan_id}

@app.get("/recon/leaks/jobs")
async def get_leak_jobs(current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    jobs = await db.leak_reports.find().sort("created_at", -1).to_list(100)
    for j in jobs:
        j["_id"] = str(j["_id"])
    return {"jobs": jobs}

@app.get("/recon/leaks/results/{scan_id}")
async def get_leak_results(scan_id: str, current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    report = await db.leak_reports.find_one({"scan_id": scan_id})
    if not report:
        raise HTTPException(status_code=404, detail="Leak report not found")
    report["_id"] = str(report["_id"])
    return {"report": report}

# ─── Global Threat Intelligence Endpoints ─────────────────────────────────────

@app.get("/intel/feed")
async def get_threat_intel_feed(current_user: str = Depends(auth_module.get_current_user)):
    """Fetches the latest global threat intelligence feed (NVD, Rapid7, MITRE)."""
    import threat_intel_feed
    feed = threat_intel_feed.get_latest_threat_intel()
    return {"feed": feed}

@app.post("/recon/leaks/scan")
async def start_leak_scan(req: ReconRequest, background_tasks: BackgroundTasks, current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    from models import LeakReport
    report = LeakReport(target_domain=req.target_domain, status="running")
    await db.leak_jobs.insert_one(report.dict())
    
    async def run_leaks_background(domain: str, scan_id: str):
        import leak_scanner
        scanner = leak_scanner.LeakScanner(domain)
        findings = await scanner.execute_scan()
        await db.leak_jobs.update_one({"scan_id": scan_id}, {"$set": {"status": "completed", "findings": findings, "completed_at": datetime.utcnow().isoformat()}})

    background_tasks.add_task(run_leaks_background, req.target_domain, report.scan_id)
    return {"message": "Leak scan initiated", "scan_id": report.scan_id}

@app.get("/recon/leaks/jobs")
async def get_leak_jobs(current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    jobs = await db.leak_jobs.find().sort("created_at", -1).to_list(100)
    for j in jobs:
        j["_id"] = str(j["_id"])
    return {"jobs": jobs}

@app.get("/recon/leaks/results/{scan_id}")
async def get_leak_results(scan_id: str, current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    report = await db.leak_jobs.find_one({"scan_id": scan_id})
    if not report:
        raise HTTPException(status_code=404, detail="Leak report not found")
    report["_id"] = str(report["_id"])
    return {"report": report}

# ─── NMAP API (v1) ───────────────────────────────────────────────────────────

@app.post("/api/v1/nmap/scan")
async def start_nmap_scan_v1(request: NmapRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    db = get_db()
    v1_user = "v1_guest"
    
    # Register in existing scans collection for persistence
    scan_doc = {
        "scan_id": scan_id, "user": v1_user, "target": request.target,
        "description": "Nmap Scan (v1 API)", "scan_types": ["nmap"],
        "status": "pending", "status_detail": "Initializing Nmap...",
        "created_at": datetime.utcnow().isoformat(),
        "vuln_count": 0, "host_count": 0
    }
    await db.scans.insert_one(scan_doc)
    
    # Run using the same refined background runner
    background_tasks.add_task(_run_scan_background, scan_id, request.target, ["nmap"], v1_user)
    return {"scan_id": scan_id, "status": "started"}

@app.get("/api/v1/nmap/status/{scan_id}")
async def get_nmap_status_v1(scan_id: str):
    db = get_db()
    scan = await db.scans.find_one({"scan_id": scan_id})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Map to requested structure
    return {
        "scan_id": scan["scan_id"],
        "status": scan["status"],
        "progress": 100 if scan["status"] == "completed" else 50 if scan["status"] == "running" else 0,
        "message": scan.get("status_detail", ""),
        "logs": scan.get("logs", [])[-50:]
    }

# ─── GARAK API (v1) ──────────────────────────────────────────────────────────

@app.get("/api/v1/garak/models")
async def list_models_v1(limit: int = 50):
    """List available LLM generators from Garak (Curated Open Models)."""
    import garak_scanner
    models = await garak_scanner.fetch_available_models(limit=limit)
    return [m["id"] for m in models]

@app.get("/api/v1/garak/probes")
async def list_probes_v1():
    """List available Garak probes."""
    import garak_scanner
    return [p["id"] for p in garak_scanner.AVAILABLE_PROBES]

@app.post("/api/v1/garak/scan")
async def start_garak_scan_v1(request: GarakScanRequest, background_tasks: BackgroundTasks):
    # Aliased to trigger_llm_scan logic but with v1 inputs
    from models import LLMScanRequest as RealLLMRequest
    probes_list = request.probes.split(",") if request.probes and request.probes != "all" else ["dan", "promptinject", "web_injection"]
    v1_user = "v1_guest"
    
    # Determine target type automatically (defaulting to local 'huggingface' for friction-free ops)
    target_type = "huggingface"
    if "gpt" in request.target.lower(): target_type = "openai"
    
    req = RealLLMRequest(model_name=request.target, target_type=target_type, probes=probes_list)
    return await trigger_llm_scan(req, background_tasks, v1_user)

@app.get("/api/v1/garak/status/{scan_id}")
async def get_garak_status_v1(scan_id: str):
    db = get_db()
    job = await db.llm_scan_jobs.find_one({"scan_id": scan_id})
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": job["scan_id"],
        "status": job["status"],
        "progress": 100 if job["status"] == "completed" else 50,
        "message": "Scan in progress" if job["status"] == "running" else job["status"],
        "logs": [strip_ansi(l) for l in job.get("logs", [])[-50:]]
    }

@app.get("/api/v1/garak/results/{scan_id}")
async def get_scan_results_v1(scan_id: str):
    db = get_db()
    job = await db.llm_scan_jobs.find_one({"scan_id": scan_id})
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Map to requested structure for high-compatibility
    results = []
    for r in job.get("results", []):
        results.append({
            "id": str(uuid.uuid4()),
            "scanner": "Garak",
            "name": f"Garak Probe: {r.get('probe')}",
            "severity": r.get("severity", "medium"),
            "url": job.get("model_name"),
            "asset": "LLM Model",
            "description": f"Target: {r.get('probe')}\nDetector: {r.get('detector')}",
            "passed": r.get("status") == "PASS"
        })
    return results

# ─── ACUNETIX PROXY (v1) ─────────────────────────────────────────────────────

@app.api_route("/api/v1/acunetix/{path:path}", methods=["GET", "POST", "PATCH", "DELETE", "PUT"])
async def acunetix_proxy_v1(request: Request, path: str):
    import httpx
    ACUNETIX_BASE = "https://kali:3443/api/v1"
    clean_path = path.lstrip("/")
    url = f"{ACUNETIX_BASE}/{clean_path}"
    
    if request.query_params:
        url += f"?{request.query_params}"
        
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ["host", "content-length", "connection"]}
    # Inject API Key from config
    headers["X-Auth"] = config.ACUNETIX_KEY
    
    body = await request.body()
    
    try:
        async with httpx.AsyncClient(verify=False, timeout=60.0) as client:
            resp = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body
            )
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers={k: v for k, v in resp.headers.items() if k.lower() not in ["content-encoding", "transfer-encoding", "content-length", "connection"]}
            )
    except Exception as e:
        logger.error(f"Acunetix Proxy Error: {e}")
        raise HTTPException(status_code=500, detail=f"Proxy error: {str(e)}")

# ─── LLM Vulnerability Scanning Endpoints (NVIDIA garak - LEGACY) ─────────────

@app.get("/llm/models")
async def get_llm_models(current_user: str = Depends(auth_module.get_current_user)):
    import garak_scanner
    models = await garak_scanner.fetch_available_models()
    return {"models": models}

@app.get("/llm/probes")
async def get_llm_probes(current_user: str = Depends(auth_module.get_current_user)):
    import garak_scanner
    return {"probes": garak_scanner.AVAILABLE_PROBES}

@app.post("/llm/scan")
async def trigger_llm_scan(req: LLMScanRequest, background_tasks: BackgroundTasks, current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    from models import LLMScanJob
    job = LLMScanJob(
        model_name=req.model_name,
        target_type=req.target_type,
        probes=req.probes,
        status="running"
    )
    await db.llm_scan_jobs.insert_one(job.dict())
    
    async def log_to_db(msg: str):
        await db.llm_scan_jobs.update_one(
            {"scan_id": job.scan_id},
            {"$push": {"logs": msg}}
        )

    async def run_scan(scan_id: str, model_name: str, target_type: str, probes: list):
        try:
            import garak_scanner
            scanner = garak_scanner.GarakScanner(
                model_name=model_name,
                target_type=target_type,
                probes=probes,
                scan_id=scan_id,
                log_callback=log_to_db
            )
            results = await scanner.execute_scan()
            await db.llm_scan_jobs.update_one(
                {"scan_id": scan_id},
                {"$set": {
                    "status": "completed", 
                    "results": results,
                    "completed_at": datetime.utcnow()
                }}
            )
        except Exception as e:
            logger.error(f"LLM Scan failed: {e}")
            await db.llm_scan_jobs.update_one(
                {"scan_id": scan_id},
                {"$set": {"status": "failed", "error": str(e), "completed_at": datetime.utcnow()}}
            )

    background_tasks.add_task(run_scan, job.scan_id, req.model_name, req.target_type, req.probes)
    return {"status": "running", "scan_id": job.scan_id}

@app.get("/llm/jobs")
async def get_llm_jobs(current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    jobs = await db.llm_scan_jobs.find().sort("created_at", -1).to_list(100)
    for j in jobs:
        j["_id"] = str(j["_id"])
    return {"jobs": jobs}

@app.get("/llm/results/{scan_id}")
async def get_llm_results(scan_id: str, current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    job = await db.llm_scan_jobs.find_one({"scan_id": scan_id})
    if not job:
        raise HTTPException(status_code=404, detail="LLM scan job not found")
    job["_id"] = str(job["_id"])
    return {"job": job}

@app.get("/llm/{scan_id}/report")
async def download_llm_report(scan_id: str, token: str = Depends(auth_module.oauth2_scheme)):
    auth_module.decode_token(token)
    db = get_db()
    job = await db.llm_scan_jobs.find_one({"scan_id": scan_id})
    if not job:
        raise HTTPException(status_code=404, detail="LLM scan not found")
    if job.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    vulns = []
    for r in job.get("results", []):
        if r.get("status") == "FAIL":
            vulns.append({
                "name": f"Garak Probe Failure: {r.get('probe')}",
                "severity": r.get("severity", "medium").lower() if r.get("severity") else "medium",
                "cve_id": "",
                "host": job.get("model_name", ""),
                "port": "API",
                "service": "LLM API",
                "source": "Garak Scanner",
                "description": f"Target Probe: {r.get('probe')}\nDetector triggered: {r.get('detector')}\nDetails: {r.get('msg', 'N/A')}",
                "remediation": "Review the specific prompt injection or jailbreak technique causing this failure and implement input guardrails."
            })
            
    import report_generator
    pdf = report_generator.generate_pdf_report(
        scan_id=scan_id, target=job.get("model_name", "LLM Model"),
        vulnerabilities=vulns, graph_data=None, created_at=job.get("created_at"),
    )
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="cyberguard_llm_report_{scan_id[:8]}.pdf"'})

# ─── Mobile Scan Endpoints ───────────────────────────────────────────────────

@app.post("/mobile/scan")
async def trigger_mobile_scan(file: UploadFile = File(...), current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    
    # Save file temporarily
    os.makedirs("/tmp/cyberguard_mobile", exist_ok=True)
    file_path = f"/tmp/cyberguard_mobile/{uuid.uuid4()}_{file.filename}"
    
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save uploaded file: {str(e)}")
        
    from models import MobileScan
    
    # Calc simple MD5 hash
    hasher = hashlib.md5()
    with open(file_path, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    file_hash = hasher.hexdigest()
    
    scan_doc = MobileScan(filename=file.filename, file_hash=file_hash, status="pending")
    await db.mobile_scans.insert_one(scan_doc.dict())
    
    # Trigger background Celery Task
    import celery_tasks
    celery_tasks.run_mobile_scan_task.delay(scan_doc.scan_id, file_path, file.filename)
    
    return {"message": "Mobile scan job initiated", "scan_id": scan_doc.scan_id}

@app.get("/mobile/jobs")
async def list_mobile_jobs(current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    jobs = await db.mobile_scans.find().sort("created_at", -1).to_list(100)
    for j in jobs:
        j["_id"] = str(j["_id"])
    return {"jobs": jobs}

@app.get("/mobile/results/{scan_id}")
async def get_mobile_results(scan_id: str, current_user: str = Depends(auth_module.get_current_user)):
    db = get_db()
    job = await db.mobile_scans.find_one({"scan_id": scan_id})
    if not job:
        raise HTTPException(status_code=404, detail="Mobile scan not found")
    job["_id"] = str(job["_id"])
    return {"job": job}

@app.get("/mobile/{scan_id}/report")
async def download_mobile_report(scan_id: str, token: str = Depends(auth_module.oauth2_scheme)):
    auth_module.decode_token(token)
    db = get_db()
    job = await db.mobile_scans.find_one({"scan_id": scan_id})
    if not job:
        raise HTTPException(status_code=404, detail="Mobile scan not found")
    if job.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not completed yet")
    
    vulns = []
    # Map MobSF issues to vulnerability schema
    for file_path, issues_list in job.get("report", {}).items():
        if isinstance(issues_list, list):
            for issue in issues_list:
                sev = issue.get("severity", "info").lower()
                vulns.append({
                    "name": issue.get("title", "Mobile Security Issue"),
                    "severity": "critical" if sev == "high" else "high" if sev == "warning" else "info" if sev == "secure" else "medium",
                    "cve_id": "",
                    "host": job.get("filename", "App"),
                    "port": "APK/IPA",
                    "service": "Mobile App",
                    "source": "MobSF Scanner",
                    "description": f"File: {file_path}\nDescription: {issue.get('description', '')}",
                    "remediation": "Review the code pattern and implement secure mobile coding guidelines."
                })
            
    import report_generator
    pdf = report_generator.generate_pdf_report(
        scan_id=scan_id, target=job.get("filename", "Mobile App"),
        vulnerabilities=vulns, graph_data=None, created_at=job.get("created_at"),
    )
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="cyberguard_mobile_report_{scan_id[:8]}.pdf"'})

# ─── Agents Endpoints ────────────────────────────────────────────────────────

@app.get("/scans")
async def list_scans(limit: int = 20, skip: int = 0, token: str = Depends(auth_module.oauth2_scheme)):
    payload = auth_module.decode_token(token)
    db = get_db()
    cursor = db.scans.find({"user": payload["sub"]}, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit)
    scans = await cursor.to_list(length=limit)
    total = await db.scans.count_documents({"user": payload["sub"]})
    return {"scans": scans, "total": total}


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str, token: str = Depends(auth_module.oauth2_scheme)):
    auth_module.decode_token(token)
    db = get_db()
    scan = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, token: str = Depends(auth_module.oauth2_scheme)):
    payload = auth_module.decode_token(token)
    db = get_db()
    scan = await db.scans.find_one({"scan_id": scan_id, "user": payload["sub"]})
    if not scan:
        raise HTTPException(404, "Scan not found")
    await db.scans.delete_one({"scan_id": scan_id})
    await db.vulnerabilities.delete_many({"scan_id": scan_id})
    await db.hosts.delete_many({"scan_id": scan_id})
    await db.graphs.delete_one({"scan_id": scan_id})
    return Response(status_code=204)


@app.get("/scans/{scan_id}/hosts")
async def get_scan_hosts(scan_id: str, token: str = Depends(auth_module.oauth2_scheme)):
    auth_module.decode_token(token)
    db = get_db()
    hosts = await db.hosts.find({"scan_id": scan_id}, {"_id": 0}).to_list(500)
    return {"hosts": hosts}


@app.get("/scans/{scan_id}/vulnerabilities")
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = 300,
    token: str = Depends(auth_module.oauth2_scheme),
):
    auth_module.decode_token(token)
    db = get_db()
    query = {"scan_id": scan_id}
    if severity:
        query["severity"] = severity
    if source:
        query["source"] = source
    cursor = db.vulnerabilities.find(query, {"_id": 0}).limit(limit)
    vulns = await cursor.to_list(length=limit)
    total = await db.vulnerabilities.count_documents(query)
    return {"vulnerabilities": vulns, "total": total}


@app.get("/scans/{scan_id}/graph")
async def get_attack_graph(scan_id: str, token: str = Depends(auth_module.oauth2_scheme)):
    auth_module.decode_token(token)
    db = get_db()
    graph = await db.graphs.find_one({"scan_id": scan_id}, {"_id": 0})
    if not graph:
        raise HTTPException(404, "Attack graph not found — scan may not have completed")
    return graph


@app.get("/scans/{scan_id}/simulation")
async def get_attack_simulation(scan_id: str, token: str = Depends(auth_module.oauth2_scheme)):
    """Generates an LLM-driven step-by-step attack simulation based on the scan results."""
    auth_module.decode_token(token)
    db = get_db()
    
    scan = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(404, "Scan not found")
        
    vulns = await db.vulnerabilities.find({"scan_id": scan_id}, {"_id": 0}).limit(50).to_list(50)
    hosts = await db.hosts.find({"scan_id": scan_id}, {"_id": 0}).limit(10).to_list(10)
    
    ports = []
    for h in hosts:
        ports.extend(h.get("ports", []))
        
    import attack_simulator
    loop = asyncio.get_event_loop()
    
    # Run the LLM network call in an executor block to prevent blocking the async FastAPI loop
    simulation_steps = await loop.run_in_executor(
        None, 
        lambda: attack_simulator.generate_attack_chain(scan_id, scan.get("target", "unknown"), vulns, ports)
    )
    
    return {"simulation": simulation_steps}


@app.get("/scans/{scan_id}/report")
async def download_report(scan_id: str, token: str = Depends(auth_module.oauth2_scheme)):
    auth_module.decode_token(token)
    db = get_db()
    scan = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.get("status") != "completed":
        raise HTTPException(400, "Scan not completed yet")
    vulns = await db.vulnerabilities.find({"scan_id": scan_id}, {"_id": 0}).to_list(500)
    graph = await db.graphs.find_one({"scan_id": scan_id}, {"_id": 0})
    import report_generator
    pdf = report_generator.generate_pdf_report(
        scan_id=scan_id, target=scan.get("target", ""),
        vulnerabilities=vulns, graph_data=graph, created_at=scan.get("created_at"),
    )
    return Response(content=pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="cyberguard_report_{scan_id[:8]}.pdf"'})


# ─── WEBSOCKET — live scan progress ───────────────────────────────────────────
@app.websocket("/ws/scans/{scan_id}")
async def scan_ws(websocket: WebSocket, scan_id: str):
    await ws_manager.connect(scan_id, websocket)
    try:
        # Send current status immediately
        db = get_db()
        scan = await db.scans.find_one({"scan_id": scan_id}, {"_id": 0})
        if scan:
            await websocket.send_json({"type": "status", "status": scan.get("status"), "detail": scan.get("status_detail")})
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)


# ─── STATS + VULNERABILITIES ───────────────────────────────────────────────────
@app.get("/stats")
async def get_stats(token: str = Depends(auth_module.oauth2_scheme)):
    payload = auth_module.decode_token(token)
    username = payload["sub"]
    db = get_db()
    scan_ids = [s["scan_id"] async for s in db.scans.find({"user": username}, {"scan_id": 1})]
    q = {"scan_id": {"$in": scan_ids}}
    total_vulns = await db.vulnerabilities.count_documents(q)
    critical = await db.vulnerabilities.count_documents({**q, "severity": "critical"})
    high = await db.vulnerabilities.count_documents({**q, "severity": "high"})
    medium = await db.vulnerabilities.count_documents({**q, "severity": "medium"})
    low = await db.vulnerabilities.count_documents({**q, "severity": "low"})
    completed = await db.scans.count_documents({"user": username, "status": "completed"})
    running = await db.scans.count_documents({"user": username, "status": "running"})
    
    import rag_engine
    intelligence_count = rag_engine.collection_count()
    
    # ── Calculate Organization Security Posture Score ──
    # Formula: 100 - (critical * 10) - (high * 5) - (medium * 2) - (low * 1)
    score = 100 - (critical * 10) - (high * 5) - (medium * 2) - (low * 1)
    score = max(0, score)
    
    if score >= 90:
        risk_level = "Low"
    elif score >= 70:
        risk_level = "Medium"
    elif score >= 40:
        risk_level = "High"
    else:
        risk_level = "Critical"
    
    return {
        "total_scans": len(scan_ids), "completed_scans": completed, "running_scans": running,
        "total_vulnerabilities": total_vulns,
        "critical_count": critical, "high_count": high, "medium_count": medium, "low_count": low,
        "intelligence_count": intelligence_count,
        "security_score": score,
        "risk_level": risk_level,
        "severity_breakdown": {"critical": critical, "high": high, "medium": medium, "low": low,
                               "info": total_vulns - critical - high - medium - low},
    }


@app.get("/vulnerabilities")
async def list_all_vulnerabilities(
    severity: Optional[str] = None, source: Optional[str] = None,
    cve_id: Optional[str] = None, limit: int = 100, skip: int = 0,
    token: str = Depends(auth_module.oauth2_scheme),
):
    auth_module.decode_token(token)
    db = get_db()
    query = {}
    if severity:
        query["severity"] = severity
    if source:
        query["source"] = source
    if cve_id:
        query["cve_id"] = {"$regex": cve_id, "$options": "i"}
    vulns = await db.vulnerabilities.find(query, {"_id": 0}).sort("discovered_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.vulnerabilities.count_documents(query)
    return {"vulnerabilities": vulns, "total": total}


# ─── CVE LOOKUP ────────────────────────────────────────────────────────────────
@app.get("/cve/{cve_id}")
async def lookup_cve(cve_id: str, token: str = Depends(auth_module.oauth2_scheme)):
    """Fetch CVE details from NVD API."""
    auth_module.decode_token(token)
    try:
        import threat_intel
        loop = asyncio.get_event_loop()
        data = await loop.run_in_executor(None, lambda: threat_intel.fetch_cve_details(cve_id.upper()))
        return data
    except Exception as e:
        raise HTTPException(404, f"CVE not found or NVD unavailable: {e}")


# ─── CHAT ──────────────────────────────────────────────────────────────────────
@app.post("/chat", response_model=ChatResponse)
async def chat(body: ChatRequest, token: str = Depends(auth_module.oauth2_scheme)):
    payload = auth_module.decode_token(token)
    username = payload["sub"]
    scan_context = None
    if body.scan_id:
        db = get_db()
        vulns = await db.vulnerabilities.find({"scan_id": body.scan_id}, {"_id": 0}).limit(30).to_list(30)
        if vulns:
            import llm_chatbot
            scan_context = llm_chatbot.build_scan_context(vulns)
    import llm_chatbot
    loop = asyncio.get_event_loop()
    answer, context_used = await loop.run_in_executor(None, lambda: llm_chatbot.ask(body.question, scan_context=scan_context))
    try:
        db = get_db()
        await db.chats.insert_one({
            "user": username, "question": body.question, "answer": answer,
            "scan_id": body.scan_id, "timestamp": datetime.utcnow().isoformat(),
        })
    except Exception:
        pass
    return {"answer": answer, "context_used": context_used[:3]}


@app.get("/proxy/flower/{path:path}")
async def proxy_flower(path: str, request: Request, token: str = Depends(auth_module.oauth2_scheme)):
    """Proxy requests to Flower API with query parameters and Basic Auth."""
    auth_module.decode_token(token)
    import httpx
    import base64
    
    query_params = str(request.query_params)
    url = f"http://localhost:5555/api/{path}"
    if query_params:
        url += f"?{query_params}"
    
    # Flower Basic Auth: admin:cyberguard2024
    auth_str = "admin:cyberguard2024"
    encoded_auth = base64.b64encode(auth_str.encode()).decode()
    headers = {"Authorization": f"Basic {encoded_auth}"}
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=10)
            if resp.status_code != 200:
                return {"error": f"Flower API returned {resp.status_code}", "status_code": resp.status_code}
            return resp.json()
    except Exception as e:
        logger.error(f"[proxy] Flower proxy failed for {path}: {e}")
        return {"error": str(e), "success": False}


@app.get("/chat/history")
async def chat_history(limit: int = 50, token: str = Depends(auth_module.oauth2_scheme)):
    payload = auth_module.decode_token(token)
    db = get_db()
    chats = await db.chats.find({"user": payload["sub"]}, {"_id": 0}).sort("timestamp", -1).limit(limit).to_list(limit)
    return {"chats": chats, "total": len(chats)}


# ─── DEMO SCAN (non-blocking) ──────────────────────────────────────────────────
@app.post("/demo/scan-localhost")
async def demo_scan_localhost(
    background_tasks: BackgroundTasks,
    token: str = Depends(auth_module.oauth2_scheme),
):
    """Quick demo scan — starts Nmap in background, returns scan_id immediately."""
    payload = auth_module.decode_token(token)
    username = payload["sub"]
    scan_id = str(uuid.uuid4())
    db = get_db()

    scan_doc = {
        "scan_id": scan_id, "user": username, "target": "127.0.0.1",
        "description": "Demo localhost scan", "scan_types": ["nmap"],
        "status": "pending", "status_detail": "Starting...",
        "created_at": datetime.utcnow().isoformat(),
        "started_at": None, "completed_at": None, "vuln_count": 0, "host_count": 0,
    }
    await db.scans.insert_one(scan_doc)
    background_tasks.add_task(_run_scan_background, scan_id, "127.0.0.1", ["nmap"], username)
    return {"scan_id": scan_id, "status": "pending", "message": "Scan started in background — poll /scans/{scan_id} for updates"}


# ─── SWAGGER DOCS ──────────────────────────────────────────────────────────────
# Available at /docs and /redoc automatically via FastAPI

# ─── HACKATHON DEMO ENDPOINTS ────────────────────────────────────────────────

@app.post("/api/v1/agent/hacker-mode")
async def start_hacker_mode(request: ReconRequest, background_tasks: BackgroundTasks, token: str = Depends(auth_module.oauth2_scheme)):
    """The 'Winning Button' — Orchestrates full autonomous demo workflow."""
    payload = auth_module.decode_token(token)
    username = payload["sub"]
    scan_id = str(uuid.uuid4())
    db = get_db()
    
    target = request.target_domain
    
    # 1. Create a Master Scan entry
    scan_doc = {
        "scan_id": scan_id, "user": username, "target": target,
        "description": "🚀 AI Hacker Mode — Full Workflow", "scan_types": ["nmap", "acunetix"],
        "status": "pending", "status_detail": "Initializing Hacker Mode...",
        "created_at": datetime.utcnow().isoformat(),
        "is_hacker_mode": True,
        "vuln_count": 0, "host_count": 0
    }
    await db.scans.insert_one(scan_doc)
    
    # 2. Add as a background task that chains everything
    async def run_hacker_workflow():
        await ws_manager.broadcast(scan_id, {"type": "log", "msg": "🚀 Deploying CyberGuard AI Hacker Mode...", "level": "info"})
        
        # Step A: Recon
        await ws_manager.broadcast(scan_id, {"type": "log", "msg": "📡 Phase 1: Deep Reconnaissance starting...", "level": "info"})
        import recon_scanner
        # Mocking recon speed for demo impact
        await asyncio.sleep(2) 
        await recon_scanner.run_recon_job(scan_id, target, db)
        
        # Step B: Vulnerability Scan
        await ws_manager.broadcast(scan_id, {"type": "log", "msg": "🔍 Phase 2: Vulnerability Analysis...", "level": "info"})
        await _run_scan_background(scan_id, target, ["nmap", "acunetix"], username)
        
        # Step C: Final Polish
        await ws_manager.broadcast(scan_id, {"type": "log", "msg": "✅ Hacker Mode Cycle Complete. Final Report Ready.", "level": "success"})

    background_tasks.add_task(run_hacker_workflow)
    return {"scan_id": scan_id, "status": "started", "message": "CyberGuard AI Agent deployed in Hacker Mode."}

@app.get("/api/v1/agent/simulator/{scan_id}")
async def get_attack_scenario(scan_id: str):
    """Generates a cinematic narrative of 'What can hackers do?'."""
    db = get_db()
    vulns = await db.vulnerabilities.find({"scan_id": scan_id}).to_list(10)
    if not vulns:
        return {"scenario": "Attacker is currently profiling the target. No direct entry points identified yet."}
    
    # Simple narrative builder for demo power
    critical = [v for v in vulns if v.get("severity") == "critical"]
    high = [v for v in vulns if v.get("severity") == "high"]
    
    entry = critical[0] if critical else high[0] if high else vulns[0]
    
    scenario = [
        f"1. Attacker identifies an exposed {entry.get('service', 'service')} on port {entry.get('port', 'unknown')}.",
        f"2. Attacker leverages '{entry.get('name', 'vulnerability')}' to bypass initial perimeter security.",
        "3. Lateral movement detected towards internal API endpoints.",
        "4. Attacker successfully extracts database credentials from environment variables.",
        "5. COMPLETE COMPROMISE: Attacker achieves full data access and exfiltration capability."
    ]
    
    return {"scenario": scenario, "impact": "CRITICAL" if critical else "HIGH"}

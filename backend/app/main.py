import asyncio
import os
import random
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings
from app.storage.db import db
from app.auth import get_session_user, initialize_auth
from app.routers.auth import COOKIE_NAME, router as auth_router
from app.storage.memory_store import memory_store
from app.models.schemas import AlertItem, SeverityLevel, ThreatType, ThreatStatus
from app.remediation.knowledge_base import get_remediation_guide
from app.routers import (
    dashboard_router,
    alerts_router,
    security_router,
    traffic_router,
    simulator_router,
    integrations_router,
)

# Background task to stream live system metrics and simulated benign shopping activity
async def background_metrics_stream():
    benign_endpoints = [
        ("GET", "/api/products?category=electronics"),
        ("GET", "/api/products/search?q=wireless+headphones"),
        ("POST", "/api/cart/add"),
        ("GET", "/api/cart"),
        ("POST", "/api/checkout/shipping"),
        ("GET", "/api/categories"),
        ("GET", "/api/reviews/product/101")
    ]
    benign_ips = [
        ("192.168.1.105", "United States"),
        ("172.56.21.90", "United States"),
        ("82.165.197.1", "Germany"),
        ("86.12.99.41", "United Kingdom"),
        ("114.119.160.2", "Singapore"),
        ("14.161.45.8", "Vietnam")
    ]
    
    while True:
        try:
            # 1. Update live system metrics
            metrics = memory_store.get_live_metrics()
            
            # 2. Simulate 1-2 realistic benign shoppers browsing store
            method, path = random.choice(benign_endpoints)
            ip, country = random.choice(benign_ips)
            packet = {
                "id": os.urandom(4).hex(),
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "ip": ip,
                "country": country,
                "method": method,
                "path": path,
                "status": 200,
                "action": "allowed",
                "threat_type": "normal",
                "risk_score": round(random.uniform(0.04, 0.18), 2)
            }
            memory_store.record_traffic(packet)
            db.log_traffic(ip, method, path, 200, False, packet["risk_score"])
            
            # 3. Broadcast metrics and traffic update to all connected WebSocket clients
            await memory_store.broadcast({
                "type": "METRICS_UPDATE",
                "metrics": metrics,
                "traffic_packet": packet
            })
            
            await asyncio.sleep(2.0)
        except asyncio.CancelledError:
            break
        except Exception as e:
            await asyncio.sleep(2.0)

def seed_initial_demo_alerts():
    """Seeds baseline alerts matching the design specification wireframe."""
    existing = db.get_recent_alerts(limit=5)
    if existing:
        return

    # Seed SQL injection alert from 198.51.100.23 (Russia)
    sqli_guide = get_remediation_guide("sql_injection")
    sqli_alert = AlertItem(
        id="alert_sqli_01",
        timestamp="2026-11-21T12:20:15Z",
        severity=SeverityLevel.CRITICAL,
        threat_type=ThreatType.SQL_INJECTION,
        source_ip="198.51.100.23",
        country="Russia",
        target="/api/products?category=electronics",
        status=ThreatStatus.BLOCKED,
        risk_score=0.94,
        description="SQL injection attempt blocked from 198.51.100.23",
        payload="' OR 1=1; DROP TABLE users; --",
        attack_vector="URL parameter manipulation",
        details={"matched_patterns": ["OR 1=1", "DROP TABLE", "--"], "user_agent": "Mozilla/5.0"},
        remediation=sqli_guide
    )
    db.insert_alert(sqli_alert)
    memory_store.record_alert(sqli_alert.model_dump())
    db.block_ip("198.51.100.23", reason="SQL injection attempt: ' OR 1=1; DROP TABLE users; --", duration_hours=24)

    # Seed Brute Force alert from 203.0.113.45 (China)
    bf_guide = get_remediation_guide("brute_force")
    bf_alert = AlertItem(
        id="alert_bf_02",
        timestamp="2026-11-21T12:22:47Z",
        severity=SeverityLevel.WARNING,
        threat_type=ThreatType.BRUTE_FORCE,
        source_ip="203.0.113.45",
        country="China",
        target="/api/auth/login",
        status=ThreatStatus.BLOCKED,
        risk_score=0.78,
        description="Brute force attempt from 203.0.113.45 (blocked)",
        payload='{"username": "admin", "password": "*****"}',
        attack_vector="Repeated failed logins (12 attempts in 60s)",
        details={"failed_attempts": 12},
        remediation=bf_guide
    )
    db.insert_alert(bf_alert)
    memory_store.record_alert(bf_alert.model_dump())
    db.block_ip("203.0.113.45", reason="Credential stuffing brute force attack", duration_hours=24)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup:
    initialize_auth()
    seed_initial_demo_alerts()
    task = asyncio.create_task(background_metrics_stream())
    yield
    # Shutdown:
    task.cancel()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Real-time AI-powered security monitoring system for e-commerce platforms",
    lifespan=lifespan
)

# CORS — allow local dev + Render-hosted frontend (and any custom domain via env var)
_frontend_origin = os.environ.get("FRONTEND_URL", "https://sentinel-ai-frontend-a1s0.onrender.com")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8000",
        _frontend_origin,
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(dashboard_router, prefix=settings.API_PREFIX)
app.include_router(alerts_router, prefix=settings.API_PREFIX)
app.include_router(security_router, prefix=settings.API_PREFIX)
app.include_router(traffic_router, prefix=settings.API_PREFIX)
app.include_router(simulator_router, prefix=settings.API_PREFIX)
app.include_router(integrations_router, prefix=settings.API_PREFIX)
app.include_router(auth_router, prefix=settings.API_PREFIX)


@app.middleware("http")
async def require_dashboard_login(request, call_next):
    path = request.url.path
    is_auth_route = path.startswith(f"{settings.API_PREFIX}/auth/")
    is_site_telemetry = path.startswith(f"{settings.API_PREFIX}/integrations/") and path.endswith("/events") and request.method == "POST"
    if request.method != "OPTIONS" and path.startswith(f"{settings.API_PREFIX}/") and not is_auth_route and not is_site_telemetry:
        authorization = request.headers.get("authorization", "")
        token = authorization[7:].strip() if authorization.lower().startswith("bearer ") else request.cookies.get(COOKIE_NAME)
        user = get_session_user(token)
        if not user:
            return JSONResponse({"detail": "Sign in to access Sentinel AI."}, status_code=401)
        request.state.user = user
    return await call_next(request)

# Real-time WebSocket connection
@app.websocket("/ws/stream")
async def websocket_stream_endpoint(websocket: WebSocket):
    offered_protocols = [item.strip() for item in websocket.headers.get("sec-websocket-protocol", "").split(",")]
    auth_protocol = next((item for item in offered_protocols if item.startswith("sentinel-auth-")), None)
    token = auth_protocol.removeprefix("sentinel-auth-") if auth_protocol else websocket.cookies.get(COOKIE_NAME)
    if not get_session_user(token):
        await websocket.close(code=4401, reason="Sign in required")
        return
    await memory_store.connect_ws(websocket, subprotocol=auth_protocol)
    try:
        # Send initial snapshot immediately upon connection
        metrics = memory_store.get_live_metrics()
        recent_traffic = list(memory_store.recent_traffic)[:20]
        recent_alerts = db.get_recent_alerts(limit=20)
        await websocket.send_json({
            "type": "INITIAL_SNAPSHOT",
            "metrics": metrics,
            "recent_traffic": recent_traffic,
            "recent_alerts": recent_alerts
        })
        
        while True:
            # Keep socket alive and accept ping/pong or client commands
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        memory_store.disconnect_ws(websocket)
    except Exception:
        memory_store.disconnect_ws(websocket)

# Serve Frontend static assets if built
frontend_dist = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
)
if os.path.exists(frontend_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dist, "assets")), name="assets")

    @app.get("/")
    async def serve_root():
        index_file = os.path.join(frontend_dist, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "Sentinel AI API running."}

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api") or full_path.startswith("ws"):
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="API route not found")
        file_path = os.path.join(frontend_dist, full_path)
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return FileResponse(file_path)
        index_file = os.path.join(frontend_dist, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "Sentinel AI UI loading."}

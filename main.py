"""
Mobile API Vulnerability Scanner
Basé sur OWASP Mobile Top 10 & OWASP API Security Top 10
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import uuid
import asyncio
from datetime import datetime
from pathlib import Path

from scanner.api_scanner import APIScanner
from engine.vulnerability_engine import VulnerabilityEngine
from reports.report_generator import ReportGenerator
from models import ScanRequest, ScanResult, ScanStatus

app = FastAPI(
    title="Mobile API Vulnerability Scanner",
    description="Scanner automatisé de vulnérabilités pour APIs mobiles - OWASP",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Montage des fichiers statiques
app.mount("/static", StaticFiles(directory="static"), name="static")

# Stockage en mémoire des scans (en prod: utiliser Redis/DB)
scan_jobs = {}

@app.get("/", response_class=HTMLResponse)
async def root():
    """Interface web principale"""
    html_path = Path("templates/index.html")
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))

@app.post("/api/scan", response_model=dict)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Lance un scan de vulnérabilités sur une API mobile"""
    scan_id = str(uuid.uuid4())
    scan_jobs[scan_id] = {
        "status": "pending",
        "created_at": datetime.now().isoformat(),
        "target": request.target_url,
        "progress": 0,
        "results": None
    }
    background_tasks.add_task(run_scan, scan_id, request)
    return {"scan_id": scan_id, "status": "started", "message": "Scan lancé avec succès"}

@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Récupère le statut d'un scan"""
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    job = scan_jobs[scan_id]
    return {
        "scan_id": scan_id,
        "status": job["status"],
        "progress": job["progress"],
        "created_at": job["created_at"],
        "target": job["target"]
    }

@app.get("/api/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Récupère les résultats complets d'un scan"""
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    job = scan_jobs[scan_id]
    if job["status"] != "completed":
        raise HTTPException(status_code=202, detail=f"Scan en cours: {job['status']}")
    return job["results"]

@app.get("/api/scan/{scan_id}/report")
async def download_report(scan_id: str, format: str = "html"):
    """Télécharge le rapport de vulnérabilités"""
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail="Scan non trouvé")
    job = scan_jobs[scan_id]
    if job["status"] != "completed":
        raise HTTPException(status_code=202, detail="Scan non terminé")

    generator = ReportGenerator()
    report_path = generator.generate(scan_id, job["results"], format=format)
    return FileResponse(
        report_path,
        filename=f"vulnerability_report_{scan_id[:8]}.{format}",
        media_type="text/html" if format == "html" else "application/json"
    )

@app.get("/api/scans")
async def list_scans():
    """Liste tous les scans effectués"""
    return [
        {"scan_id": sid, "status": job["status"], "target": job["target"], "created_at": job["created_at"]}
        for sid, job in scan_jobs.items()
    ]

@app.get("/api/vulnerabilities/owasp")
async def get_owasp_list():
    """Retourne la liste des vulnérabilités OWASP Mobile Top 10"""
    from engine.owasp_rules import OWASP_MOBILE_TOP10, OWASP_API_TOP10
    return {"mobile_top10": OWASP_MOBILE_TOP10, "api_top10": OWASP_API_TOP10}

async def run_scan(scan_id: str, request: ScanRequest):
    """Exécute le scan en arrière-plan"""
    try:
        scan_jobs[scan_id]["status"] = "running"

        # Phase 1: Discovery
        scan_jobs[scan_id]["progress"] = 10
        scanner = APIScanner(request.target_url, request.options)
        endpoints = await scanner.discover_endpoints()

        # Phase 2: Tests de vulnérabilités
        scan_jobs[scan_id]["progress"] = 40
        engine = VulnerabilityEngine()
        vulnerabilities = await engine.analyze(request.target_url, endpoints, request.options)

        # Phase 3: Génération rapport
        scan_jobs[scan_id]["progress"] = 80
        generator = ReportGenerator()
        results = generator.compile_results(scan_id, request.target_url, endpoints, vulnerabilities)

        scan_jobs[scan_id]["progress"] = 100
        scan_jobs[scan_id]["status"] = "completed"
        scan_jobs[scan_id]["results"] = results
        scan_jobs[scan_id]["completed_at"] = datetime.now().isoformat()

    except Exception as e:
        scan_jobs[scan_id]["status"] = "failed"
        scan_jobs[scan_id]["error"] = str(e)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

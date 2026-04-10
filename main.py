from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from scanner import CyberSentry
from database import init_db, get_db, ScanHistorico

app = FastAPI(
    title="CyberSentry API",
    description="Scanner de vulnerabilidades web para PMEs",
    version="1.0.0"
)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── INICIALIZA BANCO ──
@app.on_event("startup")
def startup():
    init_db()

# ── MODELOS ──
class ScanRequest(BaseModel):
    url: str

# ── ENDPOINTS ──
@app.get("/")
def root():
    return {"status": "online", "produto": "CyberSentry"}

@app.post("/scan")
def realizar_scan(request: ScanRequest, db: Session = Depends(get_db)):
    valida, motivo = CyberSentry.validar_url(request.url)
    if not valida:
        raise HTTPException(status_code=400, detail=motivo)

    scanner = CyberSentry(request.url)
    resultados = scanner.scan()

    # Salva no banco
    scan = ScanHistorico(
        url=request.url,
        hostname=scanner.hostname,
        resultados=resultados
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    return {
        "id": scan.id,
        "url": scan.url,
        "hostname": scan.hostname,
        "criado_em": scan.criado_em,
        "resultados": resultados
    }

@app.get("/historico")
def listar_historico(db: Session = Depends(get_db)):
    scans = db.query(ScanHistorico).order_by(ScanHistorico.criado_em.desc()).all()
    return [
        {
            "id": s.id,
            "url": s.url,
            "hostname": s.hostname,
            "criado_em": s.criado_em
        }
        for s in scans
    ]

@app.get("/historico/{scan_id}")
def buscar_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanHistorico).filter(ScanHistorico.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    return {
        "id": scan.id,
        "url": scan.url,
        "hostname": scan.hostname,
        "criado_em": scan.criado_em,
        "resultados": scan.resultados
    }
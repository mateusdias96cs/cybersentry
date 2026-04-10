from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scanner import CyberSentry

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

# ── MODELOS ──
class ScanRequest(BaseModel):
    url: str

# ── ENDPOINTS ──
@app.get("/")
def root():
    return {"status": "online", "produto": "CyberSentry"}

@app.post("/scan")
def realizar_scan(request: ScanRequest):
    valida, motivo = CyberSentry.validar_url(request.url)
    if not valida:
        raise HTTPException(status_code=400, detail=motivo)

    scanner = CyberSentry(request.url)
    resultados = scanner.scan()
    return {
        "url": request.url,
        "hostname": scanner.hostname,
        "resultados": resultados
    }
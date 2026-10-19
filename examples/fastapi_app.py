"""Minimal FastAPI app protected by PirelyWebAmilen.

Run:  uvicorn examples.fastapi_app:app --port 8000
"""
from fastapi import FastAPI

from pirelywebamilen import Pirely
from pirelywebamilen.middleware import StarletteShield

app = FastAPI()

shield = Pirely(
    policy="strict",
    allow=["10.0.0.0/8"],
    allow_accounts=["ops"],
    cache_ttl=30,
    audit_path="pwa-audit.jsonl",
)
app.add_middleware(StarletteShield, shield=shield)


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/")
def index():
    return {"hello": "world", "shield": shield.core_status}

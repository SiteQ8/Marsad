"""Marsad API — application entrypoint."""
from __future__ import annotations
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .database import init_db
from .routers import auth as auth_router
from .routers import catalog, findings, dashboard

settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(title=settings.APP_TITLE, version=settings.VERSION, lifespan=lifespan,
              description="Enterprise vulnerability management: asset inventory, "
                          "CVSS-scored findings, remediation workflow with SLAs, "
                          "scanner import and executive dashboards.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["meta"])
def health():
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.VERSION}


app.include_router(auth_router.router)
app.include_router(auth_router.users_router)
app.include_router(catalog.assets)
app.include_router(catalog.vulns)
app.include_router(findings.router)
app.include_router(dashboard.router)

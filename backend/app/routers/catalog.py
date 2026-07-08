from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Asset, Vulnerability, Role
from ..schemas import AssetCreate, AssetOut, VulnCreate, VulnOut
from ..auth import require_role, get_current_user
from ..cvss import base_score, severity_band, CVSSError

assets = APIRouter(prefix="/api/assets", tags=["assets"])
vulns = APIRouter(prefix="/api/vulnerabilities", tags=["vulnerabilities"])


# ── assets ──
@assets.get("", response_model=list[AssetOut])
def list_assets(q: str | None = Query(None), db: Session = Depends(get_db), _=Depends(get_current_user)):
    query = db.query(Asset)
    if q:
        like = f"%{q}%"
        query = query.filter((Asset.name.ilike(like)) | (Asset.ip_address.ilike(like)) | (Asset.hostname.ilike(like)))
    return query.order_by(Asset.criticality.desc(), Asset.name).all()


@assets.post("", response_model=AssetOut, status_code=201)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db), _=Depends(require_role(Role.analyst))):
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@assets.put("/{asset_id}", response_model=AssetOut)
def update_asset(asset_id: int, payload: AssetCreate, db: Session = Depends(get_db), _=Depends(require_role(Role.analyst))):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    for k, v in payload.model_dump().items():
        setattr(asset, k, v)
    db.commit()
    db.refresh(asset)
    return asset


@assets.delete("/{asset_id}", status_code=204)
def delete_asset(asset_id: int, db: Session = Depends(get_db), _=Depends(require_role(Role.admin))):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    db.delete(asset)
    db.commit()


# ── vulnerabilities ──
@vulns.get("", response_model=list[VulnOut])
def list_vulns(q: str | None = Query(None), db: Session = Depends(get_db), _=Depends(get_current_user)):
    query = db.query(Vulnerability)
    if q:
        like = f"%{q}%"
        query = query.filter((Vulnerability.title.ilike(like)) | (Vulnerability.cve_id.ilike(like)))
    return query.order_by(Vulnerability.cvss_score.desc()).all()


@vulns.post("", response_model=VulnOut, status_code=201)
def create_vuln(payload: VulnCreate, db: Session = Depends(get_db), _=Depends(require_role(Role.analyst))):
    data = payload.model_dump()
    score, severity = 0.0, "Info"
    if data.get("cvss_vector"):
        try:
            score = base_score(data["cvss_vector"])
            severity = severity_band(score)
        except CVSSError as e:
            raise HTTPException(422, f"Invalid CVSS vector: {e}")
    vuln = Vulnerability(**data, cvss_score=score, severity=severity)
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln

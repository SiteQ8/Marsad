import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from ..models import Finding, FindingStatus, Comment, ScanImport, Role, User
from ..schemas import (
    FindingCreate, FindingOut, FindingDetail, FindingStatusUpdate,
    CommentCreate, CommentOut,
)
from ..auth import require_role, get_current_user
from ..scoring import is_overdue
from ..services import (
    import_nessus, import_csv, upsert_finding, contextual_risk,
)
from .. import models

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=list[FindingOut])
def list_findings(
    status: FindingStatus | None = None,
    severity: str | None = None,
    asset_id: int | None = None,
    overdue: bool | None = None,
    sort: str = Query("risk", pattern="^(risk|due|first_seen)$"),
    db: Session = Depends(get_db), _=Depends(get_current_user),
):
    query = db.query(Finding).join(Finding.vulnerability)
    if status:
        query = query.filter(Finding.status == status)
    if asset_id:
        query = query.filter(Finding.asset_id == asset_id)
    if severity:
        query = query.filter(models.Vulnerability.severity == severity)
    order = {"risk": Finding.risk_score.desc(), "due": Finding.due_date.asc(),
             "first_seen": Finding.first_seen.desc()}[sort]
    results = query.order_by(order).all()
    if overdue is not None:
        results = [f for f in results if is_overdue(f.status.value, f.due_date) == overdue]
    return results


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: int, db: Session = Depends(get_db), _=Depends(get_current_user)):
    f = (db.query(Finding)
         .options(joinedload(Finding.asset), joinedload(Finding.vulnerability), joinedload(Finding.comments))
         .filter(Finding.id == finding_id).first())
    if not f:
        raise HTTPException(404, "Finding not found")
    out = FindingDetail.model_validate(f)
    out.overdue = is_overdue(f.status.value, f.due_date)
    return out


@router.post("", response_model=FindingOut, status_code=201)
def create_finding(payload: FindingCreate, db: Session = Depends(get_db), _=Depends(require_role(Role.analyst))):
    asset = db.get(models.Asset, payload.asset_id)
    vuln = db.get(models.Vulnerability, payload.vulnerability_id)
    if not asset or not vuln:
        raise HTTPException(404, "Asset or vulnerability not found")
    finding, _created = upsert_finding(db, asset=asset, vuln=vuln, port=payload.port, detail=payload.detail)
    if payload.assigned_to:
        finding.assigned_to = payload.assigned_to
    db.commit()
    db.refresh(finding)
    return finding


@router.patch("/{finding_id}/status", response_model=FindingOut)
def update_status(finding_id: int, payload: FindingStatusUpdate,
                  db: Session = Depends(get_db), user: User = Depends(require_role(Role.analyst))):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    prev = f.status
    f.status = payload.status
    if payload.assigned_to is not None:
        f.assigned_to = payload.assigned_to
    if payload.status in (FindingStatus.remediated, FindingStatus.accepted, FindingStatus.false_positive):
        f.resolved_at = dt.datetime.now(dt.timezone.utc)
    else:
        f.resolved_at = None
    db.add(Comment(finding_id=f.id, author=user.full_name,
                   body=f"Status changed {prev.value} → {payload.status.value}"))
    db.commit()
    db.refresh(f)
    return f


@router.post("/{finding_id}/comments", response_model=CommentOut, status_code=201)
def add_comment(finding_id: int, payload: CommentCreate,
                db: Session = Depends(get_db), user: User = Depends(require_role(Role.analyst))):
    if not db.get(Finding, finding_id):
        raise HTTPException(404, "Finding not found")
    c = Comment(finding_id=finding_id, author=user.full_name, body=payload.body)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@router.post("/import", tags=["import"])
async def import_scan(
    file: UploadFile = File(...),
    db: Session = Depends(get_db), user: User = Depends(require_role(Role.analyst)),
):
    raw = await file.read()
    fname = (file.filename or "scan").lower()
    source = "nessus" if fname.endswith(".nessus") or raw[:200].lstrip().startswith(b"<?xml") else "csv"
    scan = ScanImport(filename=file.filename, source=source, imported_by=user.full_name)
    db.add(scan)
    db.flush()
    try:
        if source == "nessus":
            created, updated = import_nessus(db, raw, scan)
        else:
            created, updated = import_csv(db, raw, scan)
    except Exception as e:  # noqa: BLE001 — surface parse errors cleanly
        db.rollback()
        raise HTTPException(422, f"Import failed: {e}")
    scan.findings_created = created
    scan.findings_updated = updated
    db.commit()
    return {"source": source, "findings_created": created, "findings_updated": updated}

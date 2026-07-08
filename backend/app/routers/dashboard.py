import datetime as dt

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Finding, FindingStatus, Asset, Vulnerability
from ..auth import get_current_user
from ..scoring import is_overdue

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

_OPEN = (FindingStatus.open, FindingStatus.triaged, FindingStatus.in_progress)


@router.get("")
def dashboard(db: Session = Depends(get_db), _=Depends(get_current_user)):
    open_findings = db.query(Finding).join(Finding.vulnerability).filter(Finding.status.in_(_OPEN)).all()

    by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in open_findings:
        by_sev[f.vulnerability.severity] = by_sev.get(f.vulnerability.severity, 0) + 1

    overdue = [f for f in open_findings if is_overdue(f.status.value, f.due_date)]

    # Mean time to remediate (days) over resolved findings.
    resolved = db.query(Finding).filter(Finding.resolved_at.isnot(None)).all()
    mttr = None
    if resolved:
        deltas = [(f.resolved_at - f.first_seen).days for f in resolved
                  if f.resolved_at and f.first_seen]
        if deltas:
            mttr = round(sum(deltas) / len(deltas), 1)

    # Top risk-scored open findings for the leaderboard.
    top = (db.query(Finding).join(Finding.vulnerability)
           .filter(Finding.status.in_(_OPEN))
           .order_by(Finding.risk_score.desc()).limit(10).all())
    top_out = [{
        "id": f.id, "risk_score": f.risk_score,
        "title": f.vulnerability.title, "cve": f.vulnerability.cve_id,
        "severity": f.vulnerability.severity, "asset": f.asset.name,
        "status": f.status.value,
        "overdue": is_overdue(f.status.value, f.due_date),
    } for f in top]

    status_counts = dict(
        db.query(Finding.status, func.count(Finding.id)).group_by(Finding.status).all()
    )

    return {
        "totals": {
            "assets": db.query(func.count(Asset.id)).scalar(),
            "vulnerabilities": db.query(func.count(Vulnerability.id)).scalar(),
            "open_findings": len(open_findings),
            "overdue": len(overdue),
            "mttr_days": mttr,
        },
        "by_severity": by_sev,
        "by_status": {k.value if hasattr(k, "value") else str(k): v for k, v in status_counts.items()},
        "top_risks": top_out,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }

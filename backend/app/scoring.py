"""
Composite (contextual) risk scoring.

Raw CVSS answers "how bad is this vuln in the abstract". Enterprises need
"how bad is this vuln *here*" — a critical CVE on an internet-facing crown-jewel
asset outranks the same CVE on an isolated dev box. Marsad folds asset context
into a 0–100 contextual risk score used for prioritisation and dashboards.
"""
from __future__ import annotations
import datetime as dt

from .config import get_settings

settings = get_settings()

# Multiplier applied to the normalised CVSS by asset criticality (1..4).
_CRIT_WEIGHT = {1: 0.7, 2: 1.0, 3: 1.3, 4: 1.6}


def contextual_risk(cvss_score: float, criticality: int, internet_facing: bool) -> float:
    """Return a 0–100 contextual risk score."""
    base = (cvss_score / 10.0) * 100.0
    score = base * _CRIT_WEIGHT.get(criticality, 1.0)
    if internet_facing:
        score *= 1.25
    return round(min(score, 100.0), 1)


def sla_due_date(severity: str, first_seen: dt.datetime) -> dt.datetime:
    """Compute the remediation due date from severity-based SLA."""
    days = settings.SLA_DAYS.get(severity, 90)
    return first_seen + dt.timedelta(days=days)


def is_overdue(finding_status: str, due_date: dt.datetime | None) -> bool:
    if due_date is None or finding_status in ("remediated", "accepted", "false_positive"):
        return False
    now = dt.datetime.now(dt.timezone.utc)
    if due_date.tzinfo is None:
        due_date = due_date.replace(tzinfo=dt.timezone.utc)
    return now > due_date

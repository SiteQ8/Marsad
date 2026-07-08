"""
Scanner ingestion + shared finding service.

Supports:
  * Nessus (.nessus XML export from Tenable Nessus / Tenable.io)
  * Generic CSV (host, ip, cve, name, cvss_vector, port, severity ...)

Both funnel into `upsert_finding`, which de-duplicates on (asset, vulnerability,
port) so re-importing a later scan updates last_seen rather than creating dupes.
"""
from __future__ import annotations
import csv
import datetime as dt
import io
import xml.etree.ElementTree as ET
from typing import Optional

from sqlalchemy.orm import Session

from . import models
from .cvss import base_score, severity_band, CVSSError
from .scoring import contextual_risk, sla_due_date


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def get_or_create_asset(db: Session, *, name: str, ip: str | None,
                        internet_facing: bool = False, criticality: int = 2) -> models.Asset:
    q = db.query(models.Asset)
    asset = None
    if ip:
        asset = q.filter(models.Asset.ip_address == ip).first()
    if not asset:
        asset = q.filter(models.Asset.name == name).first()
    if not asset:
        asset = models.Asset(name=name or ip or "unknown", ip_address=ip,
                             hostname=name, internet_facing=internet_facing,
                             criticality=criticality)
        db.add(asset)
        db.flush()
    return asset


def get_or_create_vuln(db: Session, *, cve: str | None, title: str,
                       vector: str | None, description: str = "",
                       remediation: str = "", fallback_severity: str | None = None) -> models.Vulnerability:
    vuln = None
    if cve:
        vuln = db.query(models.Vulnerability).filter(models.Vulnerability.cve_id == cve).first()
    if not vuln:
        vuln = db.query(models.Vulnerability).filter(models.Vulnerability.title == title).first()
    if vuln:
        return vuln

    score, severity = 0.0, (fallback_severity or "Info")
    if vector:
        try:
            score = base_score(vector)
            severity = severity_band(score)
        except CVSSError:
            vector = None
    vuln = models.Vulnerability(cve_id=cve, title=title, description=description,
                               cvss_vector=vector, cvss_score=score, severity=severity,
                               remediation=remediation)
    db.add(vuln)
    db.flush()
    return vuln


def upsert_finding(db: Session, *, asset: models.Asset, vuln: models.Vulnerability,
                   port: Optional[str] = None, detail: str = "",
                   scan_import_id: int | None = None) -> tuple[models.Finding, bool]:
    """Create or refresh a finding. Returns (finding, created?)."""
    existing = (db.query(models.Finding)
                .filter(models.Finding.asset_id == asset.id,
                        models.Finding.vulnerability_id == vuln.id,
                        models.Finding.port == port)
                .first())
    risk = contextual_risk(vuln.cvss_score, asset.criticality, asset.internet_facing)
    if existing:
        existing.last_seen = _now()
        existing.risk_score = risk
        if existing.status == models.FindingStatus.remediated:
            existing.status = models.FindingStatus.open  # reappeared -> reopen
            existing.resolved_at = None
        return existing, False

    now = _now()
    finding = models.Finding(
        asset_id=asset.id, vulnerability_id=vuln.id, port=port, detail=detail,
        risk_score=risk, first_seen=now, last_seen=now,
        due_date=sla_due_date(vuln.severity, now), scan_import_id=scan_import_id,
    )
    db.add(finding)
    db.flush()
    return finding, True


# ── Nessus ────────────────────────────────────
def import_nessus(db: Session, xml_bytes: bytes, scan_import: models.ScanImport) -> tuple[int, int]:
    root = ET.fromstring(xml_bytes)
    created = updated = 0
    for host in root.iter("ReportHost"):
        host_name = host.get("name", "unknown")
        ip = None
        for tag in host.iter("tag"):
            if tag.get("name") == "host-ip":
                ip = (tag.text or "").strip()
        asset = get_or_create_asset(db, name=host_name, ip=ip or host_name)
        for item in host.iter("ReportItem"):
            severity = int(item.get("severity", "0"))
            if severity == 0:
                continue  # skip informational plugins
            cve_el = item.find("cve")
            cve = cve_el.text.strip() if cve_el is not None and cve_el.text else None
            vector = None
            v = item.find("cvss3_vector") or item.find("cvss_vector")
            if v is not None and v.text:
                vector = v.text.strip()
                if not vector.upper().startswith("CVSS") and "/" in vector:
                    vector = "CVSS:3.1/" + vector
            title = item.get("pluginName", "Unnamed plugin")
            desc = (item.findtext("description") or "").strip()
            remediation = (item.findtext("solution") or "").strip()
            vuln = get_or_create_vuln(db, cve=cve, title=title, vector=vector,
                                      description=desc, remediation=remediation,
                                      fallback_severity=["Info", "Low", "Medium", "High", "Critical"][min(severity, 4)])
            _, is_new = upsert_finding(db, asset=asset, vuln=vuln,
                                       port=item.get("port"), detail=desc[:500],
                                       scan_import_id=scan_import.id)
            created += is_new
            updated += (not is_new)
    return created, updated


# ── CSV ───────────────────────────────────────
def import_csv(db: Session, csv_bytes: bytes, scan_import: models.ScanImport) -> tuple[int, int]:
    text = csv_bytes.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    created = updated = 0
    for row in reader:
        r = { (k or "").strip().lower(): (v or "").strip() for k, v in row.items() }
        name = r.get("host") or r.get("hostname") or r.get("name") or r.get("ip") or "unknown"
        ip = r.get("ip") or r.get("ip_address")
        asset = get_or_create_asset(db, name=name, ip=ip)
        vector = r.get("cvss_vector") or r.get("vector") or None
        if vector and not vector.upper().startswith("CVSS") and "/" in vector:
            vector = "CVSS:3.1/" + vector
        vuln = get_or_create_vuln(
            db, cve=r.get("cve") or None,
            title=r.get("name") or r.get("title") or r.get("plugin") or "Imported finding",
            vector=vector, description=r.get("description", ""),
            remediation=r.get("remediation", "") or r.get("solution", ""),
            fallback_severity=(r.get("severity") or "Info").capitalize(),
        )
        _, is_new = upsert_finding(db, asset=asset, vuln=vuln, port=r.get("port") or None,
                                   detail=r.get("description", "")[:500], scan_import_id=scan_import.id)
        created += is_new
        updated += (not is_new)
    return created, updated

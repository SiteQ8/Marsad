"""
Domain model for Marsad.

Entities:
  User          — an operator with a role (admin / analyst / viewer)
  Asset         — a tracked host, application, service or device
  Vulnerability — a catalog entry (a CVE / plugin), scored once with CVSS
  Finding       — a Vulnerability observed on a specific Asset (the unit of work)
  Comment       — remediation notes / audit trail on a Finding
  ScanImport    — a record of an ingested scanner file
"""
from __future__ import annotations
import datetime as dt
import enum

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, Float, Enum, Boolean,
)
from sqlalchemy.orm import relationship

from .database import Base


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Role(str, enum.Enum):
    admin = "admin"      # manage users + everything below
    analyst = "analyst"  # create/import/triage findings, run remediation
    viewer = "viewer"    # read-only (execs, auditors)


class FindingStatus(str, enum.Enum):
    open = "open"
    triaged = "triaged"
    in_progress = "in_progress"
    remediated = "remediated"
    accepted = "accepted"       # risk formally accepted
    false_positive = "false_positive"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(Role), default=Role.viewer, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, index=True)
    hostname = Column(String(255))
    ip_address = Column(String(64), index=True)
    asset_type = Column(String(64), default="Server")
    environment = Column(String(32), default="production")   # production/staging/dev
    business_unit = Column(String(128))
    owner = Column(String(128))
    # Criticality drives risk prioritisation on top of raw CVSS: 1 (low) .. 4 (critical)
    criticality = Column(Integer, default=2)
    internet_facing = Column(Boolean, default=False)
    tags = Column(String(512), default="")
    created_at = Column(DateTime, default=utcnow)

    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(32), index=True)            # e.g. CVE-2024-3400 (nullable)
    title = Column(String(512), nullable=False)
    description = Column(Text, default="")
    cvss_vector = Column(String(128))
    cvss_score = Column(Float, default=0.0)
    severity = Column(String(16), default="Info")
    remediation = Column(Text, default="")
    references = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow)

    findings = relationship("Finding", back_populates="vulnerability")


class Finding(Base):
    """A vulnerability instance on an asset — the atomic unit of remediation work."""
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)

    status = Column(Enum(FindingStatus), default=FindingStatus.open, nullable=False, index=True)
    port = Column(String(32))
    detail = Column(Text, default="")
    assigned_to = Column(String(128))

    # Composite risk score: CVSS weighted by asset criticality & exposure (0–100).
    risk_score = Column(Float, default=0.0, index=True)

    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)
    due_date = Column(DateTime)             # first_seen + SLA(severity)
    resolved_at = Column(DateTime)
    scan_import_id = Column(Integer, ForeignKey("scan_imports.id"))

    asset = relationship("Asset", back_populates="findings")
    vulnerability = relationship("Vulnerability", back_populates="findings")
    comments = relationship("Comment", back_populates="finding", cascade="all, delete-orphan")


class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)
    author = Column(String(128))
    body = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow)

    finding = relationship("Finding", back_populates="comments")


class ScanImport(Base):
    __tablename__ = "scan_imports"
    id = Column(Integer, primary_key=True)
    filename = Column(String(255))
    source = Column(String(64))            # nessus / csv / openvas
    findings_created = Column(Integer, default=0)
    findings_updated = Column(Integer, default=0)
    imported_by = Column(String(128))
    created_at = Column(DateTime, default=utcnow)

"""Pydantic v2 schemas — the API contract."""
from __future__ import annotations
import datetime as dt
from typing import Optional

from pydantic import BaseModel, EmailStr, ConfigDict, Field

from .models import Role, FindingStatus


# ── auth / users ──────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    full_name: str


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str
    password: str = Field(min_length=8)
    role: Role = Role.viewer


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: EmailStr
    full_name: str
    role: Role
    is_active: bool


# ── assets ────────────────────────────────────
class AssetBase(BaseModel):
    name: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    asset_type: str = "Server"
    environment: str = "production"
    business_unit: Optional[str] = None
    owner: Optional[str] = None
    criticality: int = Field(default=2, ge=1, le=4)
    internet_facing: bool = False
    tags: str = ""


class AssetCreate(AssetBase):
    pass


class AssetOut(AssetBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: dt.datetime


# ── vulnerabilities ───────────────────────────
class VulnBase(BaseModel):
    cve_id: Optional[str] = None
    title: str
    description: str = ""
    cvss_vector: Optional[str] = None
    remediation: str = ""
    references: str = ""


class VulnCreate(VulnBase):
    pass


class VulnOut(VulnBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
    cvss_score: float
    severity: str


# ── findings ──────────────────────────────────
class FindingCreate(BaseModel):
    asset_id: int
    vulnerability_id: int
    port: Optional[str] = None
    detail: str = ""
    assigned_to: Optional[str] = None


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    assigned_to: Optional[str] = None


class CommentCreate(BaseModel):
    body: str


class CommentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    author: Optional[str]
    body: str
    created_at: dt.datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    asset_id: int
    vulnerability_id: int
    status: FindingStatus
    port: Optional[str]
    detail: str
    assigned_to: Optional[str]
    risk_score: float
    first_seen: dt.datetime
    due_date: Optional[dt.datetime]
    resolved_at: Optional[dt.datetime]


class FindingDetail(FindingOut):
    asset: AssetOut
    vulnerability: VulnOut
    comments: list[CommentOut] = []
    overdue: bool = False

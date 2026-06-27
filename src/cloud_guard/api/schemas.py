import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr

from cloud_guard.models.entities import Role, ScanStatus, Severity


class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Role = Role.VIEWER


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    role: Role
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class ScanCreate(BaseModel):
    provider: str
    compliance_framework: str | None = None


class ScanResponse(BaseModel):
    id: uuid.UUID
    provider: str
    compliance_framework: str | None
    status: ScanStatus
    created_at: datetime
    completed_at: datetime | None
    total_findings: int
    critical_count: int
    high_count: int

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: uuid.UUID
    rule_id: str
    title: str
    description: str
    severity: Severity
    resource_type: str
    resource_id: str
    region: str | None
    remediation: str | None
    compliance_control: str | None
    is_resolved: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class DashboardStats(BaseModel):
    total_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    compliance_score: float
    findings_by_provider: dict[str, int]
    findings_by_severity: dict[str, int]
    recent_scans: list[ScanResponse]

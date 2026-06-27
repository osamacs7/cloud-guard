import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from cloud_guard.api.dependencies import get_current_user, require_role
from cloud_guard.api.schemas import FindingResponse, ScanCreate, ScanResponse
from cloud_guard.models.database import get_db
from cloud_guard.models.entities import Finding, Role, Scan, ScanStatus, User
from cloud_guard.scanners.registry import scanner_registry

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_role(Role.ADMIN, Role.AUDITOR)),
):
    if payload.provider not in scanner_registry:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {payload.provider}")

    scan = Scan(
        provider=payload.provider,
        compliance_framework=payload.compliance_framework,
        created_by=user.id,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


@router.get("/", response_model=list[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 20,
    status_filter: ScanStatus | None = None,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    query = select(Scan).order_by(Scan.created_at.desc()).offset(skip).limit(limit)
    if status_filter:
        query = query.where(Scan.status == status_filter)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/findings", response_model=list[FindingResponse])
async def get_scan_findings(
    scan_id: uuid.UUID,
    severity: str | None = None,
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    query = select(Finding).where(Finding.scan_id == scan_id).offset(skip).limit(limit)
    if severity:
        query = query.where(Finding.severity == severity)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats/summary")
async def scan_stats(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    total = await db.execute(select(func.count(Scan.id)))
    findings_total = await db.execute(select(func.count(Finding.id)))
    critical = await db.execute(
        select(func.count(Finding.id)).where(Finding.severity == "critical")
    )

    return {
        "total_scans": total.scalar() or 0,
        "total_findings": findings_total.scalar() or 0,
        "critical_findings": critical.scalar() or 0,
    }

import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from services.db import get_db
from schemas.finding import FindingResponse, FindingSummary, FindingListResponse
from models.finding import Finding

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/findings", tags=["findings"])

ALLOWED_SORT_COLS = {"severity", "confidence", "rule_id", "source", "created_at"}


@router.get("", response_model=FindingListResponse)
async def list_findings(
    scan_id: str = Query(None),
    app_id: str = Query(None),
    severity: str = Query(None),
    source: str = Query(None),
    rule_id: str = Query(None),
    validated: bool = Query(None),
    search: str = Query(None, max_length=200),
    min_confidence: int = Query(None),
    sort_by: str = Query("severity"),
    order: str = Query("desc"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    conditions = []
    if scan_id:
        conditions.append(Finding.scan_id == scan_id)
    if app_id:
        conditions.append(Finding.app_id == app_id)
    if severity:
        sevs = [s.strip().upper() for s in severity.split(",") if s.strip().upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
        if sevs:
            conditions.append(Finding.severity.in_(sevs))
    if source:
        conditions.append(Finding.source == source)
    if rule_id:
        conditions.append(Finding.rule_id.ilike(f"%{rule_id}%"))
    if validated is not None:
        conditions.append(Finding.validated == validated)
    if search:
        conditions.append(
            Finding.title.ilike(f"%{search}%")
            | Finding.rule_id.ilike(f"%{search}%")
            | Finding.description.ilike(f"%{search}%")
        )
    if min_confidence is not None:
        conditions.append(Finding.confidence >= min_confidence)

    base_query = select(Finding).where(and_(*conditions)) if conditions else select(Finding)
    count_query = select(func.count(Finding.id)).where(and_(*conditions)) if conditions else select(func.count(Finding.id))

    result = await db.execute(count_query)
    total = result.scalar()

    if sort_by not in ALLOWED_SORT_COLS:
        sort_by = "severity"
    sort_col = getattr(Finding, sort_by)
    order_func = sort_col.desc() if order == "desc" else sort_col.asc()
    query = base_query.order_by(order_func).offset(offset).limit(limit)

    result = await db.execute(query)
    findings = result.scalars().all()

    return FindingListResponse(
        findings=[
            FindingResponse(
                id=str(f.id),
                scan_id=str(f.scan_id),
                app_id=str(f.app_id),
                rule_id=f.rule_id,
                rule_group=f.rule_group,
                title=f.title,
                description=f.description,
                severity=f.severity,
                original_sev=f.original_sev,
                category=f.category,
                source=f.source,
                confidence=f.confidence,
                validated=f.validated,
                poc_command=f.poc_command,
                poc_vector=f.poc_vector,
                impact=f.impact,
                recommendation=f.recommendation,
                location=f.location,
                escalation_rule=f.escalation_rule,
                sectors=f.sectors,
                raw_data=f.raw_data,
                created_at=f.created_at,
            )
            for f in findings
        ],
        total=total or 0,
    )


@router.get("/summary", response_model=FindingSummary)
async def get_summary(
    scan_id: str = Query(None),
    app_id: str = Query(None),
    db: AsyncSession = Depends(get_db),
):
    conditions = []
    if scan_id:
        conditions.append(Finding.scan_id == scan_id)
    if app_id:
        conditions.append(Finding.app_id == app_id)

    base = and_(*conditions) if conditions else True

    count_result = await db.execute(select(func.count(Finding.id)).where(base))
    total = count_result.scalar() or 0

    sev_rows = await db.execute(
        select(Finding.severity, func.count(Finding.id)).where(base).group_by(Finding.severity)
    )
    sevs = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for row in sev_rows:
        sevs[row[0]] = row[1]

    sources_q = await db.execute(
        select(Finding.source, func.count(Finding.id)).where(base).group_by(Finding.source)
    )
    by_source = {row[0] or "unknown": row[1] for row in sources_q}

    groups_q = await db.execute(
        select(Finding.rule_group, func.count(Finding.id)).where(base).group_by(Finding.rule_group)
    )
    by_group = {row[0] or "unknown": row[1] for row in groups_q}

    return FindingSummary(
        total=total,
        by_severity=sevs,
        by_source=by_source,
        by_rule_group=by_group,
    )


@router.get("/chains")
async def get_chains(
    scan_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    from models.exploit_chain import ExploitChain
    result = await db.execute(
        select(ExploitChain).where(ExploitChain.scan_id == scan_id)
    )
    chains = result.scalars().all()
    return [
        {
            "id": str(c.id),
            "scan_id": str(c.scan_id),
            "title": c.title,
            "severity": c.severity,
            "validated": c.validated,
            "steps": c.steps,
            "poc_sequence": c.poc_sequence,
            "created_at": c.created_at,
        }
        for c in chains
    ]


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(404, detail="Finding not found")
    return FindingResponse(
        id=str(finding.id),
        scan_id=str(finding.scan_id),
        app_id=str(finding.app_id),
        rule_id=finding.rule_id,
        rule_group=finding.rule_group,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        original_sev=finding.original_sev,
        category=finding.category,
        source=finding.source,
        confidence=finding.confidence,
        validated=finding.validated,
        poc_command=finding.poc_command,
        poc_vector=finding.poc_vector,
        impact=finding.impact,
        recommendation=finding.recommendation,
        location=finding.location,
        escalation_rule=finding.escalation_rule,
        sectors=finding.sectors,
        raw_data=finding.raw_data,
        created_at=finding.created_at,
    )

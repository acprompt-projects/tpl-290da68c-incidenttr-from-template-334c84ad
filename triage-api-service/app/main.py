import hashlib
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("triage-api")

app = FastAPI(title="Incident Triage Service", version="1.0.0")

# ---------------------------------------------------------------------------
# Pydantic Models
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class IncidentStatus(str, Enum):
    open = "open"
    triaging = "triaging"
    acknowledged = "acknowledged"
    resolved = "resolved"

class AlertPayload(BaseModel):
    source: str = Field(..., description="Origin system e.g. 'rules-engine'")
    title: str = Field(..., max_length=512)
    description: str = Field("", max_length=4096)
    labels: dict[str, str] = Field(default_factory=dict)
    severity_hint: Optional[Severity] = None
    dedup_key: Optional[str] = Field(None, description="Client-supplied dedup key")

class TriageUpdate(BaseModel):
    severity: Optional[Severity] = None
    status: Optional[IncidentStatus] = None
    assignee: Optional[str] = None
    notes: Optional[str] = None

class IncidentOut(BaseModel):
    id: str
    fingerprint: str
    source: str
    title: str
    description: str
    labels: dict[str, str]
    severity: Severity
    status: IncidentStatus
    assignee: Optional[str]
    notes: Optional[str]
    alert_count: int
    created_at: datetime
    updated_at: datetime

# ---------------------------------------------------------------------------
# In-memory store (replace with DB in production)
# ---------------------------------------------------------------------------

_incidents: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fingerprint(alert: AlertPayload) -> str:
    if alert.dedup_key:
        return alert.dedup_key
    raw = f"{alert.source}|{alert.title}|{'|'.join(sorted(alert.labels.items()))}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def _classify_severity(alert: AlertPayload) -> Severity:
    if alert.severity_hint:
        return alert.severity_hint
    title_lower = alert.title.lower()
    if any(w in title_lower for w in ("outage", "down", "data loss")):
        return Severity.critical
    if any(w in title_lower for w in ("degraded", "error spike", "slo breach")):
        return Severity.high
    if any(w in title_lower for w in ("warning", "latency", "retry")):
        return Severity.medium
    return Severity.low

async def _notify_slack(incident: dict) -> None:
    webhook = "https://hooks.slack.com/services/TRIAGE_DUMMY"
    payload = {
        "text": (
            f":rotating_light: *Incident {incident['id']}*\n"
            f"> *Severity:* {incident['severity']}\n"
            f"> *Title:* {incident['title']}\n"
            f"> *Source:* {incident['source']}"
        )
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(webhook, json=payload)
        logger.info("Slack notification sent for %s", incident["id"])
    except Exception:
        logger.warning("Slack notification failed for %s", incident["id"])

async def _notify_pagerduty(incident: dict) -> None:
    if incident["severity"] not in (Severity.critical, Severity.high):
        return
    url = "https://events.pagerduty.com/v2/enqueue"
    payload = {
        "routing_key": "TRIAGE_PD_KEY",
        "event_action": "trigger",
        "payload": {
            "summary": incident["title"],
            "severity": incident["severity"],
            "source": incident["source"],
            "timestamp": incident["created_at"].isoformat(),
        },
    }
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(url, json=payload)
        logger.info("PagerDuty notification sent for %s", incident["id"])
    except Exception:
        logger.warning("PagerDuty notification failed for %s", incident["id"])

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/incidents", response_model=IncidentOut, status_code=201)
async def submit_incident(alert: AlertPayload):
    fp = _fingerprint(alert)
    now = datetime.now(timezone.utc)

    # Deduplicate / correlate
    for inc in _incidents.values():
        if inc["fingerprint"] == fp and inc["status"] != IncidentStatus.resolved:
            inc["alert_count"] += 1
            inc["updated_at"] = now
            if alert.severity_hint and Severity[alert.severity_hint].value < Severity[inc["severity"]].value:
                pass  # keep higher severity
            elif alert.severity_hint:
                inc["severity"] = alert.severity_hint
            logger.info("Correlated alert to existing incident %s (count=%d)", inc["id"], inc["alert_count"])
            return inc

    inc_id = f"INC-{fp[:8].upper()}"
    severity = _classify_severity(alert)
    incident = {
        "id": inc_id,
        "fingerprint": fp,
        "source": alert.source,
        "title": alert.title,
        "description": alert.description,
        "labels": alert.labels,
        "severity": severity,
        "status": IncidentStatus.open,
        "assignee": None,
        "notes": None,
        "alert_count": 1,
        "created_at": now,
        "updated_at": now,
    }
    _incidents[inc_id] = incident
    await _notify_slack(incident)
    await _notify_pagerduty(incident)
    return incident

@app.get("/incidents/{incident_id}", response_model=IncidentOut)
async def get_incident(incident_id: str):
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@app.patch("/incidents/{incident_id}/triage", response_model=IncidentOut)
async def update_triage(incident_id: str, update: TriageUpdate):
    incident = _incidents.get(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    if incident["status"] == IncidentStatus.resolved:
        raise HTTPException(status_code=409, detail="Cannot triage a resolved incident")

    if update.severity:
        incident["severity"] = update.severity
    if update.status:
        incident["status"] = update.status
    if update.assignee:
        incident["assignee"] = update.assignee
    if update.notes:
        incident["notes"] = update.notes
    incident["updated_at"] = datetime.now(timezone.utc)

    if update.status == IncidentStatus.acknowledged and incident["severity"] in (Severity.critical, Severity.high):
        try:
            url = "https://events.pagerduty.com/v2/enqueue"
            async with httpx.AsyncClient(timeout=5) as client:
                await client.post(url, json={
                    "routing_key": "TRIAGE_PD_KEY",
                    "event_action": "acknowledge",
                    "dedup_key": incident["id"],
                })
        except Exception:
            logger.warning("PagerDuty ack failed for %s", incident_id)

    return incident

@app.get("/health")
async def health():
    return {"status": "ok", "incidents_tracked": len(_incidents)}
import logging
from typing import Optional

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from dispatcher import (
    NotificationDispatcher, Incident, Severity, Channel,
    RoutingRule, RateLimit, DEFAULT_ROUTING_RULES, DEFAULT_RATE_LIMITS,
)

logger = logging.getLogger("notification-dispatcher-api")

app = FastAPI(title="Notification Dispatcher", version="0.1.0")

_dispatcher: Optional[NotificationDispatcher] = None


class IncidentPayload(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    metadata: dict = Field(default_factory=dict)
    dedup_key: Optional[str] = None


class DispatchResponse(BaseModel):
    incident_id: str
    channels: dict[str, bool]


@app.on_event("startup")
async def startup():
    global _dispatcher
    import os
    _dispatcher = NotificationDispatcher(
        slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL", ""),
        pagerduty_key=os.getenv("PAGERDUTY_INTEGRATION_KEY", ""),
        email_config=_build_email_config() if os.getenv("SMTP_HOST") else None,
    )
    logger.info("NotificationDispatcher initialized with channels: %s", list(_dispatcher._notifiers.keys()))


def _build_email_config() -> dict:
    import os
    return {
        "smtp_host": os.getenv("SMTP_HOST", "localhost"),
        "smtp_port": int(os.getenv("SMTP_PORT", "587")),
        "sender": os.getenv("EMAIL_SENDER", "incidents@example.com"),
        "recipients": os.getenv("EMAIL_RECIPIENTS", "oncall@example.com").split(","),
        "username": os.getenv("SMTP_USER", ""),
        "password": os.getenv("SMTP_PASS", ""),
    }


@app.post("/dispatch", response_model=DispatchResponse)
async def dispatch_incident(payload: IncidentPayload):
    if _dispatcher is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Dispatcher not initialized")
    incident = Incident(
        id=payload.id, title=payload.title, severity=payload.severity,
        category=payload.category, description=payload.description,
        metadata=payload.metadata, dedup_key=payload.dedup_key,
    )
    results = await _dispatcher.dispatch(incident)
    return DispatchResponse(incident_id=incident.id, channels=results)


@app.get("/health")
async def health():
    channels = list(_dispatcher._notifiers.keys()) if _dispatcher else []
    return {"status": "ok", "channels": [c.value for c in channels]}
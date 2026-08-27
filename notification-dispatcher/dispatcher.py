import time
import logging
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

import httpx

logger = logging.getLogger("notification-dispatcher")


class Channel(str, Enum):
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Incident:
    id: str
    title: str
    severity: Severity
    category: str
    description: str = ""
    metadata: dict = field(default_factory=dict)
    dedup_key: Optional[str] = None


@dataclass
class RateLimit:
    max_calls: int
    window_seconds: int


@dataclass
class RoutingRule:
    severities: list[Severity]
    categories: list[str]
    channels: list[Channel]


DEFAULT_ROUTING_RULES = [
    RoutingRule(
        severities=[Severity.CRITICAL],
        categories=["*"],
        channels=[Channel.SLACK, Channel.PAGERDUTY, Channel.EMAIL],
    ),
    RoutingRule(
        severities=[Severity.HIGH],
        categories=["*"],
        channels=[Channel.SLACK, Channel.PAGERDUTY],
    ),
    RoutingRule(
        severities=[Severity.MEDIUM, Severity.LOW],
        categories=["*"],
        channels=[Channel.SLACK],
    ),
    RoutingRule(
        severities=[Severity.CRITICAL, Severity.HIGH],
        categories=["security"],
        channels=[Channel.SLACK, Channel.PAGERDUTY, Channel.EMAIL],
    ),
]

DEFAULT_RATE_LIMITS = {
    Channel.SLACK: RateLimit(max_calls=30, window_seconds=60),
    Channel.PAGERDUTY: RateLimit(max_calls=10, window_seconds=60),
    Channel.EMAIL: RateLimit(max_calls=20, window_seconds=60),
}


class ChannelRateLimiter:
    def __init__(self, rate_limits: dict[Channel, RateLimit]):
        self._limits = rate_limits
        self._timestamps: dict[Channel, list[float]] = defaultdict(list)

    def allow(self, channel: Channel) -> bool:
        now = time.monotonic()
        limit = self._limits.get(channel)
        if limit is None:
            return True
        window = self._timestamps[channel]
        cutoff = now - limit.window_seconds
        self._timestamps[channel] = [ts for ts in window if ts > cutoff]
        if len(self._timestamps[channel]) >= limit.max_calls:
            return False
        self._timestamps[channel].append(now)
        return True


class SlackNotifier:
    def __init__(self, webhook_url: str):
        self._url = webhook_url
        self._client = httpx.AsyncClient(timeout=10.0)

    async def send(self, incident: Incident) -> bool:
        severity_emoji = {
            Severity.CRITICAL: "🔴", Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡", Severity.LOW: "🟢", Severity.INFO: "⚪",
        }
        emoji = severity_emoji.get(incident.severity, "⚪")
        payload = {
            "text": f"{emoji} *[{incident.severity.value.upper()}]* {incident.title}",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn",
                 "text": f"{emoji} *[{incident.severity.value.upper()}]* {incident.title}"}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Category:*\n{incident.category}"},
                    {"type": "mrkdwn", "text": f"*Incident ID:*\n{incident.id}"},
                ]},
                {"type": "section", "text": {"type": "mrkdwn",
                 "text": f"*Description:*\n{incident.description[:800]}"}},
            ],
        }
        try:
            resp = await self._client.post(self._url, json=payload)
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", "1"))
                logger.warning("Slack rate limited, retry after %.1fs", retry_after)
                return False
            resp.raise_for_status()
            logger.info("Slack notification sent for incident %s", incident.id)
            return True
        except Exception:
            logger.exception("Slack notification failed for incident %s", incident.id)
            return False


class PagerDutyNotifier:
    def __init__(self, integration_key: str, api_url: str = "https://events.pagerduty.com/v2/enqueue"):
        self._key = integration_key
        self._url = api_url
        self._client = httpx.AsyncClient(timeout=10.0)

    async def send(self, incident: Incident) -> bool:
        severity_map = {
            Severity.CRITICAL: "critical", Severity.HIGH: "error",
            Severity.MEDIUM: "warning", Severity.LOW: "info", Severity.INFO: "info",
        }
        dedup = incident.dedup_key or hashlib.sha256(
            f"{incident.id}:{incident.category}".encode()
        ).hexdigest()[:32]
        payload = {
            "routing_key": self._key,
            "event_action": "trigger",
            "dedup_key": dedup,
            "payload": {
                "summary": f"[{incident.severity.value.upper()}] {incident.title}",
                "severity": severity_map.get(incident.severity, "warning"),
                "source": incident.metadata.get("source", "incident-triage"),
                "component": incident.category,
                "group": incident.metadata.get("group", ""),
                "class": incident.metadata.get("class", ""),
                "custom_details": {"incident_id": incident.id, "description": incident.description[:500]},
            },
        }
        try:
            resp = await self._client.post(self._url, json=payload)
            resp.raise_for_status()
            logger.info("PagerDuty notification sent for incident %s", incident.id)
            return True
        except Exception:
            logger.exception("PagerDuty notification failed for incident %s", incident.id)
            return False


class EmailNotifier:
    def __init__(self, smtp_host: str, smtp_port: int, sender: str, recipients: list[str],
                 username: str = "", password: str = ""):
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._sender = sender
        self._recipients = recipients
        self._username = username
        self._password = password

    async def send(self, incident: Incident) -> bool:
        import smtplib
        from email.mime.text import MIMEText
        subject = f"[{incident.severity.value.upper()}] {incident.title}"
        body = (
            f"Incident ID: {incident.id}\n"
            f"Severity: {incident.severity.value}\n"
            f"Category: {incident.category}\n\n"
            f"{incident.description}"
        )
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = self._sender
        msg["To"] = ", ".join(self._recipients)
        try:
            with smtplib.SMTP(self._smtp_host, self._smtp_port, timeout=10) as server:
                if self._username:
                    server.starttls()
                    server.login(self._username, self._password)
                server.sendmail(self._sender, self._recipients, msg.as_string())
            logger.info("Email notification sent for incident %s", incident.id)
            return True
        except Exception:
            logger.exception("Email notification failed for incident %s", incident.id)
            return False


class NotificationDispatcher:
    def __init__(
        self,
        slack_webhook_url: str = "",
        pagerduty_key: str = "",
        email_config: dict | None = None,
        routing_rules: list[RoutingRule] | None = None,
        rate_limits: dict[Channel, RateLimit] | None = None,
    ):
        self._notifiers: dict[Channel, object] = {}
        if slack_webhook_url:
            self._notifiers[Channel.SLACK] = SlackNotifier(slack_webhook_url)
        if pagerduty_key:
            self._notifiers[Channel.PAGERDUTY] = PagerDutyNotifier(pagerduty_key)
        if email_config:
            self._notifiers[Channel.EMAIL] = EmailNotifier(**email_config)
        self._rules = routing_rules or DEFAULT_ROUTING_RULES
        self._limiter = ChannelRateLimiter(rate_limits or DEFAULT_RATE_LIMITS)

    def resolve_channels(self, incident: Incident) -> list[Channel]:
        channels: set[Channel] = set()
        for rule in self._rules:
            severity_match = incident.severity in rule.severities or Severity.CRITICAL in rule.severities and incident.severity in [Severity.HIGH]
            severity_match = incident.severity in rule.severities
            category_match = "*" in rule.categories or incident.category in rule.categories
            if severity_match and category_match:
                channels.update(rule.channels)
        available = {ch for ch in channels if ch in self._notifiers}
        return sorted(available, key=lambda c: c.value)

    async def dispatch(self, incident: Incident) -> dict[str, bool]:
        channels = self.resolve_channels(incident)
        results: dict[str, bool] = {}
        for channel in channels:
            if not self._limiter.allow(channel):
                logger.warning("Rate limited on %s for incident %s", channel.value, incident.id)
                results[channel.value] = False
                continue
            notifier = self._notifiers[channel]
            success = await notifier.send(incident)
            results[channel.value] = success
        if not channels:
            logger.info("No channels matched for incident %s (severity=%s, category=%s)",
                        incident.id, incident.severity.value, incident.category)
        return results
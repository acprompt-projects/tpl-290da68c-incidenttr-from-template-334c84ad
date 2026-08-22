from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Category(Enum):
    INFRA = "infra"
    APP = "app"
    SECURITY = "security"
    NETWORK = "network"


@dataclass
class TriageLabel:
    severity: Severity
    category: Category
    confidence: float
    matched_rules: list[str] = field(default_factory=list)
    suppress: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "confidence": round(self.confidence, 3),
            "matched_rules": self.matched_rules,
            "suppress": self.suppress,
        }


@dataclass
class Incident:
    title: str
    description: str
    source: str
    tags: list[str] = field(default_factory=list)
    metric_value: float | None = None
    metric_name: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


_KEYWORD_SEVERITY: dict[Severity, list[str]] = {
    Severity.P1: ["outage", "down", "unreachable", "critical", "data loss", "breach"],
    Severity.P2: ["degraded", "slow", "partial", "warning", "high latency", "elevated"],
    Severity.P3: ["minor", "low", "intermittent", "retry", "flapping"],
    Severity.P4: ["info", "notice", "heartbeat", "synthetic", "test"],
}

_KEYWORD_CATEGORY: dict[Category, list[str]] = {
    Category.INFRA: ["cpu", "memory", "disk", "host", "server", "node", "vm", "pod", "cluster", "iops", "instance"],
    Category.APP: ["error", "exception", "timeout", "5xx", "4xx", "crash", "panic", "deploy", "rollback", "oom"],
    Category.SECURITY: ["breach", "unauthorized", "auth", "iam", "firewall", "intrusion", "cve", "vulnerability", "malware", "exploit"],
    Category.NETWORK: ["dns", "latency", "packet", "bandwidth", "connectivity", "route", "tls", "handshake", "gateway", "proxy"],
}

_TAG_CATEGORY: dict[str, Category] = {
    "infra": Category.INFRA, "application": Category.APP, "app": Category.APP,
    "security": Category.SECURITY, "network": Category.NETWORK,
}


@dataclass
class ClassificationThresholds:
    metric_p1: float = 0.95
    metric_p2: float = 0.80
    metric_p3: float = 0.50
    suppress_confidence: float = 0.25

    @classmethod
    def from_file(cls, path: str | Path) -> ClassificationThresholds:
        data = json.loads(Path(path).read_text())
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def to_dict(self) -> dict[str, float]:
        return {f: getattr(self, f) for f in self.__dataclass_fields__}


class IncidentClassifier:
    def __init__(self, thresholds: ClassificationThresholds | None = None) -> None:
        self.thresholds = thresholds or ClassificationThresholds()
        self._sev_patterns = {
            sev: [re.compile(rf"\b{kw}\b", re.IGNORECASE) for kw in kws]
            for sev, kws in _KEYWORD_SEVERITY.items()
        }
        self._cat_patterns = {
            cat: [re.compile(rf"\b{kw}\b", re.IGNORECASE) for kw in kws]
            for cat, kws in _KEYWORD_CATEGORY.items()
        }

    def classify(self, incident: Incident) -> TriageLabel:
        severity, sev_score, sev_rules = self._classify_severity(incident)
        category, cat_score, cat_rules = self._classify_category(incident)
        confidence = (sev_score + cat_score) / 2.0 if (sev_score + cat_score) > 0 else 0.1
        suppress = confidence < self.thresholds.suppress_confidence
        return TriageLabel(
            severity=severity,
            category=category,
            confidence=confidence,
            matched_rules=sev_rules + cat_rules,
            suppress=suppress,
        )

    def _classify_severity(self, inc: Incident) -> tuple[Severity, float, list[str]]:
        text = f"{inc.title} {inc.description}"
        scores: dict[Severity, float] = {s: 0.0 for s in Severity}
        rules: dict[Severity, list[str]] = {s: [] for s in Severity}

        for sev, patterns in self._sev_patterns.items():
            for pat in patterns:
                if pat.search(text):
                    scores[sev] += 1.0
                    rules[sev].append(f"sev_kw:{pat.pattern}")

        if inc.metric_value is not None and inc.metric_name:
            metric_sev = self._metric_severity(inc.metric_value)
            scores[metric_sev] += 1.5
            rules[metric_sev].append(f"metric:{inc.metric_name}={inc.metric_value}")

        if not any(scores.values()):
            return Severity.P3, 0.1, ["default_sev_p3"]

        best = max(Severity, key=lambda s: scores[s])
        total = sum(scores.values()) or 1.0
        return best, scores[best] / total, rules[best]

    def _metric_severity(self, value: float) -> Severity:
        t = self.thresholds
        if value >= t.metric_p1:
            return Severity.P1
        if value >= t.metric_p2:
            return Severity.P2
        if value >= t.metric_p3:
            return Severity.P3
        return Severity.P4

    def _classify_category(self, inc: Incident) -> tuple[Category, float, list[str]]:
        text = f"{inc.title} {inc.description}"
        scores: dict[Category, float] = {c: 0.0 for c in Category}
        rules: dict[Category, list[str]] = {c: [] for c in Category}

        for tag in inc.tags:
            normalized = tag.lower().strip()
            if normalized in _TAG_CATEGORY:
                scores[_TAG_CATEGORY[normalized]] += 2.0
                rules[_TAG_CATEGORY[normalized]].append(f"tag:{tag}")

        for cat, patterns in self._cat_patterns.items():
            for pat in patterns:
                if pat.search(text):
                    scores[cat] += 1.0
                    rules[cat].append(f"cat_kw:{pat.pattern}")

        if not any(scores.values()):
            return Category.APP, 0.1, ["default_cat_app"]

        best = max(Category, key=lambda c: scores[c])
        total = sum(scores.values()) or 1.0
        return best, scores[best] / total, rules[best]
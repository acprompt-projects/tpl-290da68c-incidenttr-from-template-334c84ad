import { useState, useMemo } from "react";

const SEVERITY_COLORS = {
  critical: { bg: "#fecaca", text: "#991b1b", dot: "#dc2626" },
  high: { bg: "#fed7aa", text: "#9a3412", dot: "#ea580c" },
  medium: { bg: "#fef08a", text: "#854d0e", dot: "#ca8a04" },
  low: { bg: "#bbf7d0", text: "#166534", dot: "#16a34a" },
  info: { bg: "#bfdbfe", text: "#1e40af", dot: "#2563eb" },
};

const STATUS_STYLES = {
  new: { bg: "#e0e7ff", text: "#3730a3" },
  triaging: { bg: "#fef3c7", text: "#92400e" },
  acknowledged: { bg: "#d1fae5", text: "#065f46" },
  resolved: { bg: "#f3f4f6", text: "#374151" },
};

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const STATUSES = ["new", "triaging", "acknowledged", "resolved"];

const MOCK_INCIDENTS = [
  { id: "INC-001", title: "Database primary node unreachable", severity: "critical", status: "new", service: "db-cluster", count: 14, created: "2025-01-15T08:23:00Z", updated: "2025-01-15T08:45:00Z", assignee: null, description: "Primary PostgreSQL node has been unreachable for 22 minutes. Replicas still operational but no write path available." },
  { id: "INC-002", title: "API latency above 2s threshold", severity: "high", status: "triaging", service: "api-gateway", count: 8, created: "2025-01-15T07:12:00Z", updated: "2025-01-15T08:30:00Z", assignee: "jchen", description: "P99 latency on api-gateway exceeded 2s. Correlated with elevated DB query times." },
  { id: "INC-003", title: "Disk usage above 85% on worker-03", severity: "medium", status: "acknowledged", service: "worker-pool", count: 3, created: "2025-01-15T06:00:00Z", updated: "2025-01-15T07:15:00Z", assignee: "mross", description: "Worker node disk usage trending upward. Log rotation may need adjustment." },
  { id: "INC-004", title: "SSL certificate expiring in 7 days", severity: "low", status: "acknowledged", service: "lb-prod", count: 1, created: "2025-01-14T12:00:00Z", updated: "2025-01-15T09:00:00Z", assignee: "alee", description: "Load balancer SSL cert for *.example.com expires Jan 22. Auto-renewal should handle it." },
  { id: "INC-005", title: "Deploy notification received", severity: "info", status: "resolved", service: "ci-cd", count: 1, created: "2025-01-15T09:00:00Z", updated: "2025-01-15T09:05:00Z", assignee: "ci-bot", description: "Deployment v2.14.3 completed successfully across all regions." },
  { id: "INC-006", title: "Memory leak in auth-service", severity: "high", status: "new", service: "auth-service", count: 5, created: "2025-01-15T08:50:00Z", updated: "2025-01-15T09:10:00Z", assignee: null, description: "auth-service RSS growing ~50MB/hr. OOM kill likely within 4 hours if unchecked." },
  { id: "INC-007", title: "Kafka consumer lag exceeding 10k", severity: "medium", status: "triaging", service: "event-processor", count: 6, created: "2025-01-15T05:30:00Z", updated: "2025-01-15T08:00:00Z", assignee: "pkim", description: "Consumer group event-processor-group lag growing. Potential downstream processing bottleneck." },
];

function Badge({ label, style }) {
  return (
    <span style={{ ...style, padding: "2px 8px", borderRadius: 9999, fontSize: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: 0.5, whiteSpace: "nowrap" }}>
      {label}
    </span>
  );
}

function FilterBar({ severityFilter, statusFilter, onSeverityChange, onStatusChange }) {
  return (
    <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: "#6b7280" }}>Severity:</span>
        <button onClick={() => onSeverityChange(null)} style={filterBtn(severityFilter === null)}>All</button>
        {SEVERITIES.map(s => (
          <button key={s} onClick={() => onSeverityChange(s)} style={filterBtn(severityFilter === s)}>
            <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", backgroundColor: SEVERITY_COLORS[s].dot, marginRight: 4 }} />
            {s}
          </button>
        ))}
      </div>
      <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: "#6b7280" }}>Status:</span>
        <button onClick={() => onStatusChange(null)} style={filterBtn(statusFilter === null)}>All</button>
        {STATUSES.map(s => (
          <button key={s} onClick={() => onStatusChange(s)} style={filterBtn(statusFilter === s)}>{s}</button>
        ))}
      </div>
    </div>
  );
}

function filterBtn(active) {
  return {
    padding: "4px 10px", borderRadius: 6, border: `1px solid ${active ? "#6366f1" : "#d1d5db"}`,
    background: active ? "#eef2ff" : "#fff", color: active ? "#4338ca" : "#374151",
    fontSize: 12, fontWeight: 600, cursor: "pointer", display: "inline-flex", alignItems: "center",
  };
}

function IncidentTable({ incidents, selectedId, onSelect }) {
  return (
    <div style={{ overflowX: "auto", border: "1px solid #e5e7eb", borderRadius: 8 }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 14 }}>
        <thead>
          <tr style={{ background: "#f9fafb", textAlign: "left" }}>
            {["ID", "Title", "Severity", "Status", "Service", "Alerts", "Assignee", "Updated"].map(h => (
              <th key={h} style={{ padding: "10px 12px", fontWeight: 600, color: "#6b7280", borderBottom: "1px solid #e5e7eb", fontSize: 12, textTransform: "uppercase" }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {incidents.map(inc => (
            <tr key={inc.id} onClick={() => onSelect(inc.id)} style={{ background: selectedId === inc.id ? "#f0f0ff" : "#fff", cursor: "pointer", borderBottom: "1px solid #f3f4f6" }}>
              <td style={{ padding: "10px 12px", fontWeight: 600, color: "#4338ca" }}>{inc.id}</td>
              <td style={{ padding: "10px 12px", maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{inc.title}</td>
              <td style={{ padding: "10px 12px" }}><Badge label={inc.severity} style={SEVERITY_COLORS[inc.severity]} /></td>
              <td style={{ padding: "10px 12px" }}><Badge label={inc.status} style={STATUS_STYLES[inc.status]} /></td>
              <td style={{ padding: "10px 12px", fontFamily: "monospace", fontSize: 13 }}>{inc.service}</td>
              <td style={{ padding: "10px 12px", textAlign: "center" }}>{inc.count}</td>
              <td style={{ padding: "10px 12px" }}>{inc.assignee || "—"}</td>
              <td style={{ padding: "10px 12px", color: "#6b7280", fontSize: 13 }}>{new Date(inc.updated).toLocaleTimeString()}</td>
            </tr>
          ))}
          {incidents.length === 0 && (
            <tr><td colSpan={8} style={{ padding: 24, textAlign: "center", color: "#9ca3af" }}>No incidents match filters</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function IncidentDetail({ incident, onClose }) {
  if (!incident) return null;
  const sev = SEVERITY_COLORS[incident.severity];
  return (
    <div style={{ position: "fixed", right: 0, top: 0, bottom: 0, width: 400, background: "#fff", borderLeft: "1px solid #e5e7eb", boxShadow: "-4px 0 16px rgba(0,0,0,0.06)", padding: 24, overflowY: "auto", zIndex: 50 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2 style={{ margin: 0, fontSize: 16, color: "#1f2937" }}>{incident.id}</h2>
        <button onClick={onClose} style={{ background: "none", border: "none", fontSize: 20, cursor: "pointer", color: "#9ca3af" }}>✕</button>
      </div>
      <h3 style={{ margin: "0 0 12px", fontSize: 15 }}>{incident.title}</h3>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        <Badge label={incident.severity} style={sev} />
        <Badge label={incident.status} style={STATUS_STYLES[incident.status]} />
      </div>
      <DetailRow label="Service" value={incident.service} mono />
      <DetailRow label="Alert Count" value={incident.count} />
      <DetailRow label="Assignee" value={incident.assignee || "Unassigned"} />
      <DetailRow label="Created" value={new Date(incident.created).toLocaleString()} />
      <DetailRow label="Updated" value={new Date(incident.updated).toLocaleString()} />
      <div style={{ marginTop: 16 }}>
        <p style={{ fontSize: 13, fontWeight: 600, color: "#6b7280", marginBottom: 4 }}>Description</p>
        <p style={{ fontSize: 14, lineHeight: 1.6, color: "#374151" }}>{incident.description}</p>
      </div>
      <div style={{ marginTop: 20, display: "flex", gap: 8 }}>
        <button style={actionBtn("#4338ca", "#fff")}>Acknowledge</button>
        <button style={actionBtn("#fff", "#374151")}>Resolve</button>
      </div>
    </div>
  );
}

function DetailRow({ label, value, mono }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "1px solid #f3f4f6" }}>
      <span style={{ fontSize: 13, color: "#6b7280", fontWeight: 600 }}>{label}</span>
      <span style={{ fontSize: 14, color: "#1f2937", fontFamily: mono ? "monospace" : "inherit" }}>{value}</span>
    </div>
  );
}

function actionBtn(bg, color) {
  return { padding: "8px 16px", borderRadius: 6, border: `1px solid ${bg === "#fff" ? "#d1d5db" : bg}`, background: bg, color, fontSize: 13, fontWeight: 600, cursor: "pointer" };
}

export default function App() {
  const [severityFilter, setSeverityFilter] = useState(null);
  const [statusFilter, setStatusFilter] = useState(null);
  const [selectedId, setSelectedId] = useState(null);

  const filtered = useMemo(() => {
    return MOCK_INCIDENTS.filter(inc => {
      if (severityFilter && inc.severity !== severityFilter) return false;
      if (statusFilter && inc.status !== statusFilter) return false;
      return true;
    }).sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  }, [severityFilter, statusFilter]);

  const selected = MOCK_INCIDENTS.find(i => i.id === selectedId);

  return (
    <div style={{ fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', background: "#f3f4f6", minHeight: "100vh" }}>
      <header style={{ background: "#1e1b4b", color: "#fff", padding: "16px 24px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700 }}>Incident Triage Dashboard</h1>
        <span style={{ fontSize: 13, opacity: 0.8 }}>{filtered.length} incident{filtered.length !== 1 && "s"}</span>
      </header>
      <main style={{ padding: 24, marginRight: selectedId ? 400 : 0, transition: "margin-right 0.2s" }}>
        <FilterBar severityFilter={severityFilter} statusFilter={statusFilter} onSeverityChange={setSeverityFilter} onStatusChange={setStatusFilter} />
        <div style={{ marginTop: 16 }}>
          <IncidentTable incidents={filtered} selectedId={selectedId} onSelect={setSelectedId} />
        </div>
      </main>
      {selectedId && <IncidentDetail incident={selected} onClose={() => setSelectedId(null)} />}
    </div>
  );
}
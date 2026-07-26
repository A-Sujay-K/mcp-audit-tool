import React from 'react';
import RiskGauge from './RiskGauge';
import { formatTime, riskColor } from '../utils/constants';

/**
 * Scan overview — summary stats cards + risk gauge.
 */
export default function ScanOverview({ scan }) {
  if (!scan) {
    return (
      <div className="empty-state">
        <div className="empty-state__icon">🔍</div>
        <div className="empty-state__title">No Scan Selected</div>
        <div className="empty-state__description">
          Run <code className="mono">mcp-audit scan</code> or trigger a scan from the API to see results here.
        </div>
      </div>
    );
  }

  const stats = [
    {
      label: 'Servers',
      value: scan.total_servers ?? scan.servers_discovered?.length ?? 0,
      icon: '🖥️',
      iconClass: 'stat-icon--blue',
      valueClass: 'card__value--info',
    },
    {
      label: 'Tools Discovered',
      value: scan.total_tools ?? scan.tools_classified?.length ?? 0,
      icon: '🔧',
      iconClass: 'stat-icon--purple',
      valueClass: 'card__value--info',
    },
    {
      label: 'Findings',
      value: scan.total_findings ?? scan.findings?.length ?? 0,
      icon: '⚠️',
      iconClass: 'stat-icon--yellow',
      valueClass: scan.total_findings > 0 ? 'card__value--warning' : 'card__value--success',
    },
    {
      label: 'Confirmed Exploits',
      value: scan.confirmed_exploits ?? 0,
      icon: '💥',
      iconClass: 'stat-icon--red',
      valueClass: scan.confirmed_exploits > 0 ? 'card__value--danger' : 'card__value--success',
    },
  ];

  return (
    <div>
      {/* Stats row */}
      <div className="grid grid--4 mb-lg">
        {stats.map((s) => (
          <div key={s.label} className="card">
            <div className="card__header">
              <span className="card__title">{s.label}</span>
              <span className={`stat-icon ${s.iconClass}`}>{s.icon}</span>
            </div>
            <div className={`card__value ${s.valueClass}`}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Risk gauge + scan info */}
      <div className="grid grid--2">
        <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <h3 style={{ marginBottom: 'var(--space-lg)' }}>Overall Risk Score</h3>
          <RiskGauge score={scan.overall_risk_score ?? 0} size={200} />
        </div>
        <div className="card">
          <h3 style={{ marginBottom: 'var(--space-md)' }}>Scan Details</h3>
          <div className="flex flex-col gap-md">
            <DetailRow label="Scan ID" value={scan.id} mono />
            <DetailRow label="Status" value={<ScanStatusBadge status={scan.status} />} />
            <DetailRow label="Config Source" value={scan.config_source || 'auto-detect'} />
            <DetailRow label="Started" value={formatTime(scan.started_at)} />
            <DetailRow label="Completed" value={formatTime(scan.completed_at)} />
            <DetailRow
              label="Risk Score"
              value={
                <span style={{ color: riskColor(scan.overall_risk_score ?? 0), fontWeight: 700 }}>
                  {(scan.overall_risk_score ?? 0).toFixed(1)} / 10.0
                </span>
              }
            />
          </div>
        </div>
      </div>
    </div>
  );
}

function DetailRow({ label, value, mono = false }) {
  return (
    <div className="flex justify-between items-center" style={{ borderBottom: '1px solid var(--glass-border)', paddingBottom: 'var(--space-sm)' }}>
      <span className="text-muted" style={{ fontSize: '0.8rem' }}>{label}</span>
      <span className={mono ? 'mono' : ''} style={{ fontSize: '0.85rem', maxWidth: '60%', textAlign: 'right', wordBreak: 'break-all' }}>
        {value}
      </span>
    </div>
  );
}

function ScanStatusBadge({ status }) {
  const config = {
    completed: { cls: 'badge--failed', label: '✅ Completed' },
    pending: { cls: 'badge--pending', label: '⏳ Pending' },
    discovering: { cls: 'badge--pending', label: '🔍 Discovering' },
    classifying: { cls: 'badge--pending', label: '🏷️ Classifying' },
    analyzing: { cls: 'badge--partial', label: '📊 Analyzing' },
    exploiting: { cls: 'badge--confirmed', label: '💥 Exploiting' },
    failed: { cls: 'badge--confirmed', label: '❌ Failed' },
  };
  const c = config[status] || config.pending;
  return <span className={`badge ${c.cls}`}>{c.label}</span>;
}

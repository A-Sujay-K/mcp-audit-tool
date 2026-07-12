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

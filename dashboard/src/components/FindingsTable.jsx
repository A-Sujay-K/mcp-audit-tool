import React, { useState } from 'react';
import { FINDING_TYPE_LABELS, VERDICT_CONFIG, CAPABILITY_LABELS, riskColor, riskLevel } from '../utils/constants';

/**
 * Sortable, filterable findings table with risk score badges and exploit status.
 */
export default function FindingsTable({ findings = [], onSelectFinding }) {
  const [sortField, setSortField] = useState('risk_score');
  const [sortAsc, setSortAsc] = useState(false);
  const [filterType, setFilterType] = useState('all');

  const filtered = findings.filter((f) => filterType === 'all' || f.finding_type === filterType);

  const sorted = [...filtered].sort((a, b) => {
    const va = a[sortField] ?? 0;
    const vb = b[sortField] ?? 0;
    return sortAsc ? (va > vb ? 1 : -1) : (va < vb ? 1 : -1);
  });

  const handleSort = (field) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  const sortIcon = (field) => {
    if (sortField !== field) return '';
    return sortAsc ? ' ↑' : ' ↓';
  };

  if (!findings.length) {
    return (
      <div className="card empty-state">
        <div className="empty-state__icon">✅</div>
        <div className="empty-state__title">No Findings</div>
        <div className="empty-state__description">
          No dangerous capability combinations were detected in the current scan.
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* Filters */}
      <div className="flex gap-sm mb-lg flex-wrap">
        {['all', 'lethal_trifecta', 'code_execution_chain', 'credential_theft', 'filesystem_manipulation'].map((t) => (
          <button
            key={t}
            className={`nav-tab ${filterType === t ? 'nav-tab--active' : ''}`}
            onClick={() => setFilterType(t)}
          >
            {t === 'all' ? 'All' : FINDING_TYPE_LABELS[t]}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th style={{ cursor: 'pointer' }} onClick={() => handleSort('risk_score')}>
                Risk{sortIcon('risk_score')}
              </th>
              <th>Type</th>
              <th>Attack Chain</th>
              <th>Servers</th>
              <th>Exploit Status</th>
              <th style={{ cursor: 'pointer' }} onClick={() => handleSort('is_cross_server')}>
                Cross-Server{sortIcon('is_cross_server')}
              </th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f) => (
              <tr key={f.id} onClick={() => onSelectFinding?.(f)} style={{ cursor: 'pointer' }}>
                <td>
                  <span
                    className="mono"
                    style={{
                      color: riskColor(f.risk_score),
                      fontWeight: 700,
                      fontSize: '1rem',
                    }}
                  >
                    {f.risk_score?.toFixed(1)}
                  </span>
                </td>
                <td>
                  <span className={`badge badge--${riskLevel(f.risk_score)}`}>
                    {FINDING_TYPE_LABELS[f.finding_type] || f.finding_type}
                  </span>
                </td>
                <td style={{ maxWidth: 300 }}>
                  <div className="flex gap-sm flex-wrap" style={{ fontSize: '0.78rem' }}>
                    {f.injection_tool && (
                      <ToolChip tool={f.injection_tool} cap="ingests_untrusted_content" />
                    )}
                    {f.injection_tool && (f.data_tool || f.exfil_tool) && <span className="text-muted">→</span>}
                    {f.data_tool && <ToolChip tool={f.data_tool} cap="reads_sensitive_data" />}
                    {f.data_tool && f.exfil_tool && <span className="text-muted">→</span>}
                    {f.exfil_tool && <ToolChip tool={f.exfil_tool} cap="sends_data_out" />}
                    {f.code_exec_tool && <ToolChip tool={f.code_exec_tool} cap="executes_code" />}
                    {f.credential_tool && <ToolChip tool={f.credential_tool} cap="manages_credentials" />}
                  </div>
                </td>
                <td>
                  <div className="flex gap-sm flex-wrap">
                    {(f.servers_involved || []).map((s) => (
                      <span key={s} className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {s}
                      </span>
                    ))}
                  </div>
                </td>
                <td>
                  <ExploitBadge verdict={f.exploit_verdict} />
                </td>
                <td>
                  {f.is_cross_server ? (
                    <span className="badge badge--confirmed" style={{ fontSize: '0.65rem' }}>CROSS-SERVER</span>
                  ) : (
                    <span className="text-muted" style={{ fontSize: '0.75rem' }}>local</span>
                  )}
                </td>
                <td>
                  <span className="text-muted" style={{ fontSize: '1.1rem' }}>→</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ToolChip({ tool, cap }) {
  const label = CAPABILITY_LABELS[cap];
  const name = typeof tool === 'string' ? tool : tool?.tool_name || '?';
  return (
    <span className={`cap-tag ${label?.cssClass || ''}`}>
      {label?.emoji} {name}
    </span>
  );
}

function ExploitBadge({ verdict }) {
  if (!verdict) return <span className="badge badge--pending">⏳ Pending</span>;
  const cfg = VERDICT_CONFIG[verdict] || VERDICT_CONFIG.ERROR;
  return (
    <span className={`badge ${cfg.cssClass}`}>
      {cfg.emoji} {cfg.label}
    </span>
  );
}

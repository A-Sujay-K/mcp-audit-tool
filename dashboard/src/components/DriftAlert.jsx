import React from 'react';
import { DRIFT_TYPE_LABELS, SEVERITY_CONFIG, shortHash, formatTime, CAPABILITY_LABELS } from '../utils/constants';

/**
 * Drift/rug-pull detection alerts — timeline of tool definition changes.
 */
export default function DriftAlert({ driftEvents = [] }) {
  if (!driftEvents.length) {
    return (
      <div className="card empty-state">
        <div className="empty-state__icon">🛡️</div>
        <div className="empty-state__title">No Drift Detected</div>
        <div className="empty-state__description">
          All tool definitions match their previous scan baselines. No rug-pull indicators found.
        </div>
      </div>
    );
  }

  // Group by severity
  const critical = driftEvents.filter((e) => e.severity === 'critical');
  const others = driftEvents.filter((e) => e.severity !== 'critical');

  return (
    <div className="flex flex-col gap-md">
      {/* Critical alerts first */}
      {critical.length > 0 && (
        <div className="card" style={{ borderColor: 'rgba(255,107,107,0.3)' }}>
          <h3 style={{ color: 'var(--color-danger)', marginBottom: 'var(--space-md)' }}>
            🚨 Critical Drift Events ({critical.length})
          </h3>
          <div className="flex flex-col gap-md">
            {critical.map((event) => (
              <DriftEventCard key={event.id} event={event} />
            ))}
          </div>
        </div>
      )}

      {/* Other alerts */}
      {others.length > 0 && (
        <div className="card">
          <h3 style={{ marginBottom: 'var(--space-md)' }}>
            Drift Events ({others.length})
          </h3>
          <div className="flex flex-col gap-md">
            {others.map((event) => (
              <DriftEventCard key={event.id} event={event} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function DriftEventCard({ event }) {
  const severityCfg = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.medium;
  const typeLabel = DRIFT_TYPE_LABELS[event.drift_type] || event.drift_type;
  const icon = getDriftIcon(event.drift_type);

  return (
    <div className={`drift-alert drift-alert--${event.severity}`}>
      <div className="drift-alert__icon">{icon}</div>
      <div className="drift-alert__body">
        <div className="drift-alert__title">
          <span className={`badge ${severityCfg.cssClass}`} style={{ marginRight: 8 }}>
            {severityCfg.emoji} {event.severity?.toUpperCase()}
          </span>
          {typeLabel}
        </div>
        <div className="drift-alert__description">
          <strong className="mono">{event.server_name}:{event.tool_name}</strong>
          {event.description && <> — {event.description}</>}
        </div>

        {/* Hash diff */}
        {(event.old_hash || event.new_hash) && (
          <div className="drift-alert__hash">
            {event.old_hash && (
              <div>
                <span className="text-danger">- </span>
                {shortHash(event.old_hash)}
              </div>
            )}
            {event.new_hash && (
              <div>
                <span className="text-success">+ </span>
                {shortHash(event.new_hash)}
              </div>
            )}
          </div>
        )}

        {/* Capability changes */}
        {event.drift_type === 'capability_escalation' && event.new_capabilities && (
          <div className="flex gap-sm flex-wrap mt-sm">
            <span className="text-muted" style={{ fontSize: '0.72rem' }}>New capabilities:</span>
            {event.new_capabilities.map((cap) => {
              const label = CAPABILITY_LABELS[cap];
              return (
                <span key={cap} className={`cap-tag ${label?.cssClass || ''}`}>
                  {label?.emoji} {label?.label || cap}
                </span>
              );
            })}
          </div>
        )}

        <div className="mt-sm text-muted" style={{ fontSize: '0.7rem' }}>
          {formatTime(event.detected_at)}
        </div>
      </div>
    </div>
  );
}

function getDriftIcon(type) {
  switch (type) {
    case 'tool_added': return '➕';
    case 'tool_removed': return '➖';
    case 'description_changed': return '📝';
    case 'schema_changed': return '🔄';
    case 'capability_escalation': return '⬆️';
    case 'capability_deescalation': return '⬇️';
    default: return '🔔';
  }
}

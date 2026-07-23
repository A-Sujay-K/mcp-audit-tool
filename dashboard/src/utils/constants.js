/**
 * API client constants and utility hooks.
 */

// API base — set VITE_API_URL at build time to point to your backend.
// Falls back to same-origin /api for local development.
export const API_BASE = import.meta.env.VITE_API_URL || '/api';


export const CAPABILITY_LABELS = {
  reads_sensitive_data: { label: 'Reads Data', emoji: '🔴', cssClass: 'cap-tag--reads' },
  ingests_untrusted_content: { label: 'Ingests Untrusted', emoji: '🟡', cssClass: 'cap-tag--ingests' },
  sends_data_out: { label: 'Sends Out', emoji: '🔵', cssClass: 'cap-tag--sends' },
  executes_code: { label: 'Executes Code', emoji: '🟣', cssClass: 'cap-tag--executes' },
  modifies_filesystem: { label: 'Modifies FS', emoji: '🟠', cssClass: 'cap-tag--modifies' },
  manages_credentials: { label: 'Credentials', emoji: '🔑', cssClass: 'cap-tag--credentials' },
};

export const FINDING_TYPE_LABELS = {
  lethal_trifecta: 'Lethal Trifecta',
  code_execution_chain: 'Code Execution Chain',
  credential_theft: 'Credential Theft',
  filesystem_manipulation: 'Filesystem Manipulation',
};

export const VERDICT_CONFIG = {
  CONFIRMED: { label: 'Confirmed', cssClass: 'badge--confirmed', emoji: '🔴' },
  PARTIAL: { label: 'Partial', cssClass: 'badge--partial', emoji: '🟡' },
  FAILED: { label: 'Not Exploitable', cssClass: 'badge--failed', emoji: '🟢' },
  TIMEOUT: { label: 'Timeout', cssClass: 'badge--pending', emoji: '⏱️' },
  ERROR: { label: 'Error', cssClass: 'badge--pending', emoji: '⚠️' },
};

export const DRIFT_TYPE_LABELS = {
  tool_added: 'Tool Added',
  tool_removed: 'Tool Removed',
  description_changed: 'Description Changed',
  schema_changed: 'Schema Changed',
  capability_escalation: 'Capability Escalation',
  capability_deescalation: 'Capability De-escalation',
};

export const SEVERITY_CONFIG = {
  critical: { cssClass: 'badge--critical', emoji: '🔴' },
  high: { cssClass: 'badge--high', emoji: '🟠' },
  medium: { cssClass: 'badge--medium', emoji: '🟡' },
  low: { cssClass: 'badge--low', emoji: '🟢' },
};

/**
 * Compute a risk color based on score 0–10.
 */
export function riskColor(score) {
  if (score >= 7) return 'var(--color-danger)';
  if (score >= 4) return 'var(--color-warning)';
  return 'var(--color-success)';
}

/**
 * Compute risk level string.
 */
export function riskLevel(score) {
  if (score >= 8) return 'critical';
  if (score >= 6) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/**
 * Format a date string to a relative or short time string.
 */
export function formatTime(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  const now = new Date();
  const diffMs = now - d;
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHrs = Math.floor(diffMins / 60);
  if (diffHrs < 24) return `${diffHrs}h ago`;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

/**
 * Truncate a hash for display.
 */
export function shortHash(hash) {
  if (!hash) return '—';
  return hash.slice(0, 12) + '…';
}

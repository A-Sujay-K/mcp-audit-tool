import React, { useState } from 'react';
import ScanOverview from './components/ScanOverview';
import CapabilityGraph from './components/CapabilityGraph';
import FindingsTable from './components/FindingsTable';
import ExploitTimeline from './components/ExploitTimeline';
import DriftAlert from './components/DriftAlert';

/* ═══════════════════════════════════════════════════════════════════════
   Demo data — used when the API is not available (first run / demo mode).
   ═══════════════════════════════════════════════════════════════════════ */
const DEMO_SCAN = {
  id: 'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
  status: 'completed',
  config_source: '~/.cursor/mcp.json',
  started_at: new Date(Date.now() - 120000).toISOString(),
  completed_at: new Date().toISOString(),
  overall_risk_score: 8.7,
  total_servers: 4,
  total_tools: 12,
  total_findings: 3,
  confirmed_exploits: 1,
};

const DEMO_GRAPH = {
  nodes: [
    { id: 'filesystem:read_file', server_name: 'filesystem', tool_name: 'read_file', capabilities: ['reads_sensitive_data'], confidence: 0.95 },
    { id: 'filesystem:write_file', server_name: 'filesystem', tool_name: 'write_file', capabilities: ['modifies_filesystem'], confidence: 0.92 },
    { id: 'filesystem:list_files', server_name: 'filesystem', tool_name: 'list_files', capabilities: ['reads_sensitive_data'], confidence: 0.88 },
    { id: 'browser:fetch_url', server_name: 'browser', tool_name: 'fetch_url', capabilities: ['ingests_untrusted_content'], confidence: 0.97 },
    { id: 'browser:scrape_page', server_name: 'browser', tool_name: 'scrape_page', capabilities: ['ingests_untrusted_content'], confidence: 0.91 },
    { id: 'slack:send_message', server_name: 'slack', tool_name: 'send_message', capabilities: ['sends_data_out'], confidence: 0.96 },
    { id: 'slack:read_channel', server_name: 'slack', tool_name: 'read_channel', capabilities: ['reads_sensitive_data', 'ingests_untrusted_content'], confidence: 0.89 },
    { id: 'github:create_issue', server_name: 'github', tool_name: 'create_issue', capabilities: ['sends_data_out'], confidence: 0.87 },
    { id: 'github:run_workflow', server_name: 'github', tool_name: 'run_workflow', capabilities: ['executes_code'], confidence: 0.94 },
    { id: 'database:query', server_name: 'database', tool_name: 'query', capabilities: ['reads_sensitive_data'], confidence: 0.98 },
    { id: 'database:store_secret', server_name: 'database', tool_name: 'store_secret', capabilities: ['manages_credentials'], confidence: 0.93 },
    { id: 'email:send_email', server_name: 'email', tool_name: 'send_email', capabilities: ['sends_data_out'], confidence: 0.99 },
  ],
  edges: [
    { source: 'browser:fetch_url', target: 'filesystem:read_file', edge_type: 'injection_surface', is_cross_server: true },
    { source: 'browser:fetch_url', target: 'slack:send_message', edge_type: 'injection_surface', is_cross_server: true },
    { source: 'browser:fetch_url', target: 'github:run_workflow', edge_type: 'rce_path', is_cross_server: true },
    { source: 'filesystem:read_file', target: 'slack:send_message', edge_type: 'data_exfiltration', is_cross_server: true },
    { source: 'filesystem:read_file', target: 'email:send_email', edge_type: 'data_exfiltration', is_cross_server: true },
    { source: 'database:query', target: 'slack:send_message', edge_type: 'data_exfiltration', is_cross_server: true },
    { source: 'database:store_secret', target: 'email:send_email', edge_type: 'credential_theft', is_cross_server: true },
    { source: 'slack:read_channel', target: 'filesystem:write_file', edge_type: 'injection_surface', is_cross_server: true },
  ],
};

const DEMO_FINDINGS = [
  {
    id: 'f1',
    finding_type: 'lethal_trifecta',
    risk_score: 8.7,
    injection_tool: { tool_name: 'fetch_url', server_name: 'browser' },
    data_tool: { tool_name: 'read_file', server_name: 'filesystem' },
    exfil_tool: { tool_name: 'send_message', server_name: 'slack' },
    servers_involved: ['browser', 'filesystem', 'slack'],
    is_cross_server: true,
    exploit_verdict: 'CONFIRMED',
    description: 'Attacker embeds prompt injection in a fetched URL, reads files via filesystem server, exfiltrates via Slack.',
  },
  {
    id: 'f2',

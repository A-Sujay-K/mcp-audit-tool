# API Reference

The mcp-audit FastAPI backend exposes a JSON REST API on `/api/`.

## Base URL

- **Local**: `http://localhost:8000`
- **Production**: `https://mcp-audit-api.onrender.com` (example)

## Authentication

Currently none. For production deployments, it is recommended to deploy behind
a reverse proxy that handles authentication.

## Endpoints

### Health

#### `GET /api/health`

Returns the API status and version.

**Response:**
```json
{"status": "ok", "version": "0.1.0"}
```

---

### Scans

#### `POST /api/scans`

Trigger a new scan. Returns immediately with a `scan_id`; the scan runs in the background.

**Request body:**
```json
{
  "config_path": "/path/to/config.json",
  "auto_detect": true,
  "confirm_exploits": false
}
```

**Response (202):**
```json
{"scan_id": "uuid", "status": "running"}
```

#### `GET /api/scans`

List all scans, ordered by most recent first.

**Response:**
```json
[{"id": "uuid", "status": "completed", "start_time": "2026-08-10T10:00:00Z", ...}]
```

#### `GET /api/scans/{scan_id}`

Get a specific scan by ID.

**Response (200):** Scan object.
**Response (404):** `{"detail": "Scan not found"}`

#### `GET /api/scans/{scan_id}/tools`

List all tools discovered in a scan.

---

### Findings

#### `GET /api/findings`

List all findings across all scans.

#### `GET /api/findings/{scan_id}`

List findings for a specific scan, ordered by risk score descending.

---

### Drift

#### `GET /api/drift`

List all drift events, ordered by most recent first.

---

### Graph

#### `GET /api/graph/{scan_id}`

Return the capability graph for a scan as a JSON node-link format suitable for
rendering with D3.js or react-flow.

**Response:**
```json
{
  "nodes": [{"id": "server:tool", "server": "...", "capabilities": [...]}],
  "edges": [{"source": "...", "target": "...", "edge_type": "data_exfiltration"}]
}
```

# Deployment Guide

This guide covers deploying mcp-audit-tool to production using
**Render** (backend) and **Vercel** (frontend dashboard) -- both free tier.

## Prerequisites

- GitHub account with the `mcp-audit-tool` repo pushed
- Render account (sign up at render.com with GitHub)
- Vercel account (sign up at vercel.com with GitHub)

## Step 1 -- Deploy Backend on Render

1. Go to [render.com](https://render.com) -> **New +** -> **Web Service**
2. Select your `A-Sujay-K/mcp-audit-tool` repository
3. Render detects `render.yaml` automatically -- click **Apply**
4. Wait ~2 minutes for the initial build
5. Copy the service URL (e.g. `https://mcp-audit-api.onrender.com`)

### Manual Settings

| Field         | Value                                                         |
|---------------|---------------------------------------------------------------|
| Runtime       | Python 3                                                      |
| Build Command | `pip install -e .`                                            |
| Start Command | `uvicorn mcp_audit.api.main:app --host 0.0.0.0 --port $PORT` |
| Instance Type | Free                                                          |

### Environment Variables

| Key                      | Value                                      |
|--------------------------|--------------------------------------------|
| `PYTHON_VERSION`         | `3.11.0`                                   |
| `DATABASE_URL`           | `sqlite+aiosqlite:///./mcp_audit.db`       |
| `MCP_AUDIT_LLM_API_KEY`  | Your OpenAI / Anthropic key (optional)     |

### Verify Backend

```bash
curl https://mcp-audit-api.onrender.com/api/health
# Expected: {"status":"ok","version":"0.1.0"}
```

> **Free tier note**: The service sleeps after 15 min of inactivity.
> First request after sleep takes ~30 seconds.

## Step 2 -- Deploy Frontend on Vercel

1. Go to [vercel.com](https://vercel.com) -> **Add New Project**
2. Import `A-Sujay-K/mcp-audit-tool`
3. Vercel detects `vercel.json` automatically
4. Under **Environment Variables**, add:
   - `VITE_API_URL` = `https://mcp-audit-api.onrender.com/api`
5. Click **Deploy**

### Verify Frontend

Open `https://your-app.vercel.app` -- you should see the dashboard.
If the API is unreachable, the dashboard shows built-in demo data.

## Troubleshooting

| Symptom                         | Fix                                                        |
|---------------------------------|------------------------------------------------------------|
| Build fails: No module mcp_audit | Ensure build command is `pip install -e .`                |
| Dashboard shows blank page       | Check that `VITE_API_URL` is set in Vercel env vars       |
| CORS error in browser            | Set `MCP_AUDIT_CORS_ORIGINS=["*"]` in Render env vars     |
| asyncpg import error on Render   | Add `DATABASE_URL=sqlite+aiosqlite:///./mcp_audit.db`     |

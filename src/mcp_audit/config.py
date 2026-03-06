"""Application configuration using Pydantic Settings."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProvider(str, Enum):
    """Supported LLM providers for capability classification and red-team agent."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    OLLAMA = "ollama"


class DatabaseBackend(str, Enum):
    """Supported database backends."""

    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"


class Settings(BaseSettings):
    """Global application settings loaded from environment variables and .env files."""

    model_config = SettingsConfigDict(
        env_prefix="MCP_AUDIT_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── LLM Configuration ──────────────────────────────────────────────
    llm_provider: LLMProvider = Field(
        default=LLMProvider.OPENAI,
        description="LLM provider for capability classification and red-team agent.",
    )
    llm_model: str = Field(
        default="gpt-4o",
        description="Model identifier (e.g. gpt-4o, claude-sonnet-4-20250514, gemini-2.5-pro).",
    )
    llm_api_key: str = Field(
        default="",
        description="API key for the chosen LLM provider.",
    )
    llm_base_url: str | None = Field(
        default=None,
        description="Custom base URL (for Ollama or proxy endpoints).",
    )
    llm_temperature: float = Field(
        default=0.1,
        description="Temperature for LLM calls. Low = deterministic classification.",
    )

    # ── Database Configuration ─────────────────────────────────────────
    db_backend: DatabaseBackend = Field(
        default=DatabaseBackend.SQLITE,
        description="Database backend (sqlite for dev, postgresql for production).",
    )
    db_url: str = Field(
        default="sqlite+aiosqlite:///./mcp_audit.db",
        description="Full database connection URL.",
    )
    db_echo: bool = Field(
        default=False,
        description="Echo all SQL statements to stdout (useful for debugging).",
    )

    # ── Sandbox Configuration ──────────────────────────────────────────
    sandbox_enabled: bool = Field(
        default=True,
        description="Enable Docker sandbox for exploit confirmation.",
    )
    sandbox_image: str = Field(
        default="mcp-audit-sandbox:latest",
        description="Docker image for the exploit sandbox container.",
    )
    sandbox_timeout_seconds: int = Field(
        default=120,
        description="Hard timeout for each exploit attempt in the sandbox.",
    )
    sandbox_memory_limit: str = Field(
        default="512m",
        description="Memory limit for sandbox containers.",
    )
    sandbox_network_disabled: bool = Field(
        default=True,
        description="Disable network access in sandbox containers (non-negotiable for safety).",
    )

    # ── Scan Configuration ─────────────────────────────────────────────
    max_tools_per_scan: int = Field(
        default=500,
        description="Maximum tools to process in a single scan.",
    )
    classification_batch_size: int = Field(
        default=10,
        description="Number of tools to classify in a single LLM batch call.",
    )
    classification_cache_dir: Path = Field(
        default=Path(".mcp-audit-cache"),
        description="Directory for caching classification results.",
    )

    # ── API Configuration ──────────────────────────────────────────────
    api_host: str = Field(default="127.0.0.1", description="API server host.")
    api_port: int = Field(default=8000, description="API server port.")
    cors_origins: list[str] = Field(
        default=["http://localhost:5173", "http://localhost:3000"],
        description="Allowed CORS origins for the dashboard.",
    )

    # ── Drift Detection ────────────────────────────────────────────────
    drift_check_interval_hours: int = Field(
        default=24,
        description="How often to automatically check for tool drift (in hours).",
    )


def get_settings() -> Settings:
    """Create and return a Settings instance (cached at module level)."""
    return Settings()

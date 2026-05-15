"""Docker sandbox manager for isolated exploit confirmation.

Manages the lifecycle of Docker containers used to safely run exploit
attempts against mock MCP servers. All containers run with network disabled,
read-only root filesystem, and memory limits.
"""

from __future__ import annotations

import json
import logging
import tempfile
import textwrap
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcp_audit.config import Settings
from mcp_audit.parser.schemas import (
    ExploitResult,
    ExploitVerdict,
    TrifectaFinding,
)
from mcp_audit.sandbox.exploit_logger import ExploitLogger
from mcp_audit.sandbox.mock_mcp_server import MockMCPServerGenerator

try:
    import docker
    from docker.errors import DockerException, ImageNotFound

    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

logger = logging.getLogger(__name__)


class SandboxManager:
    """Manages Docker containers for sandboxed exploit confirmation."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.mock_generator = MockMCPServerGenerator()
        self._client = None

        if DOCKER_AVAILABLE:
            try:
                self._client = docker.from_env()
                logger.info("Docker client initialized successfully.")
            except Exception as e:
                logger.warning(f"Docker client unavailable: {e}")
        else:
            logger.warning(
                "Docker SDK not installed. Install with: pip install docker"
            )

    @property
    def client(self):
        return self._client

    async def ensure_image(self) -> bool:
        """Check if the sandbox Docker image exists, pull base if needed."""
        if not self.client:
            return False

        image_name = self.settings.sandbox_image
        try:
            self.client.images.get(image_name)
            logger.info(f"Sandbox image '{image_name}' found.")
            return True
        except Exception:
            pass

        # Fall back to pulling a slim Python image
        try:
            logger.info("Pulling python:3.12-slim as sandbox base...")
            self.client.images.pull("python", tag="3.12-slim")
            return True
        except Exception as e:
            logger.error(f"Failed to pull sandbox image: {e}")
            return False

    async def run_exploit(
        self,
        finding: TrifectaFinding,
        mock_server_script: str | None = None,
    ) -> ExploitResult:
        """Run an exploit attempt in an isolated Docker container.

        Args:
            finding: The trifecta finding to test.
            mock_server_script: Pre-generated mock server script.
                If None, one will be generated from the finding.

        Returns:
            ExploitResult with the verdict and detailed steps.
        """
        exploit_logger = ExploitLogger(finding.id)
        start_time = datetime.now(UTC)

        # Docker availability check
        if not self.client:
            return exploit_logger.build_result(
                verdict=ExploitVerdict.ERROR,
                sensitive_data_exfiltrated=False,
                injection_payload=None,
                failure_reason=(
                    "Docker is not available. Install Docker and the docker "
                    "Python package to enable sandboxed exploit confirmation."
                ),
                recommendations=["Install Docker Desktop or Docker Engine"],
            )

        # Generate scripts
        if mock_server_script is None:
            mock_server_script = self.mock_generator.create_mock_server_script(finding)

        runner_script = self._generate_exploit_runner(finding)

        exploit_logger.log_step(
            action="Preparing sandbox environment",
            detail="Generated mock MCP server and exploit runner scripts",
            tool_used=None,
            succeeded=True,
        )

        container = None
        try:
            # Write scripts to a temp directory
            with tempfile.TemporaryDirectory(prefix="mcp_audit_") as tmpdir:
                server_path = Path(tmpdir) / "server.py"
                runner_path = Path(tmpdir) / "runner.py"
                server_path.write_text(mock_server_script, encoding="utf-8")
                runner_path.write_text(runner_script, encoding="utf-8")

                exploit_logger.log_step(
                    action="Creating isolated container",
                    detail=f"network=none, read_only=true, mem_limit={self.settings.sandbox_memory_limit}",
                    tool_used=None,
                    succeeded=True,
                )

                # Create container
                container = self.client.containers.create(
                    image="python:3.12-slim",
                    command=["python", "/app/runner.py"],
                    network_mode="none" if self.settings.sandbox_network_disabled else "bridge",
                    read_only=True,
                    mem_limit=self.settings.sandbox_memory_limit,
                    tmpfs={"/tmp": "size=64m"},
                    volumes={
                        tmpdir: {"bind": "/app", "mode": "ro"},
                    },
                    user="nobody",
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    detach=True,
                )

                # Start and wait
                container.start()
                exploit_logger.log_step(
                    action="Exploit runner started",
                    detail=f"Container ID: {container.short_id}",
                    tool_used=None,
                    succeeded=True,
                )

                # Wait for completion or timeout
                try:
                    result = container.wait(
                        timeout=self.settings.sandbox_timeout_seconds
                    )
                    exit_code = result.get("StatusCode", -1)
                except Exception:
                    exploit_logger.log_step(
                        action="Timeout reached",
                        detail=f"Container exceeded {self.settings.sandbox_timeout_seconds}s limit",
                        tool_used=None,
                        succeeded=False,
                    )
                    container.kill()
                    return exploit_logger.build_result(
                        verdict=ExploitVerdict.TIMEOUT,
                        sensitive_data_exfiltrated=False,
                        injection_payload=None,
                        failure_reason="Exploit attempt timed out",
                        recommendations=["Increase timeout or simplify the exploit chain"],
                    )

                # Extract logs from container stdout
                stdout_logs = container.logs(stdout=True, stderr=False).decode(
                    "utf-8", errors="replace"
                )
                stderr_logs = container.logs(stdout=False, stderr=True).decode(
                    "utf-8", errors="replace"
                )

                # Try to extract the structured exploit log
                exploit_log = self._parse_exploit_output(stdout_logs)

                # Determine verdict
                sensitive_data_found = exploit_log.get(
                    "sensitive_data_exfiltrated", False
                )
                injection_used = exploit_log.get("injection_payload_used")

                # Add steps from the exploit runner output
                for step_data in exploit_log.get("steps", []):
                    exploit_logger.log_step(
                        action=step_data.get("action", "Unknown"),
                        detail=step_data.get("detail", ""),
                        tool_used=step_data.get("tool_used"),
                        succeeded=step_data.get("succeeded", False),
                    )

                if sensitive_data_found:
                    verdict = ExploitVerdict.CONFIRMED
                elif any(s.get("succeeded") for s in exploit_log.get("steps", [])):

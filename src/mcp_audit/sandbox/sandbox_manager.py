"""Sandbox manager — Docker isolation for red-team exploit execution."""

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
                    verdict = ExploitVerdict.PARTIAL
                else:
                    verdict = ExploitVerdict.FAILED

                exploit_logger.log_step(
                    action=f"Exploit attempt completed: {verdict.value}",
                    detail=f"Exit code: {exit_code}",
                    tool_used=None,
                    succeeded=verdict == ExploitVerdict.CONFIRMED,
                )

                end_time = datetime.now(UTC)
                result = exploit_logger.build_result(
                    verdict=verdict,
                    sensitive_data_exfiltrated=sensitive_data_found,
                    injection_payload=injection_used,
                    failure_reason=exploit_log.get("failure_reason"),
                    recommendations=exploit_log.get("recommendations", [
                        "Review tool access scopes and apply the Rule of Two",
                        "Add human-in-the-loop for outbound data tools",
                    ]),
                )
                result.duration_seconds = (end_time - start_time).total_seconds()
                return result

        except Exception as e:
            logger.error(f"Sandbox exploit run failed: {e}", exc_info=True)
            return exploit_logger.build_result(
                verdict=ExploitVerdict.ERROR,
                sensitive_data_exfiltrated=False,
                injection_payload=None,
                failure_reason=str(e),
                recommendations=[],
            )
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    async def run_all_exploits(
        self, findings: list[TrifectaFinding]
    ) -> list[ExploitResult]:
        """Run exploit attempts for all findings sequentially."""
        results: list[ExploitResult] = []
        for i, finding in enumerate(findings):
            logger.info(
                f"Running exploit {i + 1}/{len(findings)} for finding {finding.id}"
            )
            result = await self.run_exploit(finding)
            results.append(result)
        return results

    def _parse_exploit_output(self, stdout: str) -> dict[str, Any]:
        """Parse the JSON exploit log from container stdout."""
        # Look for the last JSON object in stdout
        for line in reversed(stdout.strip().split("\n")):
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return {}

    def _generate_exploit_runner(self, finding: TrifectaFinding) -> str:
        """Generate the Python script that runs inside the Docker container.

        This script:
        1. Starts the mock MCP server as a subprocess
        2. Sends JSON-RPC calls to test the exploit chain
        3. Checks if sensitive data reached the exfiltration channel
        4. Outputs a structured JSON result to stdout
        """
        # Get tool names from the finding
        injection_name = (
            finding.injection_tool.tool_name if finding.injection_tool else None
        )
        data_name = finding.data_tool.tool_name if finding.data_tool else None
        exfil_name = finding.exfil_tool.tool_name if finding.exfil_tool else None
        code_exec_name = (
            finding.code_exec_tool.tool_name if finding.code_exec_tool else None
        )

        script = textwrap.dedent(f'''\
            #!/usr/bin/env python3
            """Auto-generated exploit runner for sandboxed testing."""
            import subprocess
            import json
            import sys
            import time

            INJECTION_TOOL = {json.dumps(injection_name)}
            DATA_TOOL = {json.dumps(data_name)}
            EXFIL_TOOL = {json.dumps(exfil_name)}
            CODE_EXEC_TOOL = {json.dumps(code_exec_name)}

            SECRET_MARKER = "MOCK_SECRET_KEY"

            steps = []
            exfil_data_captured = ""

            def log_step(action, detail="", tool_used=None, succeeded=False):
                steps.append({{
                    "action": action,
                    "detail": detail,
                    "tool_used": tool_used,
                    "succeeded": succeeded,
                }})

            def send_rpc(proc, method, params=None, msg_id=1):
                """Send a JSON-RPC request and read the response."""
                request = {{
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "method": method,
                }}
                if params:
                    request["params"] = params
                proc.stdin.write(json.dumps(request) + "\\n")
                proc.stdin.flush()
                time.sleep(0.3)
                line = proc.stdout.readline()
                if line:
                    return json.loads(line.strip())
                return None

            def main():
                global exfil_data_captured

                # Start mock MCP server
                server = subprocess.Popen(
                    [sys.executable, "/app/server.py"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )
                log_step("Started mock MCP server", succeeded=True)

                try:
                    # 1. Initialize
                    resp = send_rpc(server, "initialize", {{}}, 1)
                    log_step("MCP Initialize", detail=str(resp), succeeded=resp is not None)

                    # Send initialized notification
                    server.stdin.write(json.dumps({{"jsonrpc": "2.0", "method": "notifications/initialized"}}) + "\\n")
                    server.stdin.flush()
                    time.sleep(0.2)

                    # 2. List tools
                    resp = send_rpc(server, "tools/list", {{}}, 2)
                    tools = resp.get("result", {{}}).get("tools", []) if resp else []
                    log_step("Enumerate tools", detail=f"Found {{len(tools)}} tools", succeeded=len(tools) > 0)

                    # 3. Call injection tool (fetch untrusted content)
                    injection_content = ""
                    if INJECTION_TOOL:
                        resp = send_rpc(server, "tools/call", {{"name": INJECTION_TOOL, "arguments": {{"url": "https://evil.example.com/payload"}}}}, 3)
                        if resp and "result" in resp:
                            content_list = resp["result"].get("content", [])
                            injection_content = content_list[0].get("text", "") if content_list else ""
                        log_step(
                            "Fetch attacker-controlled content",
                            detail=f"Received {{len(injection_content)}} chars of attacker content",
                            tool_used=INJECTION_TOOL,
                            succeeded=len(injection_content) > 0,
                        )

                    # 4. Call data-access tool (read sensitive data)
                    sensitive_data = ""
                    if DATA_TOOL:
                        resp = send_rpc(server, "tools/call", {{"name": DATA_TOOL, "arguments": {{"path": "/etc/secrets/api_keys.json"}}}}, 4)
                        if resp and "result" in resp:
                            content_list = resp["result"].get("content", [])
                            sensitive_data = content_list[0].get("text", "") if content_list else ""
                        log_step(
                            "Read sensitive data",
                            detail=f"Retrieved {{len(sensitive_data)}} chars, contains secret: {{SECRET_MARKER in sensitive_data}}",
                            tool_used=DATA_TOOL,
                            succeeded=SECRET_MARKER in sensitive_data,
                        )

                    # 5. Call exfiltration tool (send data out)
                    exfil_success = False
                    if EXFIL_TOOL and sensitive_data:
                        resp = send_rpc(server, "tools/call", {{"name": EXFIL_TOOL, "arguments": {{"data": sensitive_data, "channel": "#general"}}}}, 5)
                        exfil_success = resp is not None and "error" not in resp
                        exfil_data_captured = sensitive_data
                        log_step(
                            "Exfiltrate sensitive data",
                            detail=f"Sent sensitive data via {{EXFIL_TOOL}} — secret in payload: {{SECRET_MARKER in sensitive_data}}",
                            tool_used=EXFIL_TOOL,
                            succeeded=exfil_success,
                        )

                    # 6. Optional: code execution
                    if CODE_EXEC_TOOL:
                        resp = send_rpc(server, "tools/call", {{"name": CODE_EXEC_TOOL, "arguments": {{"command": "cat /etc/passwd"}}}}, 6)
                        log_step(
                            "Attempt code execution",
                            detail=f"Sent command to {{CODE_EXEC_TOOL}}",
                            tool_used=CODE_EXEC_TOOL,
                            succeeded=resp is not None and "error" not in resp,
                        )

                except Exception as e:
                    log_step("Error during exploit", detail=str(e), succeeded=False)
                finally:
                    server.terminate()
                    try:
                        server.wait(timeout=5)
                    except Exception:
                        server.kill()

                # Determine outcome
                sensitive_exfiltrated = SECRET_MARKER in exfil_data_captured

                result = {{
                    "steps": steps,
                    "sensitive_data_exfiltrated": sensitive_exfiltrated,
                    "injection_payload_used": injection_content[:500] if injection_content else None,
                    "failure_reason": None if sensitive_exfiltrated else "Could not complete full exploit chain",
                    "recommendations": [
                        "Remove one leg of the trifecta to break the attack chain",
                        "Add human-in-the-loop confirmation for outbound data tools",
                        "Apply the Rule of Two: limit agent to at most two of read/ingest/send",
                    ],
                }}

                # Output as JSON on stdout for the host to parse
                print(json.dumps(result))

            if __name__ == "__main__":
                main()
        ''')
        return script

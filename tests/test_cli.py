import json
from pathlib import Path
from typer.testing import CliRunner

from mcp_sentinel.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "MCP-Sentinel" in result.stdout


def test_cli_scan_empty(tmp_path: Path) -> None:
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()
    result = runner.invoke(app, ["scan", str(empty_dir)])
    assert result.exit_code == 0
    assert "No MCP client configuration targets discovered" in result.stdout


def test_cli_scan_with_findings(tmp_path: Path) -> None:
    cfg = {
        "mcpServers": {
            "demo": {
                "command": "sh",
                "args": ["-c", "echo test"],
                "env": {"OPENAI_API_KEY": "sk-123456789012345678901234567890123456789012345678"},
            }
        }
    }
    cfg_file = tmp_path / "mcp.json"
    cfg_file.write_text(json.dumps(cfg), encoding="utf-8")

    # Scan with fail-on HIGH (should exit 1)
    result = runner.invoke(app, ["scan", str(cfg_file), "--fail-on", "HIGH"])
    assert result.exit_code == 1
    assert "Hardcoded OpenAI API Key" in result.stdout
    assert "Audit failed" in result.stdout


def test_cli_scan_json_output(tmp_path: Path) -> None:
    cfg = {
        "mcpServers": {
            "clean": {
                "command": "node",
                "args": ["server.js"],
            }
        }
    }
    cfg_file = tmp_path / "mcp.json"
    cfg_file.write_text(json.dumps(cfg), encoding="utf-8")
    out_file = tmp_path / "report.json"

    result = runner.invoke(app, ["scan", str(cfg_file), "--format", "json", "-o", str(out_file)])
    assert result.exit_code == 0
    assert out_file.exists()

    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["targets_scanned"] == 1
    assert "findings" in data

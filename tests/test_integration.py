import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_sentinel.cli import app
from mcp_sentinel.supply_chain.osv import OsvVulnerabilityRule

runner = CliRunner()


def test_cli_formats(tmp_path: Path) -> None:
    cfg = {
        "mcpServers": {
            "test": {
                "command": "node",
                "args": ["server.js"],
            }
        }
    }
    cfg_file = tmp_path / "mcp.json"
    cfg_file.write_text(json.dumps(cfg), encoding="utf-8")

    # 1. SARIF format
    sarif_out = tmp_path / "out.sarif"
    res_sarif = runner.invoke(
        app, ["scan", str(cfg_file), "--format", "sarif", "-o", str(sarif_out)]
    )
    assert res_sarif.exit_code == 0
    assert sarif_out.exists()
    sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_data["version"] == "2.1.0"

    # 2. Markdown format
    md_out = tmp_path / "out.md"
    res_md = runner.invoke(app, ["scan", str(cfg_file), "--format", "markdown", "-o", str(md_out)])
    assert res_md.exit_code == 0
    assert md_out.exists()
    assert "MCP-Sentinel Security Audit Report" in md_out.read_text(encoding="utf-8")

    # 3. HTML format
    html_out = tmp_path / "out.html"
    res_html = runner.invoke(app, ["scan", str(cfg_file), "--format", "html", "-o", str(html_out)])
    assert res_html.exit_code == 0
    assert html_out.exists()
    assert "<!DOCTYPE html>" in html_out.read_text(encoding="utf-8")

    # 4. SBOM command
    sbom_out = tmp_path / "sbom.json"
    res_sbom = runner.invoke(app, ["sbom", str(cfg_file), "-o", str(sbom_out)])
    assert res_sbom.exit_code == 0
    assert sbom_out.exists()
    sbom_data = json.loads(sbom_out.read_text(encoding="utf-8"))
    assert sbom_data["bomFormat"] == "CycloneDX"


def test_osv_empty_and_offline() -> None:
    rule = OsvVulnerabilityRule()
    # Empty query returns empty list
    assert rule.query_packages([]) == []

from mcp_sentinel.core.models import ServerTarget, TransportType
from mcp_sentinel.supply_chain.cyclonedx import generate_cyclonedx_sbom
from mcp_sentinel.supply_chain.typosquat import TyposquattingRule, damerau_levenshtein


def test_damerau_levenshtein() -> None:
    assert damerau_levenshtein("kitten", "sitting") == 3
    assert damerau_levenshtein("mcp", "mcp") == 0
    # Transposition
    assert damerau_levenshtein("ab", "ba") == 1
    # Insertion
    assert damerau_levenshtein("git", "gitt") == 1


def test_typosquatting_rule() -> None:
    rule = TyposquattingRule()
    # "mcp-server-sqlte" is 1 edit from "mcp-server-sqlite"
    typo_target = ServerTarget(
        name="db", transport=TransportType.STDIO, command="uvx", args=["mcp-server-sqlte@1.0.0"]
    )
    findings = rule.evaluate_target(typo_target)
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP-SEC-005"
    assert "mcp-server-sqlite" in findings[0].evidence

    # Legitimate exact package
    clean_target = ServerTarget(
        name="db", transport=TransportType.STDIO, command="uvx", args=["mcp-server-sqlite@1.0.0"]
    )
    assert len(rule.evaluate_target(clean_target)) == 0


def test_cyclonedx_sbom_generation() -> None:
    target = ServerTarget(
        name="filesystem-server",
        transport=TransportType.STDIO,
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem@1.5.0", "/data"],
        client_type="claude-desktop",
    )
    sbom = generate_cyclonedx_sbom([target], version="0.1.0")

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert len(sbom["components"]) == 1

    comp = sbom["components"][0]
    assert comp["name"] == "@modelcontextprotocol/server-filesystem"
    assert comp["version"] == "1.5.0"
    assert "pkg:generic/@modelcontextprotocol/server-filesystem@1.5.0" in comp["purl"]

from mcp_sentinel.core.models import ServerTarget, TransportType
from mcp_sentinel.discovery.detector import get_default_config_locations
from mcp_sentinel.rules.static.shadowing import jaccard_similarity, tokenize
from mcp_sentinel.rules.static.unpinned import UnpinnedPackageRule


def test_get_default_config_locations() -> None:
    locs = get_default_config_locations()
    assert len(locs) > 0
    names = [name for name, _ in locs]
    assert "claude" in names
    assert "mcp-json" in names


def test_unpinned_docker_rules() -> None:
    rule = UnpinnedPackageRule()
    vuln_docker = ServerTarget(
        name="docker-srv",
        transport=TransportType.STDIO,
        command="docker",
        args=["run", "-i", "my-mcp-image:latest"],
    )
    findings = rule.evaluate_target(vuln_docker)
    assert len(findings) == 1
    assert "missing immutable digest" in findings[0].message

    pinned_docker = ServerTarget(
        name="docker-pinned",
        transport=TransportType.STDIO,
        command="docker",
        args=["run", "-i", "my-mcp-image@sha256:abcdef1234567890abcdef1234567890"],
    )
    assert len(rule.evaluate_target(pinned_docker)) == 0


def test_jaccard_similarity_empty() -> None:
    assert jaccard_similarity(set(), {"a", "b"}) == 0.0
    assert jaccard_similarity({"a"}, set()) == 0.0
    assert tokenize("hi") == set()  # words < 3 chars omitted
    assert tokenize("hello world") == {"hello", "world"}

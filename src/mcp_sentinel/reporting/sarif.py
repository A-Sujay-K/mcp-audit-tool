import json
from typing import Any

from mcp_sentinel.core.models import ScanReport, Severity

SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json"
)

SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "none",
}


def generate_sarif_report(report: ScanReport) -> dict[str, Any]:
    """Generates an OASIS SARIF v2.1.0 schema-compliant dictionary from a ScanReport."""
    rules_map: dict[str, dict[str, Any]] = {}
    rule_indices: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for f in report.findings:
        if f.rule_id not in rules_map:
            rule_index = len(rules_map)
            rule_indices[f.rule_id] = rule_index

            tags = list(f.standards.cwe) + list(f.standards.owasp_llm) + list(f.standards.owasp_mcp)
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_name.replace(" ", ""),
                "shortDescription": {"text": f.rule_name},
                "fullDescription": {"text": f.message},
                "defaultConfiguration": {
                    "level": SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning")
                },
                "help": {
                    "text": f"Remediation: {f.remediation}",
                    "markdown": f"**Remediation:** {f.remediation}\n\n**Standards:** {', '.join(tags)}",
                },
                "properties": {
                    "tags": tags,
                    "precision": "high",
                    "security-severity": "8.5"
                    if f.severity in (Severity.CRITICAL, Severity.HIGH)
                    else "5.0",
                },
            }

        rule_idx = rule_indices[f.rule_id]
        loc_uri = f.location or f.target or "config.json"
        # Sanitize URI
        loc_uri = loc_uri.replace("\\", "/")

        results.append(
            {
                "ruleId": f.rule_id,
                "ruleIndex": rule_idx,
                "level": SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": loc_uri, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": 1, "startColumn": 1},
                        }
                    }
                ],
                "fingerprints": {"guideline/v1": f.fingerprint},
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-sentinel",
                        "semanticVersion": report.version,
                        "informationUri": "https://github.com/A-Sujay-K/mcp-audit-tool",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def serialize_sarif(report: ScanReport, indent: int = 2) -> str:
    """Serializes a ScanReport to formatted SARIF 2.1.0 JSON string."""
    sarif_dict = generate_sarif_report(report)
    return json.dumps(sarif_dict, indent=indent)

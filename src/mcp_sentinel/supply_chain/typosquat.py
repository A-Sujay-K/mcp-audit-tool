from mcp_sentinel.core.models import Finding, RuleMetadata, ServerTarget, Severity, StandardMapping
from mcp_sentinel.rules.base import BaseRule

# Curated list of verified official / widely used MCP packages
OFFICIAL_MCP_PACKAGES = [
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-gdrive",
    "@modelcontextprotocol/server-sentry",
    "mcp-server-sqlite",
    "mcp-server-git",
    "mcp-server-fetch",
    "mcp-server-filesystem",
    "mcp-server-postgres",
    "mcp-server-github",
]


def damerau_levenshtein(s1: str, s2: str) -> int:
    """Computes the Damerau-Levenshtein distance between two strings."""
    d: dict[tuple[int, int], int] = {}
    len1, len2 = len(s1), len(s2)

    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,  # deletion
                d[(i, j - 1)] + 1,  # insertion
                d[(i - 1, j - 1)] + cost,  # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)  # transposition

    return d[(len1 - 1, len2 - 1)]


class TyposquattingRule(BaseRule):
    """Detects packages that closely mimic legitimate official MCP packages (typosquatting)."""

    @property
    def metadata(self) -> RuleMetadata:
        return RuleMetadata(
            id="MCP-SEC-005",
            name="Potential Package Typosquatting",
            severity=Severity.HIGH,
            description="The declared package name is within an edit distance of 1-2 characters from a verified official MCP package, indicating potential typosquatting.",
            standards=StandardMapping(
                cwe=["CWE-829"],
                owasp_llm=["OWASP-LLM05:2025"],
                owasp_mcp=["OWASP-MCP-M05"],
            ),
            remediation="Verify the package spelling against the official Model Context Protocol organization and ensure the correct namespace is used.",
        )

    def evaluate_target(self, target: ServerTarget) -> list[Finding]:
        findings: list[Finding] = []
        candidates: list[str] = []

        # Check command and arguments for package names
        for arg in target.args:
            if not arg.startswith("-"):
                # Strip SemVer tags like @1.2.3 or ==1.2.3
                clean_name = (
                    arg.split("@")[0] if not arg.startswith("@") else "@" + arg[1:].split("@")[0]
                )
                clean_name = clean_name.split("==")[0]
                candidates.append(clean_name)

        for cand in candidates:
            cand_lower = cand.lower()
            for official in OFFICIAL_MCP_PACKAGES:
                off_lower = official.lower()
                if cand_lower == off_lower:
                    continue  # Exact match to legitimate official package

                dist = damerau_levenshtein(cand_lower, off_lower)
                if 1 <= dist <= 2 and abs(len(cand_lower) - len(off_lower)) <= 2:
                    findings.append(
                        Finding(
                            rule_id=self.metadata.id,
                            rule_name=self.metadata.name,
                            severity=self.metadata.severity,
                            target=target.name,
                            message=f"Package '{cand}' on server '{target.name}' is {dist} edit(s) away from official package '{official}'.",
                            evidence=f"Declared: '{cand}' | Official Target: '{official}' | Edit Distance: {dist}",
                            remediation=self.metadata.remediation,
                            standards=self.metadata.standards,
                            location=target.source_file,
                        )
                    )

        return findings

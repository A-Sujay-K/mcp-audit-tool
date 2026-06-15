"""Unit tests for CapabilityClassifier — rule-based and LLM fallback."""
from __future__ import annotations

import asyncio

import pytest

from mcp_audit.parser.capability_classifier import RuleBasedFallbackClassifier
from mcp_audit.parser.schemas import DiscoveredTool, ToolCapability, TransportType


def make_tool(name: str, description: str) -> DiscoveredTool:
    return DiscoveredTool(
        server_name="test-server",
        name=name,
        description=description,
        input_schema={},
        transport=TransportType.STDIO,
    )


class TestRuleBasedFallbackClassifier:
    def setup_method(self):
        self.classifier = RuleBasedFallbackClassifier()

    def _classify_sync(self, tool: DiscoveredTool):
        return asyncio.get_event_loop().run_until_complete(
            self.classifier.classify_tool(tool)
        )

    def test_read_file_classified_as_reads_sensitive(self):
        tool = make_tool("read_file", "Read the contents of a file at a given path")
        result = self._classify_sync(tool)
        assert ToolCapability.READS_SENSITIVE_DATA in result.classification.capabilities

    def test_fetch_url_classified_as_ingests_untrusted(self):
        tool = make_tool("fetch_url", "Fetch content from any URL on the internet")
        result = self._classify_sync(tool)
        assert ToolCapability.INGESTS_UNTRUSTED in result.classification.capabilities

    def test_send_slack_classified_as_sends_data_out(self):
        tool = make_tool("send_slack_message", "Send a message to a Slack channel")
        result = self._classify_sync(tool)
        assert ToolCapability.SENDS_DATA_OUT in result.classification.capabilities

    def test_run_shell_classified_as_executes_code(self):
        tool = make_tool("run_shell", "Execute a shell command and return the output")
        result = self._classify_sync(tool)
        assert ToolCapability.EXECUTES_CODE in result.classification.capabilities

    def test_get_secret_classified_as_manages_credentials(self):
        tool = make_tool("get_secret", "Retrieve a secret from the secret store by key name")
        result = self._classify_sync(tool)
        assert ToolCapability.MANAGES_CREDENTIALS in result.classification.capabilities

    def test_benign_tool_has_no_dangerous_capabilities(self):
        tool = make_tool("get_current_time", "Return the current UTC timestamp as a string")
        result = self._classify_sync(tool)
        dangerous = {
            ToolCapability.READS_SENSITIVE_DATA,
            ToolCapability.INGESTS_UNTRUSTED,
            ToolCapability.SENDS_DATA_OUT,
            ToolCapability.EXECUTES_CODE,
        }
        caps = set(result.classification.capabilities)
        assert not caps.intersection(dangerous)

    def test_classify_batch_returns_same_count(self):
        tools = [
            make_tool("read_file", "Read a file"),
            make_tool("send_email", "Send an email to a recipient"),
            make_tool("get_time", "Get current time"),
        ]
        results = asyncio.get_event_loop().run_until_complete(
            self.classifier.classify_batch(tools)
        )
        assert len(results) == len(tools)

    def test_classification_has_confidence_score(self):
        tool = make_tool("read_file", "Read file contents")
        result = self._classify_sync(tool)
        assert 0.0 <= result.classification.confidence <= 1.0

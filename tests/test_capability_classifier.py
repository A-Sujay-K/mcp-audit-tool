"""Tests for the capability classifier module."""

import pytest

from mcp_audit.parser.capability_classifier import RuleBasedFallbackClassifier
from mcp_audit.parser.schemas import DiscoveredTool, ToolCapability


class TestRuleBasedClassifier:
    """Test the keyword-based fallback classifier."""

    def test_classify_file_reader(self):
        """A file-reading tool should be classified as READS_SENSITIVE_DATA."""
        tool = DiscoveredTool(
            server_name="filesystem",
            tool_name="read_file",
            description="Read the complete contents of a file from the filesystem.",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
        )
        classifier = RuleBasedFallbackClassifier()
        classified = classifier.classify(tool)

        assert ToolCapability.READS_SENSITIVE_DATA in classified.capabilities

    def test_classify_url_fetcher(self):
        """A URL fetcher should be classified as INGESTS_UNTRUSTED."""
        tool = DiscoveredTool(
            server_name="fetch",
            tool_name="fetch_url",
            description="Fetch content from a URL and return the response body.",
            input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
        )
        classifier = RuleBasedFallbackClassifier()
        classified = classifier.classify(tool)

        assert ToolCapability.INGESTS_UNTRUSTED in classified.capabilities

    def test_classify_message_sender(self):
        """A message sender should be classified as SENDS_DATA_OUT."""
        tool = DiscoveredTool(
            server_name="slack",
            tool_name="send_message",
            description="Send a message to a Slack channel via the Slack API.",
            input_schema={},
        )
        classifier = RuleBasedFallbackClassifier()
        classified = classifier.classify(tool)

        assert ToolCapability.SENDS_DATA_OUT in classified.capabilities

    def test_classify_code_executor(self):
        """A shell command executor should be classified as EXECUTES_CODE."""
        tool = DiscoveredTool(
            server_name="shell",
            tool_name="run_command",
            description="Execute a shell command and return stdout.",
            input_schema={},
        )
        classifier = RuleBasedFallbackClassifier()
        classified = classifier.classify(tool)

        assert ToolCapability.EXECUTES_CODE in classified.capabilities

    @pytest.mark.asyncio
    async def test_classify_preserves_metadata(self):
        """Classification should preserve the original tool metadata."""
        from mcp_audit.config import Settings
        from mcp_audit.parser.capability_classifier import CapabilityClassifier

        tool = DiscoveredTool(
            server_name="test-server",
            tool_name="read_database",
            description="Query the database for records.",
            input_schema={"type": "object"},
        )
        classifier = CapabilityClassifier(Settings(llm_model="test", llm_api_key="test"))
        classified = await classifier.classify_tool(tool)

        assert classified.server_name == "test-server"
        assert classified.tool_name == "read_database"
        assert classified.description == "Query the database for records."
        assert classified.confidence > 0

    def test_multiple_capabilities(self):
        """A tool can match multiple capability categories."""
        tool = DiscoveredTool(
            server_name="multi",
            tool_name="fetch_and_send",
            description="Fetch data from a URL and send it via email webhook.",
            input_schema={},
        )
        classifier = RuleBasedFallbackClassifier()
        classified = classifier.classify(tool)

        assert len(classified.capabilities) >= 2

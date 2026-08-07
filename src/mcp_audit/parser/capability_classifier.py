"""LLM and rule-based capability classifier with batch caching."""
import json
import logging

try:
    import litellm
except ImportError:
    litellm = None

from mcp_audit.config import Settings
from mcp_audit.parser.schemas import (
    ClassificationResult,
    ClassifiedTool,
    DiscoveredTool,
    ToolCapability,
)

logger = logging.getLogger(__name__)

class CapabilityClassifier:
    """Classifies tool capabilities using an LLM."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.model = settings.llm_model
        # Optional litellm setup based on settings
        if settings.llm_api_key and litellm is not None:
            import os
            # Simple heuristic, ideally uses litellm provider setup
            os.environ[f"{settings.llm_provider.value.upper()}_API_KEY"] = settings.llm_api_key
        if settings.llm_base_url and litellm is not None:
            litellm.api_base = settings.llm_base_url

    def _build_prompt(self, tool: DiscoveredTool) -> str:
        return f"""
        Analyze the following MCP tool and determine its capabilities.
        
        Tool Name: {tool.tool_name}
        Server Name: {tool.server_name}
        Description: {tool.description}
        Input Schema: {json.dumps(tool.input_schema)}
        
        Classify this tool into one or more of the following capability categories:
        - {ToolCapability.READS_SENSITIVE_DATA.value}
        - {ToolCapability.INGESTS_UNTRUSTED.value}
        - {ToolCapability.SENDS_DATA_OUT.value}
        - {ToolCapability.EXECUTES_CODE.value}
        - {ToolCapability.MODIFIES_FILESYSTEM.value}
        - {ToolCapability.MANAGES_CREDENTIALS.value}
        
        Return a JSON object with:
        - "capabilities": list of capability strings.
        - "confidence": float between 0.0 and 1.0.
        - "reasoning": brief explanation of why these capabilities were chosen.
        """

    async def classify_tool(self, tool: DiscoveredTool) -> ClassifiedTool:
        """Classify a single tool via LLM with JSON mode."""
        prompt = self._build_prompt(tool)

        if litellm is None:
            logger.warning(f"litellm not installed, falling back to rule-based for {tool.tool_name}")
            fallback = RuleBasedFallbackClassifier()
            classification = fallback.classify(tool)
        else:
            try:
                response = await litellm.acompletion(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert analyzing MCP tools. Return valid JSON only."},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"},
                    temperature=self.settings.llm_temperature
                )

                content = response.choices[0].message.content
                parsed = json.loads(content)

                classification = ClassificationResult(
                    capabilities=[ToolCapability(c) for c in parsed.get("capabilities", [])],
                    confidence=parsed.get("confidence", 0.0),
                    reasoning=parsed.get("reasoning", "")
                )

            except Exception as e:
                logger.error(f"LLM classification failed for {tool.tool_name}: {e}. Falling back to Rule-Based.")
                fallback = RuleBasedFallbackClassifier()
                classification = fallback.classify(tool)

        classified = ClassifiedTool(
            server_name=tool.server_name,
            tool_name=tool.tool_name,
            description=tool.description,
            input_schema=tool.input_schema,
            annotations=tool.annotations,
            capabilities=classification.capabilities,
            confidence=classification.confidence,
            reasoning=classification.reasoning
        )
        classified.compute_hash()
        return classified

    async def classify_batch(self, tools: list[DiscoveredTool]) -> list[ClassifiedTool]:
        """Classify a batch of tools concurrently with caching."""
        # Note: robust caching implementation should save to settings.classification_cache_dir
        # This implementation uses simple gather for concurrency
        tasks = [self.classify_tool(tool) for tool in tools]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        classified_tools = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                logger.error(f"Error classifying batch item {tools[i].tool_name}: {res}")
                # Fallback on failure
                fallback = RuleBasedFallbackClassifier()
                class_res = fallback.classify(tools[i])
                ct = ClassifiedTool(
                    server_name=tools[i].server_name,
                    tool_name=tools[i].tool_name,
                    description=tools[i].description,
                    input_schema=tools[i].input_schema,
                    capabilities=class_res.capabilities,
                    confidence=class_res.confidence,
                    reasoning=class_res.reasoning
                )
                ct.compute_hash()
                classified_tools.append(ct)
            else:
                classified_tools.append(res)

        return classified_tools


class RuleBasedFallbackClassifier:
    """Uses keyword matching to classify tools when LLM is unavailable."""

    def __init__(self):
        self.rules = {
            ToolCapability.READS_SENSITIVE_DATA: ["read", "file", "database", "query", "get", "fetch", "secret", "credential", "list_files", "search"],
            ToolCapability.INGESTS_UNTRUSTED: ["url", "http", "fetch", "browse", "email", "upload", "download", "web", "scrape", "crawl"],
            ToolCapability.SENDS_DATA_OUT: ["send", "post", "webhook", "notify", "email", "push", "transmit", "slack", "message", "chat"],
            ToolCapability.EXECUTES_CODE: ["exec", "run", "shell", "command", "eval", "script", "code", "terminal", "bash", "python"],
            ToolCapability.MODIFIES_FILESYSTEM: ["write", "create", "delete", "remove", "save", "update_file", "mkdir"],
            ToolCapability.MANAGES_CREDENTIALS: ["key", "token", "password", "secret", "credential", "auth", "login", "api_key"]
        }

    def classify(self, tool: DiscoveredTool) -> ClassificationResult:
        capabilities = set()
        text_to_search = f"{tool.tool_name} {tool.description} {json.dumps(tool.input_schema)}".lower()

        for capability, keywords in self.rules.items():
            if any(kw in text_to_search for kw in keywords):
                capabilities.add(capability)

        reasoning = "Classified using fallback rule-based keyword matching."
        if not capabilities:
            reasoning = "No capabilities detected via rule-based matching."

        return ClassificationResult(
            capabilities=list(capabilities),
            confidence=0.5,
            reasoning=reasoning
        )

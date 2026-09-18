class SentinelError(Exception):
    """Base exception for all mcp-sentinel domain errors."""


class ConfigParseError(SentinelError):
    """Raised when an MCP client configuration cannot be discovered or parsed."""


class TransportError(SentinelError):
    """Raised when an error occurs during MCP protocol communication."""


class AuthorizationRequiredError(SentinelError):
    """Raised when an active probe is attempted without the --i-have-authorization flag."""


class RuleExecutionError(SentinelError):
    """Raised when a security rule fails to execute."""


class BaselineError(SentinelError):
    """Raised when loading, generating, or validating a drift baseline fails."""


class SupplyChainError(SentinelError):
    """Raised when supply chain or OSV advisory querying encounters a failure."""

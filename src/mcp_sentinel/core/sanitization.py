import html
import re

# ANSI escape sequence regex
ANSI_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Dangerous / invisible Unicode characters (Zero-width, BiDi control codes)
DANGEROUS_UNICODE_CHARS = {
    "\u200b": "[ZWSP]",  # Zero Width Space
    "\u200c": "[ZWNJ]",  # Zero Width Non-Joiner
    "\u200d": "[ZWJ]",  # Zero Width Joiner
    "\u200e": "[LRM]",  # Left-to-Right Mark
    "\u200f": "[RLM]",  # Right-to-Left Mark
    "\u202a": "[LRE]",  # Left-to-Right Embedding
    "\u202b": "[RLE]",  # Right-to-Left Embedding
    "\u202c": "[PDF]",  # Pop Directional Formatting
    "\u202d": "[LRO]",  # Left-to-Right Override
    "\u202e": "[RLO]",  # Right-to-Left Override
    "\u2066": "[LRI]",  # Left-to-Right Isolate
    "\u2067": "[RLI]",  # Right-to-Left Isolate
    "\u2068": "[FSI]",  # First Strong Isolate
    "\u2069": "[PDI]",  # Pop Directional Isolate
    "\ufeff": "[BOM]",  # Byte Order Mark / Zero Width No-Break Space
}


def sanitize_terminal(text: str, max_length: int = 1000) -> str:
    """Strips ANSI sequences, neutralizes invisible/BiDi Unicode, and limits length."""
    if not text:
        return ""
    # Strip ANSI escapes
    cleaned = ANSI_REGEX.sub("", text)
    # Neutralize dangerous Unicode
    for char, rep in DANGEROUS_UNICODE_CHARS.items():
        cleaned = cleaned.replace(char, rep)
    # Strip non-printable ASCII (excluding \n, \t)
    cleaned = "".join(
        ch for ch in cleaned if ch in ("\n", "\t") or (ord(ch) >= 32 and ord(ch) != 127)
    )
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + " [TRUNCATED]"
    return cleaned


def sanitize_html(text: str, max_length: int = 2000) -> str:
    """HTML escapes untrusted text and limits length."""
    if not text:
        return ""
    cleaned = sanitize_terminal(text, max_length=max_length)
    return html.escape(cleaned)


def sanitize_for_log(text: str, max_length: int = 500) -> str:
    """Sanitizes text for single-line log output to prevent log injection and collapses whitespaces."""
    if not text:
        return ""
    cleaned = sanitize_terminal(text, max_length=max_length)
    # Collapse multiple whitespaces and newlines into single spaces
    return re.sub(r"\s+", " ", cleaned).strip()

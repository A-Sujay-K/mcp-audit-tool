from mcp_sentinel.core.sanitization import (
    sanitize_for_log,
    sanitize_html,
    sanitize_terminal,
)


def test_sanitize_terminal_ansi() -> None:
    ansi_input = "\x1b[31;1mRed Alert\x1b[0m and \x1b[32mGreen\x1b[0m"
    result = sanitize_terminal(ansi_input)
    assert result == "Red Alert and Green"
    assert "\x1b" not in result


def test_sanitize_terminal_zero_width_and_bidi() -> None:
    evil = "Normal\u200bText\u202ereversed\ufeffdone"
    result = sanitize_terminal(evil)
    assert "[ZWSP]" in result
    assert "[RLO]" in result
    assert "[BOM]" in result
    assert "\u200b" not in result
    assert "\u202e" not in result


def test_sanitize_terminal_truncation() -> None:
    long_text = "A" * 1500
    result = sanitize_terminal(long_text, max_length=50)
    assert len(result) == 50 + len(" [TRUNCATED]")
    assert result.endswith(" [TRUNCATED]")


def test_sanitize_html() -> None:
    raw = '<script>alert("xss")</script> & "quotes"'
    escaped = sanitize_html(raw)
    assert "<script>" not in escaped
    assert "&lt;script&gt;" in escaped
    assert "&amp;" in escaped
    assert "&quot;" in escaped


def test_sanitize_for_log() -> None:
    multiline = "First line\nSecond line\r\nThird line"
    log_safe = sanitize_for_log(multiline)
    assert "\n" not in log_safe
    assert "\r" not in log_safe
    assert log_safe == "First line Second line Third line"

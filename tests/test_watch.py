from pathlib import Path

from mcp_sentinel.watch.daemon import run_watch_loop
from mcp_sentinel.watch.github import GitHubIssueManager


def test_github_issue_manager_headers() -> None:
    mgr = GitHubIssueManager(repo="test-owner/test-repo", token="test-token-123")
    headers = mgr._get_headers()
    assert headers["Authorization"] == "Bearer test-token-123"
    assert headers["Accept"] == "application/vnd.github+json"

    # Without token
    mgr_no_token = GitHubIssueManager(repo="test-owner/test-repo", token="")
    assert "Authorization" not in mgr_no_token._get_headers()


def test_watch_loop_single_cycle(tmp_path: Path) -> None:
    # Run 1 cycle of watch loop over empty directory
    run_watch_loop(paths=[tmp_path], interval_seconds=1, github_repo=None, max_cycles=1)

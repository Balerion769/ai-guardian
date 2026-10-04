"""GitHub App REST payload contract tests."""

from types import SimpleNamespace

from dashboard import github_app


def test_check_run_posts_completed_conclusion(monkeypatch):
    calls = []

    class Response:
        def raise_for_status(self):
            return None

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return Response()

    monkeypatch.setattr(github_app.httpx, "post", fake_post)
    settings = SimpleNamespace(github_api_url="https://api.github.com")
    github_app.create_check_run(
        settings, "ghs_installation", "Example/repo", "a" * 40,
        conclusion="failure", summary="Found one HIGH finding.",
        details_url="https://dashboard.example/audits/1",
    )
    assert calls[0][0] == "https://api.github.com/repos/Example/repo/check-runs"
    assert calls[0][1]["json"] == {
        "name": "AI Guardian",
        "head_sha": "a" * 40,
        "status": "completed",
        "conclusion": "failure",
        "details_url": "https://dashboard.example/audits/1",
        "output": {"title": "AI Guardian security audit", "summary": "Found one HIGH finding."},
    }

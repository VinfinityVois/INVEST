from pathlib import Path
from types import SimpleNamespace

import pytest

from app.sources.git import GitSourceError, clone_allowed_repository


def test_clone_uses_allowlisted_https_and_disables_hooks_and_submodules(tmp_path, monkeypatch):
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs["env"]
        destination = Path(args[-1])
        (destination / ".git").mkdir(parents=True)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("app.sources.git.subprocess.run", fake_run)
    result = clone_allowed_repository(
        "https://github.com/example/project.git",
        "main",
        tmp_path,
        {"https://github.com/example/project"},
    )

    args = captured["args"]
    assert result["source"] == "git"
    assert (tmp_path / result["path"] / ".git").is_dir()
    assert "--no-recurse-submodules" in args
    assert "protocol.file.allow=never" in args
    assert any(arg.startswith("core.hooksPath=") for arg in args)
    assert captured["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert captured["env"]["GIT_CONFIG_NOSYSTEM"] == "1"


def test_rejects_repository_not_in_allowlist_without_running_git(tmp_path, monkeypatch):
    def forbidden_run(*args, **kwargs):
        raise AssertionError("git must not run for a non-allowlisted URL")

    monkeypatch.setattr("app.sources.git.subprocess.run", forbidden_run)

    with pytest.raises(GitSourceError, match="ALLOWED_TARGETS"):
        clone_allowed_repository(
            "https://github.com/attacker/repo",
            None,
            tmp_path,
            {"https://github.com/example/repo"},
        )


@pytest.mark.parametrize("url", [
    "http://github.com/example/repo",
    "https://user:password@github.com/example/repo",
    "https://github.com/example/repo/../../other",
    "file:///tmp/repo",
])
def test_rejects_unsafe_git_urls(tmp_path, url):
    with pytest.raises(GitSourceError):
        clone_allowed_repository(url, None, tmp_path, {url})


@pytest.mark.parametrize("ref", ["--upload-pack=bad", "../main", "feature..oops", "bad ref", "main.lock"])
def test_rejects_unsafe_git_refs(tmp_path, ref):
    with pytest.raises(GitSourceError):
        clone_allowed_repository(
            "https://github.com/example/repo",
            ref,
            tmp_path,
            {"https://github.com/example/repo"},
        )



def test_clone_supports_pinned_commit_sha_with_detached_checkout(tmp_path, monkeypatch):
    commit = "fe1fcbe212669783480666b9b60147c8a8c6eef4"
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if "clone" in args:
            destination = Path(args[-1])
            (destination / ".git").mkdir(parents=True)
        if "rev-parse" in args:
            return SimpleNamespace(returncode=0, stdout=commit + "\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("app.sources.git.subprocess.run", fake_run)

    result = clone_allowed_repository(
        "https://github.com/example/project",
        commit,
        tmp_path,
        {"https://github.com/example/project"},
    )

    assert result["ref"] == commit
    assert len(calls) == 4
    assert "--branch" not in calls[0][0]
    assert calls[1][0][-3:] == ["origin", commit] or calls[1][0][-2:] == ["origin", commit]
    assert calls[2][0][-3:] == ["checkout", "--detach", "FETCH_HEAD"]


def test_clone_can_checkout_an_exact_commit_sha_without_running_hooks(tmp_path, monkeypatch):
    commit_sha = "fe1fcbe212669783480666b9b60147c8a8c6eef4"
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        if "clone" in args:
            destination = Path(args[-1])
            (destination / ".git").mkdir(parents=True)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "rev-parse" in args:
            return SimpleNamespace(returncode=0, stdout=commit_sha + "\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("app.sources.git.subprocess.run", fake_run)

    result = clone_allowed_repository(
        "https://github.com/TBagirov/training",
        commit_sha,
        tmp_path,
        {"https://github.com/TBagirov/training"},
    )

    clone_args, _ = calls[0]
    fetch_args, fetch_kwargs = calls[1]
    checkout_args, _ = calls[2]
    verify_args, _ = calls[3]
    assert result["ref"] == commit_sha
    assert "--no-checkout" in clone_args
    assert "--branch" not in clone_args
    assert "--no-tags" in fetch_args
    assert "fetch" in fetch_args and commit_sha in fetch_args
    assert "checkout" in checkout_args and "--detach" in checkout_args
    assert "rev-parse" in verify_args
    assert fetch_kwargs["cwd"] == tmp_path / result["path"]


def test_pinned_commit_sha_mismatch_is_rejected_and_workspace_removed(tmp_path, monkeypatch):
    commit_sha = "fe1fcbe212669783480666b9b60147c8a8c6eef4"

    def fake_run(args, **kwargs):
        if "clone" in args:
            destination = Path(args[-1])
            (destination / ".git").mkdir(parents=True)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if "rev-parse" in args:
            return SimpleNamespace(returncode=0, stdout="0" * 40 + "\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("app.sources.git.subprocess.run", fake_run)

    with pytest.raises(GitSourceError, match="did not match"):
        clone_allowed_repository(
            "https://github.com/TBagirov/training",
            commit_sha,
            tmp_path,
            {"https://github.com/TBagirov/training"},
        )

    assert not list(tmp_path.glob("git-*"))

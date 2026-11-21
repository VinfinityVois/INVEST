from app.workflows.templates import clone_graph, sanitize_graph


def test_template_sanitizer_removes_secret_fields_recursively():
    graph = {"name": "demo", "nodes": [{
        "id": "n1", "type": "scan.custom",
        "config": {"api_key": "secret-value", "nested": {"access_token": "nested-secret", "mode": "safe"}}
    }], "edges": []}
    safe = sanitize_graph(graph)
    assert "api_key" not in safe["nodes"][0]["config"]
    assert "access_token" not in safe["nodes"][0]["config"]["nested"]
    assert safe["nodes"][0]["config"]["nested"]["mode"] == "safe"
    assert graph["nodes"][0]["config"]["api_key"] == "secret-value"


def test_template_sanitizer_removes_local_paths_and_webhook_destination():
    graph = {"nodes": [
        {"id": "upload", "type": "source.upload", "config": {"path": "projects/private"}},
        {"id": "hook", "type": "notify.webhook", "config": {"url": "https://webhook.site/secret-id"}},
    ], "edges": []}
    safe = sanitize_graph(graph)
    assert "path" not in safe["nodes"][0]["config"]
    assert safe["nodes"][1]["config"]["url"].startswith("https://example.invalid/")
    assert "secret-id" not in str(safe)


def test_template_sanitizer_strips_git_url_credentials_and_query():
    graph = {"nodes": [{"id": "git", "type": "source.git",
        "config": {"url": "https://user:password@github.com/org/repo?token=abc", "ref": "main"}}], "edges": []}
    safe = sanitize_graph(graph)
    assert safe["nodes"][0]["config"]["url"] == "https://github.com/org/repo"
    assert safe["nodes"][0]["config"]["ref"] == "main"
    assert "password" not in str(safe)
    assert "token=abc" not in str(safe)


def test_template_clone_rekeys_nodes_and_edges_without_execution():
    graph = {"name": "original", "nodes": [{"id": "a"}, {"id": "b"}],
             "edges": [{"id": "e1", "source": "a", "target": "b"}]}
    clone = clone_graph(graph, "copy")
    assert clone["name"] == "copy"
    assert clone["nodes"][0]["id"] != "a"
    assert clone["nodes"][1]["id"] != "b"
    assert clone["edges"][0]["id"] != "e1"
    assert clone["edges"][0]["source"] == clone["nodes"][0]["id"]
    assert clone["edges"][0]["target"] == clone["nodes"][1]["id"]

"""Resolve a single enclosing archive folder to the actual project root."""
from pathlib import Path

_PROJECT_MARKERS = {
    ".git", "src", "pom.xml", "build.gradle", "build.gradle.kts",
    "settings.gradle", "settings.gradle.kts", "gradlew", "mvnw",
    "package.json", "pyproject.toml", "requirements.txt", "Cargo.toml",
    "go.mod", "composer.json", "Gemfile", "README.md",
}


def detect_project_root(artifact_root: str | Path) -> Path:
    """Strip one conventional ZIP wrapper directory, but only when unambiguous."""
    root = Path(artifact_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Project artifact root must be a directory")
    try:
        entries = list(root.iterdir())
    except OSError:
        return root
    if len(entries) != 1 or entries[0].is_symlink() or not entries[0].is_dir():
        return root
    candidate = entries[0]
    try:
        names = {item.name for item in candidate.iterdir() if not item.is_symlink()}
    except OSError:
        return root
    return candidate.resolve(strict=True) if names & _PROJECT_MARKERS else root

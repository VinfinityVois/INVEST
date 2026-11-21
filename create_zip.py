
import os
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parent
output = root / "invest-security-scan.zip"

skip_dirs = {
    "node_modules", ".git", "dist", ".venv", "venv",
    "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", "coverage", ".next", "build"
}

def skip_file(name):
    lower = name.lower()
    return (
        lower == "invest-security-scan.zip"
        or lower == "create_zip.py"
        or lower == ".env"
        or lower.startswith(".env.")
        or lower.endswith((".pyc", ".pyo"))
    )

with zipfile.ZipFile(
    output, "w", zipfile.ZIP_DEFLATED, compresslevel=6
) as archive:
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in skip_dirs]

        for name in files:
            if skip_file(name):
                continue
            path = Path(current) / name
            archive.write(path, path.relative_to(root))

print("Архив создан:", output)
print("Размер: %.2f MiB" % (output.stat().st_size / 1024 / 1024))

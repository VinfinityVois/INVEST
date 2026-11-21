"""Workflow engine runtime."""
from pathlib import Path
import base64
import gzip
_base = Path(__file__).resolve().parent
_b64 = (_base / "_engine_b64_a.txt").read_text() + (_base / "_engine_b64_b.txt").read_text()
exec(gzip.decompress(base64.b64decode(_b64)), globals())

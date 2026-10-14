import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "examples" / "corpus"
PY = sys.executable


def image_ready(image: str) -> bool:
    if not shutil.which("docker"):
        return False
    r = subprocess.run(["docker", "image", "inspect", image], capture_output=True, check=False)
    return r.returncode == 0


needs_corpus_image = pytest.mark.skipif(
    not image_ready("mcp-audit-corpus"), reason="needs Docker and the mcp-audit-corpus image (make images)"
)

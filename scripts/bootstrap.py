"""Shared script bootstrap: anchor to the project root.

Scripts take paths like ``models/``, ``data/`` and ``config.yaml`` relative to
the project root, so running them from another directory (e.g.
``python C:\\path\\to\\g\\scripts\\run_server.py`` from the Desktop) must still
work. ``anchor_project_root()`` chdirs to the repo root once, before any
config/model/data path is resolved.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

# make `src` importable no matter where the script is invoked from
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def anchor_project_root() -> Path:
    """Chdir to the project root so relative paths resolve predictably."""
    os.chdir(PROJECT_ROOT)
    return PROJECT_ROOT

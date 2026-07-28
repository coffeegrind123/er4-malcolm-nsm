"""Shared config.env loader for the Python tools.

    import sys, pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from _config import load_config_env
    load_config_env()

The bash tools do the same thing via _config.sh. Keeping both is deliberate:
these are standalone executables, not a package, and a tool that silently fails
to find its own config is exactly the failure this repo keeps hitting.

Three real bugs came from tools not reading config.env:

  * OBSERVER_DESTS was documented in config.env and GOTCHAS as the way to label
    the monitoring's own traffic, and tools/investigate only ever read os.environ
    - so setting it did nothing and the observer stayed unlabelled, which is the
    single most alarming row in a volume analysis.
  * tools/watchdog carried hardcoded data paths and ignored DATA_ROOT, so
    relocating the data would have left it checking an empty directory and
    calling the pipeline healthy.
  * MITM_FLOWS_DIR_WIN is in config.env; tools/mitm-ingest reads
    MITM_NDJSON_HOST. Different names for the same thing, so the documented knob
    was inert.

EXISTING ENVIRONMENT WINS, so a one-off `VAR=x tools/foo` still overrides the
file - which is also how a check is proven to fire at all.
"""
from __future__ import annotations

import os
from pathlib import Path


def load_config_env(start: Path | None = None) -> None:
    """Load repo-root config.env into os.environ without clobbering what is set."""
    here = (start or Path(__file__)).resolve().parent
    cfg = here.parent / "config.env"
    if not cfg.is_file():
        return

    for line in cfg.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if not key.isidentifier() or key in os.environ:
            continue
        val = val.split(" #", 1)[0].strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]
        # config.env is shell-sourced by the bash tools and may reference other
        # variables. Expand the simple ${VAR}/$VAR forms so a value like
        # "${HOME}/malcolm" does not arrive as a literal string that then fails
        # with a "No such file or directory" naming a variable.
        val = os.path.expandvars(val)
        os.environ[key] = val

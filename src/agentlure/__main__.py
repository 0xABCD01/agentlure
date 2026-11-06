"""Support `python3 -m agentlure` (used by the npm wrapper shim)."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())

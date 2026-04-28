import os
import time

def _read_version() -> str:
    # VERSION sits at the project root (one level above core/).
    # __file__ is core/meta.py → dirname → core/ → dirname → project root.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        with open(os.path.join(root, 'VERSION'), encoding='utf-8') as f:
            return f.read().strip()
    except FileNotFoundError:
        return 'unknown'

SERVER_VERSION = _read_version()

# Track when this process started (for server uptime on /status)
_SERVER_START_TIME = time.time()
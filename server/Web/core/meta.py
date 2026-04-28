import os
import time

def _read_version() -> str:
    try:
        with open(os.path.join(os.path.dirname(__file__), 'VERSION'), encoding='utf-8') as f:
            return f.read().strip()
    except FileNotFoundError:
        return 'unknown'

SERVER_VERSION = _read_version()

# Track when this process started (for server uptime on /status)
_SERVER_START_TIME = time.time()
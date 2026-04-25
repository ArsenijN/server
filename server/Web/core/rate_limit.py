import threading, time, collections

_rl_lock     = threading.Lock()
_rl_attempts: dict[str, list[float]] = collections.defaultdict(list)
_RL_WINDOW   = 60    # seconds per window
_RL_MAX_AUTH = 10    # max login/register attempts per IP per window
_RL_MAX_API  = 30    # max sensitive-API attempts per IP per window


def _rate_limit(ip: str, bucket: str = "auth", max_hits: int | None = None) -> bool:
    """Return True (allowed) or False (throttled). Thread-safe."""
    limit = max_hits if max_hits is not None else (_RL_MAX_AUTH if bucket == "auth" else _RL_MAX_API)
    key   = f"{bucket}:{ip}"
    now   = time.monotonic()
    with _rl_lock:
        recent = [t for t in _rl_attempts.get(key, []) if now - t < _RL_WINDOW]
        if len(recent) >= limit:
            if recent:
                _rl_attempts[key] = recent
            else:
                _rl_attempts.pop(key, None)
            return False
        recent.append(now)
        _rl_attempts[key] = recent
        return True

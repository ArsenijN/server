import socket, time, threading, logging as _ps, logging
from datetime import datetime
from core.db import _db_connect

_NET_PROBE_HOSTS = [
    ('8.8.8.8', 53,  'Google DNS'),
    ('1.1.1.1', 53,  'Cloudflare DNS'),
]
_NET_PROBE_TIMEOUT       = 3
_NET_PROBE_INTERVAL      = 30   # normal polling interval (s)
_NET_PROBE_INTERVAL_DOWN = 5    # faster polling during outage (s)

# Shared state — written by _net_monitor_worker, read by status.json handler
_net_monitor_state = {
    'ok':           True,
    'latency_ms':   None,
    'outage_id':    None,    # rowid of open net_outages row, or None
    'outage_since': None,    # unix timestamp of outage start
}
_net_state_lock = threading.Lock()

# ── Auth rate limiter ──────────────────────────────────────────────────────

def _net_probe_once() -> tuple[bool, float | None]:
    """TCP-connect to each probe host; return (is_ok, avg_latency_ms).

    is_ok is True when at least ONE host responds (avoids false positives
    from a single temporarily unreachable server).  Declared outage only
    when BOTH fail.
    """
    ok_lats = []
    for host, port, _ in _NET_PROBE_HOSTS:
        t0 = time.monotonic()
        try:
            with _ps.create_connection((host, port), timeout=_NET_PROBE_TIMEOUT):
                ok_lats.append((time.monotonic() - t0) * 1000)
        except Exception:
            pass
    if not ok_lats:
        return False, None
    return True, round(sum(ok_lats) / len(ok_lats), 2)


def _dd_check_google() -> bool | None:
    """Probe a third independent host to confirm whether an outage is external.

    Previously this scraped the DownDetector HTML page, which broke silently
    whenever the page layout changed (B12).  We now do a direct TCP connect to
    a well-known host that is NOT in _NET_PROBE_HOSTS so the result is
    independent of the primary probes.

    Returns True  → third host also unreachable → likely an ISP/external outage
            False → third host responds         → outage looks local/server-side
            None  → unexpected error (caller treats as unknown)
    """
    _THIRD_HOST = ('9.9.9.9', 53)   # Quad9 DNS — independent of Google & Cloudflare
    try:
        with socket.create_connection(_THIRD_HOST, timeout=_NET_PROBE_TIMEOUT):
            return False   # third host is up → outage is not external
    except OSError:
        return True        # third host also down → likely external
    except Exception:
        return None


def _open_net_outage(probe_host: str) -> int | None:
    try:
        with _db_connect() as conn:
            cur = conn.execute(
                'INSERT INTO net_outages (started_at, probe_host) VALUES (?, ?)',
                (time.time(), probe_host)
            )
            conn.commit()
            return cur.lastrowid
    except Exception:
        logging.exception('NetMonitor: failed to open outage record')
        return None


def _close_net_outage(outage_id: int, started_at: float,
                      confirmed_external: bool = False) -> None:
    try:
        now = time.time()
        dur = round(now - started_at, 1)
        with _db_connect() as conn:
            conn.execute(
                '''UPDATE net_outages
                   SET ended_at=?, duration_sec=?, confirmed_external=?
                   WHERE id=?''',
                (now, dur, 1 if confirmed_external else 0, outage_id)
            )
            conn.commit()
        logging.warning(
            f'NetMonitor: connectivity restored after {dur:.0f}s'
            + (' (external confirmed)' if confirmed_external else '')
        )
    except Exception:
        logging.exception('NetMonitor: failed to close outage record')


def _net_monitor_worker() -> None:
    """Background daemon thread — probes internet every N seconds.

    On outage:
      1. Opens a net_outages row.
      2. Spawns a one-shot thread to probe Quad9 (independent external host check).
      3. Polls every 5 s until connectivity is restored.
    On recovery:
      4. Closes the net_outages row with duration + external flag.
    """
    logging.info('NetMonitor: started (probing %s)',
                 ', '.join(f'{h}:{p}' for h, p, _ in _NET_PROBE_HOSTS))
    while True:
        is_ok, latency = _net_probe_once()

        with _net_state_lock:
            was_ok       = _net_monitor_state['ok']
            outage_id    = _net_monitor_state['outage_id']
            outage_since = _net_monitor_state['outage_since']

            _net_monitor_state['ok']         = is_ok
            _net_monitor_state['latency_ms'] = latency

            if not is_ok and was_ok:
                logging.warning('NetMonitor: connectivity LOST')
                oid = _open_net_outage(_NET_PROBE_HOSTS[0][0])
                _net_monitor_state['outage_id']   = oid
                _net_monitor_state['outage_since'] = time.time()

                def _bg_dd(oid_=oid):
                    confirmed = _dd_check_google()
                    if confirmed is not None and oid_:
                        try:
                            with _db_connect() as _c:
                                _c.execute(
                                    'UPDATE net_outages SET confirmed_external=? WHERE id=?',
                                    (1 if confirmed else 0, oid_)
                                )
                                _c.commit()
                        except Exception:
                            pass
                threading.Thread(target=_bg_dd, daemon=True, name='DDCheck').start()

            elif is_ok and not was_ok and outage_id is not None:
                ext = False
                try:
                    with _db_connect() as _c:
                        row = _c.execute(
                            'SELECT confirmed_external FROM net_outages WHERE id=?',
                            (outage_id,)
                        ).fetchone()
                        ext = bool(row[0]) if row else False
                except Exception:
                    pass
                _close_net_outage(outage_id, outage_since or time.time(), ext)
                _net_monitor_state['outage_id']   = None
                _net_monitor_state['outage_since'] = None

        time.sleep(_NET_PROBE_INTERVAL_DOWN if not is_ok else _NET_PROBE_INTERVAL)


def _get_net_outages(days: int = 7) -> list:
    """Return net outages from the last N days, newest first."""
    try:
        cutoff = time.time() - days * 86400
        with _db_connect() as conn:
            rows = conn.execute(
                '''SELECT id, started_at, ended_at, duration_sec,
                          probe_host, confirmed_external, COALESCE(note,'') as note
                   FROM net_outages
                   WHERE started_at >= ?
                   ORDER BY started_at DESC''',
                (cutoff,)
            ).fetchall()
        result = []
        for row in rows:
            oid, started, ended, dur, host, ext, note = row
            started_str = datetime.fromtimestamp(started).strftime('%Y-%m-%d %H:%M:%S')
            ended_str   = datetime.fromtimestamp(ended).strftime('%Y-%m-%d %H:%M:%S') if ended else None
            if dur is not None:
                if dur < 60:
                    dur_str = f'{dur:.0f}s'
                elif dur < 3600:
                    dur_str = f'{dur/60:.0f}m {int(dur)%60}s'
                else:
                    dur_str = f'{dur/3600:.1f}h'
            else:
                dur_str = 'ongoing'
            result.append({
                'id':                  oid,
                'started_at':          started_str,
                'ended_at':            ended_str,
                'duration_str':        dur_str,
                'is_open':             ended is None,
                'probe_host':          host,
                'confirmed_external':  bool(ext),
                'note':                note or None,
            })
        return result
    except Exception:
        logging.exception('NetMonitor: failed to fetch outages')
        return []


def _get_net_history_by_day(days: int = 90) -> dict:
    """Return {date_str: {outage_count, total_downtime_sec}} for uptime bars."""
    try:
        cutoff = time.time() - days * 86400
        with _db_connect() as conn:
            rows = conn.execute(
                """SELECT date(datetime(started_at, 'unixepoch', 'localtime')) as day,
                          COUNT(*) as outage_count,
                          SUM(COALESCE(duration_sec, 0)) as total_down
                   FROM net_outages
                   WHERE started_at >= ?
                   GROUP BY day""",
                (cutoff,)
            ).fetchall()
        return {r[0]: {'outage_count': r[1], 'total_downtime_sec': r[2] or 0}
                for r in rows}
    except Exception:
        return {}

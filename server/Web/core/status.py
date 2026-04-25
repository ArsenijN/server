import os, time, threading, logging, json
from datetime import datetime, timedelta
from core.db import _db_connect
from core.net_monitor import _net_monitor_state, _get_net_outages, _get_net_history_by_day

def _build_snapshot_cause(http_up: bool, https_up: bool, db_ok: bool,
                           mem_pct: int, disk_pct: int) -> str | None:
    """Return a short human-readable cause string when something is not fully ok."""
    parts = []
    if not http_up:
        parts.append('HTTP server unreachable')
    if not https_up:
        parts.append('HTTPS server unreachable')
    if not db_ok:
        parts.append('database query failed')
    if mem_pct >= 95:
        parts.append(f'memory critical ({mem_pct}%)')
    elif mem_pct >= 85:
        parts.append(f'memory high ({mem_pct}%)')
    if disk_pct >= 90:
        parts.append(f'disk critical ({disk_pct}%)')
    elif disk_pct >= 75:
        parts.append(f'disk usage high ({disk_pct}%)')
    return '; '.join(parts) if parts else None


def _record_status_snapshot(http_up: bool, https_up: bool, db_ok: bool,
                            mem_pct: int, disk_pct: int,
                            net_ok: bool = True,
                            latency_ms: float | None = None) -> None:
    """Write one status sample to the DB. Prunes rows older than 90 days.

    Also maintains the incident_log table: opens a new incident when the
    status transitions away from 'ok', and closes any open incident when it
    returns to 'ok'.
    """
    if http_up and https_up and db_ok:
        status = 'ok'
    elif not http_up or not https_up:
        status = 'down'
    else:
        status = 'degraded'

    cause = _build_snapshot_cause(http_up, https_up, db_ok, mem_pct, disk_pct)

    try:
        with _db_connect() as conn:
            conn.execute(
                '''INSERT INTO status_snapshots
                   (status, http_up, https_up, db_ok, mem_pct, disk_pct, cause, net_ok, latency_ms)
                   VALUES (?,?,?,?,?,?,?,?,?)''',
                (status, int(http_up), int(https_up), int(db_ok), mem_pct, disk_pct, cause,
                 int(net_ok), latency_ms)
            )
            # Keep only 90 days of data (90*24*12 = 25920 five-minute samples)
            conn.execute(
                "DELETE FROM status_snapshots WHERE sampled_at < datetime('now', '-90 days')"
            )

            # --- incident tracking ---
            open_incident = conn.execute(
                "SELECT id FROM incident_log WHERE resolved_at IS NULL ORDER BY id DESC LIMIT 1"
            ).fetchone()

            if status != 'ok' and open_incident is None:
                # New outage — open a fresh incident
                severity = 'critical' if status == 'down' else 'degraded'
                detail = (
                    f"http_up={http_up}, https_up={https_up}, "
                    f"db_ok={db_ok}, mem={mem_pct}%, disk={disk_pct}%"
                )
                conn.execute(
                    '''INSERT INTO incident_log (severity, cause, detail)
                       VALUES (?,?,?)''',
                    (severity, cause or 'unknown', detail)
                )
            elif status == 'ok' and open_incident is not None:
                # Recovered — close the incident
                conn.execute(
                    "UPDATE incident_log SET resolved_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (open_incident[0],)
                )

            conn.commit()
    except Exception:
        logging.exception('Failed to record status snapshot')


# ==============================================================================
# --- NETWORK CONNECTIVITY MONITOR ---
# ==============================================================================

def _get_recent_incidents(limit: int = 20) -> list:
    """Return the most recent incidents from incident_log, newest first.

    Each row: { id, started_at, resolved_at, severity, cause, detail,
                duration_str, is_open }
    """
    try:
        with _db_connect() as conn:
            rows = conn.execute(
                '''SELECT id, started_at, resolved_at, severity, cause, detail
                   FROM incident_log
                   ORDER BY id DESC
                   LIMIT ?''',
                (limit,)
            ).fetchall()
    except Exception:
        return []

    result = []
    for row in rows:
        inc_id, started_at, resolved_at, severity, cause, detail = row
        is_open = resolved_at is None
        if is_open:
            duration_str = 'ongoing'
        else:
            try:
                def _parse_dt(raw):
                    raw = raw[:19]
                    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M',
                                '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M'):
                        try:
                            return datetime.strptime(raw, fmt)
                        except ValueError:
                            pass
                    raise ValueError(f'Unrecognised datetime: {raw!r}')
                s = _parse_dt(started_at)
                e = _parse_dt(resolved_at)
                secs = int((e - s).total_seconds())
                if secs < 60:
                    duration_str = f'{secs}s'
                elif secs < 3600:
                    duration_str = f'{secs // 60}m {secs % 60}s'
                else:
                    duration_str = f'{secs // 3600}h {(secs % 3600) // 60}m'
            except Exception:
                duration_str = '?'
        result.append({
            'id': inc_id,
            'started_at': started_at,
            'resolved_at': resolved_at,
            'severity': severity,
            'cause': cause,
            'detail': detail,
            'duration_str': duration_str,
            'is_open': is_open,
        })
    return result


def _get_message_board(limit: int = 10) -> list:
    """Return the most recent message-board posts, newest first.

    Each row: { id, posted_at, level, title, body }
    """
    try:
        with _db_connect() as conn:
            rows = conn.execute(
                '''SELECT id, posted_at, level, title, body
                   FROM message_board
                   ORDER BY id DESC
                   LIMIT ?''',
                (limit,)
            ).fetchall()
        return [
            {'id': r[0], 'posted_at': r[1], 'level': r[2], 'title': r[3], 'body': r[4]}
            for r in rows
        ]
    except Exception:
        return []


def _get_status_history(days: int = 90) -> list:
    """Return one aggregated row per day for the last `days` days.

    Each row: { date, status ('ok'|'degraded'|'down'|'no_data'),
                uptime_pct, sample_count, causes, http_down_n, https_down_n, db_down_n,
                mem_max, disk_max }
    Days are in descending order (today first).
    causes is a deduplicated list of non-null cause strings recorded that day.
    """
    try:
        with _db_connect() as conn:
            rows = conn.execute(
                """SELECT date(sampled_at, 'localtime') as day,
                          COUNT(*) as n,
                          SUM(CASE WHEN status='ok'   THEN 1 ELSE 0 END) as ok_n,
                          SUM(CASE WHEN status='down' THEN 1 ELSE 0 END) as down_n,
                          SUM(CASE WHEN http_up=0  THEN 1 ELSE 0 END) as http_down_n,
                          SUM(CASE WHEN https_up=0 THEN 1 ELSE 0 END) as https_down_n,
                          SUM(CASE WHEN db_ok=0    THEN 1 ELSE 0 END) as db_down_n,
                          MAX(mem_pct)  as mem_max,
                          MAX(disk_pct) as disk_max
                   FROM status_snapshots
                   WHERE sampled_at >= datetime('now', ? || ' days')
                   GROUP BY day
                   ORDER BY day DESC""",
                (f'-{days}',)
            ).fetchall()
            # Fetch distinct non-null causes per day (newest first within the day)
            cause_rows = conn.execute(
                """SELECT date(sampled_at, 'localtime') as day, cause
                   FROM status_snapshots
                   WHERE cause IS NOT NULL
                     AND sampled_at >= datetime('now', ? || ' days')
                   ORDER BY sampled_at DESC""",
                (f'-{days}',)
            ).fetchall()
    except Exception:
        return []

    # Build deduplicated cause lists per day (preserve insertion order, newest first)
    causes_by_day: dict[str, list[str]] = {}
    for day, cause in cause_rows:
        seen = causes_by_day.setdefault(day, [])
        if cause not in seen:
            seen.append(cause)

    by_day = {r[0]: r for r in rows}
    result = []
    today = datetime.now().date()
    for i in range(days):
        d = (today - timedelta(days=i)).isoformat()
        if d in by_day:
            _, n, ok_n, down_n, http_down_n, https_down_n, db_down_n, mem_max, disk_max = by_day[d]
            pct = round(ok_n / n * 100, 1) if n else 0
            if down_n == n:
                st = 'down'
            elif down_n > 0 or ok_n < n:
                st = 'degraded'
            else:
                st = 'ok'
            result.append({
                'date': d, 'status': st, 'uptime_pct': pct, 'sample_count': n,
                'causes': causes_by_day.get(d, []),
                'http_down_n': http_down_n or 0,
                'https_down_n': https_down_n or 0,
                'db_down_n': db_down_n or 0,
                'mem_max': mem_max or 0,
                'disk_max': disk_max or 0,
            })
        else:
            result.append({
                'date': d, 'status': 'no_data', 'uptime_pct': None, 'sample_count': 0,
                'causes': [], 'http_down_n': 0, 'https_down_n': 0, 'db_down_n': 0,
                'mem_max': 0, 'disk_max': 0,
            })
    return result

def _build_status_page() -> str:
    """Collect all system metrics and render the status HTML page."""
    import ssl as _ssl

    now = datetime.now()
    now_str = now.strftime('%Y-%m-%d %H:%M:%S')

    # ── server uptime ──
    srv_uptime_secs = int(time.time() - _SERVER_START_TIME)
    srv_h = srv_uptime_secs // 3600
    srv_m = (srv_uptime_secs % 3600) // 60
    srv_uptime_h = str(srv_h)
    srv_start_str = datetime.fromtimestamp(_SERVER_START_TIME).strftime('%Y-%m-%d %H:%M')

    # ── system uptime (from /proc/uptime) ──
    try:
        with open('/proc/uptime') as f:
            sys_uptime_secs = int(float(f.read().split()[0]))
    except Exception:
        sys_uptime_secs = 0
    sys_h = sys_uptime_secs // 3600
    sys_uptime_h = str(sys_h)
    sys_d = sys_h // 24
    sys_uptime_str = f"{sys_d}d {sys_h % 24}h {(sys_uptime_secs % 3600) // 60}m"

    # ── disk stats ──
    def _diskinfo(path: str) -> dict:
        try:
            st = os.statvfs(path)
            total = st.f_frsize * st.f_blocks
            avail = st.f_frsize * st.f_bavail
            used  = total - avail
            pct   = round(used / total * 100, 1) if total else 0
            return {
                'total': _fmt_bytes(total), 'used': _fmt_bytes(used),
                'avail': _fmt_bytes(avail), 'pct': pct,
                'ind':   _disk_indicator(pct),
            }
        except Exception:
            return {'total':'N/A','used':'N/A','avail':'N/A','pct':0,'ind':'warn'}

    cdn_disk  = _diskinfo(SERVE_ROOT)
    root_disk = _diskinfo('/')
    tmp_disk  = _diskinfo('/tmp')

    # ── cpu load ──
    try:
        with open('/proc/loadavg') as f:
            parts = f.read().split()
        loads = [float(parts[0]), float(parts[1]), float(parts[2])]
    except Exception:
        loads = [0.0, 0.0, 0.0]

    # get CPU count for normalising load to %
    try:
        cpu_count = os.cpu_count() or 1
    except Exception:
        cpu_count = 1

    load_labels = ['1 min', '5 min', '15 min']
    cpu_bars_html = ''
    for label, load in zip(load_labels, loads):
        pct = min(round(load / cpu_count * 100), 100)
        cpu_bars_html += (
            f'<div class="cpu-row">'
            f'<div class="cpu-label">{label}</div>'
            f'<div class="cpu-track"><div class="cpu-fill" style="width:{pct}%"></div></div>'
            f'<div class="cpu-pct">{load:.2f}</div>'
            f'</div>'
        )

    # ── memory (/proc/meminfo) ──
    mem = {}
    try:
        with open('/proc/meminfo') as f:
            for line in f:
                k, v = line.split(':', 1)
                mem[k.strip()] = int(v.strip().split()[0]) * 1024  # kB → bytes
    except Exception:
        pass

    mem_total_b = mem.get('MemTotal', 0)
    mem_avail_b = mem.get('MemAvailable', 0)
    mem_used_b  = mem_total_b - mem_avail_b
    mem_pct     = round(mem_used_b / mem_total_b * 100) if mem_total_b else 0
    mem_total   = _fmt_bytes(mem_total_b)
    mem_used    = _fmt_bytes(mem_used_b)
    mem_avail   = _fmt_bytes(mem_avail_b)

    swap_total_b = mem.get('SwapTotal', 0)
    swap_free_b  = mem.get('SwapFree', 0)
    swap_used_b  = swap_total_b - swap_free_b
    swap_pct     = round(swap_used_b / swap_total_b * 100) if swap_total_b else 0
    swap_total   = _fmt_bytes(swap_total_b)
    swap_used    = _fmt_bytes(swap_used_b)

    # ── network (first non-lo interface from /proc/net/dev) ──
    net_rx_b = net_tx_b = 0
    try:
        with open('/proc/net/dev') as f:
            for line in f:
                line = line.strip()
                if ':' not in line:
                    continue
                iface, data = line.split(':', 1)
                iface = iface.strip()
                if iface == 'lo':
                    continue
                nums = data.split()
                net_rx_b += int(nums[0])
                net_tx_b += int(nums[8])
    except Exception:
        pass
    net_rx = _fmt_bytes(net_rx_b)
    net_tx = _fmt_bytes(net_tx_b)

    # ── DB stats ──
    user_count = active_sessions = active_shares = expired_shares = total_share_views = 0
    db_status = 'ok'; db_ind = 'ok'
    try:
        with _db_connect() as conn:
            user_count       = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            active_sessions  = conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE expires_at > CURRENT_TIMESTAMP"
            ).fetchone()[0]
            active_shares    = conn.execute(
                "SELECT COUNT(*) FROM shared_links WHERE (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)"
            ).fetchone()[0]
            expired_shares   = conn.execute(
                "SELECT COUNT(*) FROM shared_links WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP"
            ).fetchone()[0]
            total_share_views = conn.execute(
                "SELECT COALESCE(SUM(access_count),0) FROM shared_links"
            ).fetchone()[0]
    except Exception:
        db_status = 'degraded'; db_ind = 'warn'

    db_size_str = 'N/A'
    try:
        db_size_str = _fmt_bytes(os.path.getsize(DB_FILE))
    except Exception:
        pass

    # ── file counts ──
    def _count_dir(path: str):
        count = size = 0
        try:
            for root, _, files in os.walk(path):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        size += os.path.getsize(fp)
                        count += 1
                    except Exception:
                        pass
        except Exception:
            pass
        return count, size

    fluxdrop_dir = os.path.join(SERVE_ROOT, 'FluxDrop')
    catbox_dir   = os.path.join(SERVE_ROOT, CATBOX_UPLOAD_DIR)
    fluxdrop_files, fluxdrop_size = _count_dir(fluxdrop_dir)
    catbox_files,   catbox_size   = _count_dir(catbox_dir)
    fluxdrop_size_str = _fmt_bytes(fluxdrop_size)
    catbox_size_str   = _fmt_bytes(catbox_size)

    # ── TLS cert expiry ──
    ssl_status = 'ok'; ssl_ind = 'ok'; ssl_detail = 'valid'
    try:
        import datetime as _dt
        # get_server_certificate fetches PEM without verifying trust chain — works for self-signed certs
        pem = _ssl.get_server_certificate(('127.0.0.1', HTTPS_PORT), timeout=2)
        der = _ssl.PEM_cert_to_DER_cert(pem)
        from cryptography import x509 as _x509
        cert_obj  = _x509.load_der_x509_certificate(der)
        exp_dt    = cert_obj.not_valid_after_utc  # already timezone-aware (UTC)
        days_left = (exp_dt - _dt.datetime.now(_dt.timezone.utc)).days
        ssl_detail = f"expires in {days_left}d ({exp_dt.strftime('%Y-%m-%d')})"
        if days_left < 7:
            ssl_status = 'critical'; ssl_ind = 'crit'
        elif days_left < 30:
            ssl_status = 'expiring'; ssl_ind = 'warn'
    except Exception as _tls_err:
        logging.warning(f"TLS cert check failed: {_tls_err}")
        ssl_detail = 'check unavailable'
        ssl_ind = 'info'; ssl_status = 'info'

    # ── port liveness ──
    import socket as _sock2
    def _port_open(port: int) -> bool:
        try:
            with _sock2.create_connection(('127.0.0.1', port), timeout=1):
                return True
        except Exception:
            return False

    http_up  = _port_open(HTTP_PORT)
    https_up = _port_open(HTTPS_PORT)
    http_ind    = 'ok'   if http_up  else 'crit'
    https_ind   = 'ok'   if https_up else 'crit'
    http_status = 'operational' if http_up  else 'down'
    https_status= 'operational' if https_up else 'down'

    # ── uptime history bars (from DB — real per-day aggregates) ──────────
    total_days = 90
    history = _get_status_history(total_days)   # newest-first list of dicts
    net_day_hist = _get_net_history_by_day(total_days)  # {date_str: {outage_count, total_downtime_sec}}

    # Overall uptime % = ok samples / total samples (time-accurate, not day-granular)
    total_samples = sum(h['sample_count'] for h in history if h['status'] != 'no_data')
    if total_samples:
        ok_samples = sum(
            round(h['uptime_pct'] / 100 * h['sample_count'])
            for h in history
            if h['status'] != 'no_data' and h['uptime_pct'] is not None
        )
        uptime_pct = round(ok_samples / total_samples * 100, 2)
    else:
        # Fall back to process uptime proxy if we have no history yet
        days_up = min(int(srv_uptime_secs / 86400), total_days)
        uptime_pct = round(days_up / total_days * 100, 2) if days_up > 0 else round(
            srv_uptime_secs / (total_days * 86400) * 100, 2)
        uptime_pct = min(uptime_pct, 100.0)

    # Build bars — history[0] = today (rightmost bar)
    # Each bar is a column of 3 .uptime-seg divs: HTTP (top), HTTPS (middle), DB (bottom).
    # Segment colour: green=no outages, yellow=partial, red=all-samples-down, grey=no data.
    TITLE = {'ok': 'Operational', 'degraded': 'Degraded', 'down': 'Down', 'no_data': 'No data'}
    bars = []
    import html as _html_mod, json as _json_mod

    def _seg_class(down_n: int, total_n: int) -> str:
        if not total_n:       return 'nodata'
        if down_n == 0:       return 'ok'
        if down_n >= total_n: return 'down'
        return 'partial'

    for h in reversed(history):   # oldest → newest = left → right
        st = h['status']
        causes_json = _html_mod.escape(_json_mod.dumps(h.get('causes', []), ensure_ascii=False))
        if st == 'no_data':
            bars.append(
                f'<div class="uptime-bar" title="{h["date"]}: No data" '
                f'data-date="{h["date"]}" data-status="no_data" '
                f'data-uptime="" data-samples="0" '
                f'data-http-down="0" data-https-down="0" data-db-down="0" '
                f'data-mem-max="0" data-disk-max="0" data-causes="{causes_json}" '
                f'data-net-outages="0" data-net-downtime="0">'
                f'<div class="uptime-seg nodata"></div>'
                f'<div class="uptime-seg nodata"></div>'
                f'<div class="uptime-seg nodata"></div>'
                f'<div class="uptime-seg net-nodata"></div>'
                f'</div>'
            )
        else:
            n         = h['sample_count'] or 0
            http_cls  = _seg_class(h.get('http_down_n',  0), n)
            https_cls = _seg_class(h.get('https_down_n', 0), n)
            db_cls    = _seg_class(h.get('db_down_n',    0), n)
            pct_str   = f" ({h['uptime_pct']}%)" if h['uptime_pct'] is not None else ''
            title     = (f"{h['date']}: {TITLE[st]}{pct_str} · "
                         f"HTTP:{http_cls} HTTPS:{https_cls} DB:{db_cls}")
            _nd       = net_day_hist.get(h['date'], {})
            net_outs  = _nd.get('outage_count', 0) or 0
            net_down  = _nd.get('total_downtime_sec', 0) or 0
            if not _nd and n == 0: net_cls = 'net-nodata'
            elif not _nd:          net_cls = 'net-ok'
            elif net_outs == 0:    net_cls = 'net-ok'
            elif net_down >= 300: net_cls = 'net-down'
            else:                 net_cls = 'net-partial'
            net_title = f'{net_outs} outage(s), {net_down}s total' if net_outs else 'ok'
            bars.append(
                f'<div class="uptime-bar" title="{title}" '
                f'data-date="{h["date"]}" data-status="{st}" '
                f'data-uptime="{h["uptime_pct"] or ""}" data-samples="{n}" '
                f'data-http-down="{h.get("http_down_n", 0)}" '
                f'data-https-down="{h.get("https_down_n", 0)}" '
                f'data-db-down="{h.get("db_down_n", 0)}" '
                f'data-mem-max="{h.get("mem_max", 0)}" '
                f'data-disk-max="{h.get("disk_max", 0)}" '
                f'data-causes="{causes_json}" '
                f'data-net-outages="{net_outs}" data-net-downtime="{net_down}">'
                f'<div class="uptime-seg {http_cls}" title="HTTP: {http_cls}"></div>'
                f'<div class="uptime-seg {https_cls}" title="HTTPS: {https_cls}"></div>'
                f'<div class="uptime-seg {db_cls}" title="DB: {db_cls}"></div>'
                f'<div class="uptime-seg {net_cls}" title="NET: {net_title}"></div>'
                f'</div>'
            )
    uptime_bars_html = '\n'.join(bars)

    # ── overall status ──
    with _net_state_lock:
        _cur_net_outage = _net_monitor_state['outage_id'] is not None
    if not http_up or not https_up or db_ind == 'warn':
        overall_class = 'crit'; overall_text = 'Partial Outage'
    elif cdn_disk['ind'] == 'crit' or root_disk['ind'] == 'crit':
        overall_class = 'crit'; overall_text = 'Critical'
    elif ssl_ind == 'crit':
        overall_class = 'crit'; overall_text = 'TLS Certificate Critical'
    elif _cur_net_outage or ssl_ind == 'warn':
        overall_class = 'warn'; overall_text = 'Degraded'
    else:
        overall_class = 'ok'; overall_text = 'All Systems Operational'

    sessions_color = 'blue' if active_sessions > 0 else ''

    # ── incidents & message board ──
    incidents     = _get_recent_incidents(20)
    board_posts   = _get_message_board(10)

    SEV_IND  = {'critical': 'crit', 'degraded': 'warn'}
    SEV_LABEL = {'critical': 'Major Outage', 'degraded': 'Degraded'}

    def _esc(s: str) -> str:
        import html as _html
        return _html.escape(str(s)) if s else ''

    # Build incident rows HTML
    incident_rows_html = ''
    if incidents:
        for inc in incidents:
            ind   = 'crit' if inc['is_open'] else SEV_IND.get(inc['severity'], 'warn')
            badge_text = 'ONGOING' if inc['is_open'] else 'RESOLVED'
            badge_ind  = 'crit'   if inc['is_open'] else 'ok'
            cause_esc = _esc(inc['cause'])
            detail_esc = _esc(inc['detail'] or '')
            started_esc = _esc(inc['started_at'][:16])
            duration_esc = _esc(inc['duration_str'])
            detail_block = (
                f'<div style="font-size:10px;color:var(--muted);margin-top:4px;font-family:var(--mono)">'
                f'{detail_esc}</div>'
            ) if detail_esc else ''
            incident_rows_html += (
                f'<div class="svc-row">'
                f'  <div class="svc-indicator {ind}"></div>'
                f'  <div class="svc-name" style="flex:1">'
                f'    <div>{cause_esc}</div>'
                f'    {detail_block}'
                f'    <div style="font-size:10px;color:var(--muted);margin-top:2px">started {started_esc} · duration {duration_esc}</div>'
                f'  </div>'
                f'  <div class="svc-badge {badge_ind}">{badge_text}</div>'
                f'</div>'
            )
    else:
        incident_rows_html = (
            '<div style="padding:20px 24px;font-size:12px;color:var(--muted)">No incidents recorded yet.</div>'
        )

    # Build message board HTML
    BOARD_IND = {'info': 'info', 'warning': 'warn', 'critical': 'crit', 'ok': 'ok'}
    board_rows_html = ''
    if board_posts:
        for post in board_posts:
            ind = BOARD_IND.get(post['level'], 'info')
            title_esc = _esc(post['title'])
            body_esc  = _esc(post['body'] or '')
            date_esc  = _esc(post['posted_at'][:16])
            body_block = (
                f'<div style="font-size:11px;color:var(--muted);margin-top:4px">{body_esc}</div>'
            ) if body_esc else ''
            board_rows_html += (
                f'<div class="svc-row">'
                f'  <div class="svc-indicator {ind}"></div>'
                f'  <div class="svc-name" style="flex:1">'
                f'    <div>{title_esc}</div>'
                f'    {body_block}'
                f'    <div style="font-size:10px;color:var(--muted);margin-top:2px">{date_esc}</div>'
                f'  </div>'
                f'  <div class="svc-badge {ind}">{post["level"].upper()}</div>'
                f'</div>'
            )
    else:
        board_rows_html = (
            '<div style="padding:20px 24px;font-size:12px;color:var(--muted)">No announcements.</div>'
        )

    return _render_snippet('status_page.html',
        PUBLIC_DOMAIN=PUBLIC_DOMAIN,
        now_str=now_str,
        overall_class=overall_class,
        overall_text=overall_text,
        # system
        sys_uptime_h=sys_uptime_h,
        sys_uptime_str=sys_uptime_str,
        srv_uptime_h=str(srv_h),
        srv_start_str=srv_start_str,
        # server version
        SERVER_VERSION=SERVER_VERSION,
        # db stats
        user_count=user_count,
        active_sessions=active_sessions,
        sessions_color=sessions_color,
        fluxdrop_files=fluxdrop_files,
        fluxdrop_size_str=fluxdrop_size_str,
        catbox_files=catbox_files,
        catbox_size_str=catbox_size_str,
        active_shares=active_shares,
        expired_shares=expired_shares,
        total_share_views=total_share_views,
        # storage
        cdndisk_avail=cdn_disk['avail'], cdndisk_total=cdn_disk['total'],
        cdndisk_used=cdn_disk['used'],   cdndisk_pct=cdn_disk['pct'],
        cdndisk_ind=cdn_disk['ind'],
        rootdisk_avail=root_disk['avail'], rootdisk_total=root_disk['total'],
        rootdisk_used=root_disk['used'],   rootdisk_pct=root_disk['pct'],
        rootdisk_ind=root_disk['ind'],
        tmpdisk_avail=tmp_disk['avail'], tmpdisk_total=tmp_disk['total'],
        tmpdisk_used=tmp_disk['used'],   tmpdisk_pct=tmp_disk['pct'],
        tmpdisk_ind=tmp_disk['ind'],
        # cpu / mem
        cpu_bars_html=cpu_bars_html,
        mem_pct=mem_pct, mem_total=mem_total, mem_used=mem_used, mem_avail=mem_avail,
        swap_pct=swap_pct, swap_total=swap_total, swap_used=swap_used,
        # services
        HTTP_PORT=HTTP_PORT, HTTPS_PORT=HTTPS_PORT,
        http_ind=http_ind, http_status=http_status,
        https_ind=https_ind, https_status=https_status,
        db_ind=db_ind, db_status=db_status, db_size_str=db_size_str,
        ssl_ind=ssl_ind, ssl_status=ssl_status, ssl_detail=ssl_detail,
        # uptime
        uptime_pct=uptime_pct,
        uptime_bars_html=uptime_bars_html,
        # network
        net_rx=net_rx, net_tx=net_tx,
        # incidents & board
        incident_rows_html=incident_rows_html,
        board_rows_html=board_rows_html,
    )

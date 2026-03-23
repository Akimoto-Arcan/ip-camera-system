"""
IP Camera System — Web Dashboard (Flask)

Serves the single-page UI and a JSON API consumed by the frontend.
All heavy lifting (recording, storage management) lives in the recorder
service; this process is read-only except for config writes.
"""

import base64
import json
import logging
import math
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path

import bcrypt
import pymysql
import requests as _req
import urllib3
import yaml
from flask import (Flask, Response, abort, jsonify, redirect, render_template,
                   request, send_file, session, url_for)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("dashboard")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ipcam-admin-secret-change-me")

# ── MySQL auth config ───────────────────────────────────────────────────────────
MYSQL_HOST = os.environ.get("MYSQL_HOST", "192.168.1.158")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", 3306))
MYSQL_USER = os.environ.get("MYSQL_USER", "appuser")
MYSQL_PASS = os.environ.get("MYSQL_PASS", "thereisnospoon")
MYSQL_DB   = os.environ.get("MYSQL_DB",   "Users")


def _check_superadmin(username: str, password: str) -> bool:
    """Return True if username/password is valid and user is SuperAdmin."""
    try:
        conn = pymysql.connect(
            host=MYSQL_HOST, port=MYSQL_PORT,
            user=MYSQL_USER, password=MYSQL_PASS,
            db=MYSQL_DB, connect_timeout=5,
        )
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT password, role, groups FROM users WHERE username=%s AND approved=1 LIMIT 1",
                    (username,)
                )
                row = cur.fetchone()
        if not row:
            return False
        hashed, role, groups = row
        # PHP stores $2y$ prefix; Python bcrypt expects $2b$
        hashed_bytes = hashed.replace("$2y$", "$2b$").encode()
        if not bcrypt.checkpw(password.encode(), hashed_bytes):
            return False
        return role == "SuperAdmin" or "SuperAdmin" in (groups or "")
    except Exception as exc:
        logger.error("MySQL auth error: %s", exc)
        return False

RECORDINGS_PATH = Path(os.environ.get("RECORDINGS_PATH", "/recordings"))
CONFIG_PATH     = Path(os.environ.get("CONFIG_PATH", "/config/cameras.yml"))
FRIGATE_DB_PATH = Path(os.environ.get("FRIGATE_DB_PATH", "/config/frigate.db"))
FRIGATE_URL     = os.environ.get("FRIGATE_URL", "http://localhost:5000")
STATUS_FILE     = RECORDINGS_PATH / ".status.json"
EXCERPTS_PATH   = Path(os.environ.get("EXCERPTS_PATH", "/excerpts"))
VOD_PATH        = Path(os.environ.get("VOD_PATH", "/tmp/vod"))

# Serialise all config reads+writes so concurrent requests don't race on cameras.tmp
_config_lock = threading.Lock()

# ── VOD session state ──────────────────────────────────────────────────────────
_vod_sessions: dict = {}   # session_id → {path, proc, created, camera, known_segs}
_vod_lock = threading.Lock()

# ── VOD segment conversion concurrency control ─────────────────────────────────
# Limits simultaneous ffmpeg transcodes so the server stays responsive.
_convert_sem = threading.Semaphore(3)
_convert_locks: dict = {}          # str(dst) → Lock  (prevents double-conversion)
_convert_locks_mu = threading.Lock()


def _cleanup_old_vod_sessions() -> None:
    cutoff = time.time() - 1800  # 30 minutes (sessions are large; don't hold longer than needed)
    with _vod_lock:
        stale = [sid for sid, s in _vod_sessions.items() if s["created"] < cutoff]
    for sid in stale:
        with _vod_lock:
            sess = _vod_sessions.pop(sid, None)
        if sess:
            proc = sess.get("proc")
            if proc and proc.poll() is None:
                proc.terminate()
            shutil.rmtree(sess["path"], ignore_errors=True)
            logger.debug("VOD session %s cleaned up", sid)
    # Also sweep VOD_PATH for orphaned directories not tracked in _vod_sessions
    if VOD_PATH.is_dir():
        with _vod_lock:
            known = set(_vod_sessions.keys())
        orphan_cutoff = time.time() - 3600
        for d in VOD_PATH.iterdir():
            if d.is_dir() and d.name not in known:
                try:
                    if d.stat().st_mtime < orphan_cutoff:
                        shutil.rmtree(d, ignore_errors=True)
                        logger.info("VOD orphan dir removed: %s", d.name)
                except OSError:
                    pass


def _vod_cleanup_loop() -> None:
    """Background thread that periodically evicts expired VOD sessions."""
    while True:
        time.sleep(300)  # every 5 minutes
        try:
            _cleanup_old_vod_sessions()
        except Exception:
            pass


def _vod_extend_watcher(session_id: str, camera: str, out_dir: Path) -> None:
    """Background: after initial FFmpeg finishes, watch for new recording segments
    and remux them into the HLS playlist so playback extends seamlessly."""
    # Wait for initial FFmpeg to finish
    with _vod_lock:
        sess = _vod_sessions.get(session_id)
    if not sess:
        return
    proc = sess.get("proc")
    if proc:
        try:
            proc.wait(timeout=3600)
        except Exception:
            pass

    playlist_path = out_dir / "index.m3u8"

    # Build video args for each segment: copy H.264, transcode HEVC to H.264
    def _video_args_for(fp: Path) -> list:
        try:
            pr = subprocess.run(
                ["ffprobe", "-v", "error", "-select_streams", "v:0",
                 "-show_entries", "stream=codec_name",
                 "-of", "default=noprint_wrappers=1:nokey=1", str(fp)],
                capture_output=True, text=True, timeout=10,
            )
            vc = pr.stdout.strip().lower()
        except Exception:
            vc = ""
        if vc == "h264":
            return ["-c:v", "copy", "-bsf:v", "h264_mp4toannexb"]
        return ["-c:v", "libx264", "-preset", "fast", "-crf", "23"]

    # After initial FFmpeg finishes, mark playlist as VOD if no new segments exist
    _endlist_written = False

    def _write_endlist():
        nonlocal _endlist_written
        if _endlist_written or not playlist_path.exists():
            return
        try:
            text = playlist_path.read_text()
            if "#EXT-X-ENDLIST" not in text:
                tmp = playlist_path.with_suffix(".tmp")
                tmp.write_text(text.rstrip() + "\n#EXT-X-ENDLIST\n")
                tmp.rename(playlist_path)
                logger.info("VOD %s: marked as ended (EXT-X-ENDLIST)", session_id)
        except OSError:
            pass
        _endlist_written = True

    while True:
        with _vod_lock:
            if session_id not in _vod_sessions:
                return
            known = _vod_sessions[session_id].get("known_segs", set())

        time.sleep(5)

        new_segs = []
        for fp, _ in _frigate_segments(camera):
            if str(fp.resolve()) in known:
                continue
            try:
                st = fp.stat()
                if st.st_size == 0 or time.time() - st.st_mtime < 30:
                    continue
            except OSError:
                continue
            new_segs.append(fp)

        if not new_segs:
            # No new recordings — close the playlist so HLS.js stops at the end
            _write_endlist()
            continue

        seg_counter = len(sorted(out_dir.glob("seg*.ts")))
        try:
            playlist_text = playlist_path.read_text()
        except OSError:
            continue

        # Strip EXT-X-ENDLIST so we can append
        updated = playlist_text.replace("#EXT-X-ENDLIST\n", "")
        appended = False

        for fp in new_segs:
            ts_name = f"seg{seg_counter:05d}.ts"
            ts_path = out_dir / ts_name
            vargs = _video_args_for(fp)
            try:
                result = subprocess.run(
                    ["ffmpeg", "-y", "-i", str(fp),
                     *vargs, "-c:a", "aac", "-ac", "2",
                     "-f", "mpegts", str(ts_path)],
                    capture_output=True, timeout=180,
                )
            except Exception:
                continue
            if result.returncode != 0 or not ts_path.exists() or ts_path.stat().st_size == 0:
                continue
            try:
                dr = subprocess.run(
                    ["ffprobe", "-v", "quiet", "-show_entries", "format=duration",
                     "-of", "default=noprint_wrappers=1:nokey=1", str(fp)],
                    capture_output=True, text=True, timeout=10,
                )
                duration = float(dr.stdout.strip())
            except Exception:
                duration = 10.0
            updated += f"#EXTINF:{duration:.6f},\n{ts_name}\n"
            seg_counter += 1
            known.add(str(fp.resolve()))
            appended = True
            _endlist_written = False  # reset so live edge stays open
            logger.info("VOD %s: extended with %s (%.1fs)", session_id, fp.name, duration)

        if appended:
            tmp = playlist_path.with_suffix(".tmp")
            try:
                tmp.write_text(updated + "#EXT-X-ENDLIST\n")
                tmp.rename(playlist_path)
                with _vod_lock:
                    if session_id in _vod_sessions:
                        _vod_sessions[session_id]["known_segs"] = known
            except OSError:
                pass


def _frigate_segments(camera: str) -> list:
    """
    Return [(Path, datetime), ...] for all non-empty Frigate recordings of
    camera, sorted chronologically.

    Frigate path: RECORDINGS_PATH/<YYYY-MM-DD>/<HH>/<camera>/<MM.SS.mp4>
    Directory names and filenames are in UTC; datetimes returned are naive UTC.
    """
    segs = []
    if not RECORDINGS_PATH.is_dir():
        return segs
    for date_dir in sorted(RECORDINGS_PATH.iterdir()):
        if not date_dir.is_dir() or date_dir.name.startswith("."):
            continue
        try:
            seg_date = datetime.strptime(date_dir.name, "%Y-%m-%d").date()
        except ValueError:
            continue
        for hour_dir in sorted(date_dir.iterdir()):
            if not hour_dir.is_dir():
                continue
            try:
                hour = int(hour_dir.name)
            except ValueError:
                continue
            cam_hour_dir = hour_dir / camera
            if not cam_hour_dir.is_dir():
                continue
            for fp in sorted(cam_hour_dir.glob("*.mp4")):
                try:
                    if fp.stat().st_size == 0:
                        continue
                    parts = fp.stem.split(".")
                    minute = int(parts[0])
                    second = int(parts[1]) if len(parts) > 1 else 0
                    seg_dt_utc = datetime(
                        seg_date.year, seg_date.month, seg_date.day,
                        hour, minute, second,
                    )
                    segs.append((fp, seg_dt_utc))
                except (ValueError, OSError, IndexError):
                    continue
    return segs


def _find_segments_from(camera: str, start_dt: datetime) -> tuple:
    """
    Return ([(Path, offset_seconds), ...], actual_start_dt) for all non-empty
    recording segments at or after start_dt, sorted chronologically.

    The first entry's offset is seconds into that segment where start_dt falls.
    If start_dt falls in a recording gap (> 1800 s to next segment), playback
    begins at the start of the next available segment and offset is 0.
    Returns ([], None) when no recordings exist.
    """
    all_segs = _frigate_segments(camera)

    if not all_segs:
        return [], None, []

    # Find the last segment whose start time is at or before start_dt
    start_idx = 0
    first_offset = 0.0
    for i, (fp, seg_dt) in enumerate(all_segs):
        if seg_dt <= start_dt:
            start_idx = i
            first_offset = (start_dt - seg_dt).total_seconds()

    # If the offset is very large (recording gap), jump to the first segment
    # that actually starts at or after start_dt so FFmpeg doesn't seek past
    # the end of the file and produce empty output.
    if first_offset > 1800:
        future = [(i, fp, seg_dt) for i, (fp, seg_dt) in enumerate(all_segs)
                  if seg_dt >= start_dt]
        if future:
            start_idx, _, first_seg_dt = future[0]
            first_offset = 0.0
            actual_start = first_seg_dt
        else:
            # All recordings are before start_dt; play from the closest one
            first_offset = 0.0
            actual_start = all_segs[start_idx][1]
    else:
        actual_start = start_dt

    seg_slice = all_segs[start_idx:]
    result = [
        (fp, first_offset if i == 0 else 0.0)
        for i, (fp, _) in enumerate(seg_slice)
    ]
    return result, actual_start, seg_slice


# ── Helpers ────────────────────────────────────────────────────────────────────

def _safe_filename(name: str) -> str:
    name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    name = re.sub(r"[^\w\s\-.]", "", name).strip()
    name = re.sub(r"\s+", "_", name)
    name = name.lstrip(".-")
    return name[:80] or "excerpt"


# ── Config helpers ─────────────────────────────────────────────────────────────

def _load_config() -> dict:
    try:
        with open(CONFIG_PATH) as fh:
            return yaml.safe_load(fh) or {}
    except Exception as exc:
        logger.error("Failed to load config: %s", exc)
        return {}


def _save_config(cfg: dict) -> None:
    """Write config atomically. Must be called while holding _config_lock."""
    tmp = CONFIG_PATH.with_suffix(".tmp")
    with open(tmp, "w") as fh:
        yaml.dump(cfg, fh, default_flow_style=False, sort_keys=False)
    tmp.replace(CONFIG_PATH)


def _load_status() -> dict:
    try:
        if STATUS_FILE.exists():
            with open(STATUS_FILE) as fh:
                return json.load(fh)
    except Exception as exc:
        logger.debug("Status read error: %s", exc)
    return {}


# ── Routes — UI ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    cfg = _load_config()
    return render_template("index.html", config=cfg)


@app.route("/recordings")
def recordings_page():
    cfg = _load_config()
    return render_template("recordings.html", config=cfg)


@app.route("/admin")
def admin():
    if not session.get("is_superadmin"):
        return redirect(url_for("admin_login"))
    return render_template("admin.html", username=session.get("admin_user", ""))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if _check_superadmin(username, password):
            session["is_superadmin"] = True
            session["admin_user"] = username
            return redirect(url_for("admin"))
        error = "Invalid credentials or insufficient permissions."
    return render_template("admin_login.html", error=error)


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


# ── DVR proxy ──────────────────────────────────────────────────────────────────
# In-memory cache for static DVR resources (JS/CSS/WASM — no auth needed, rarely change)
_dvr_cache: dict = {}          # (dvr_idx, path) → {"data", "ct", "ts"}
_dvr_cache_lock = threading.Lock()
_DVR_CACHE_TTL = 300           # seconds

# Brief XML cache — fetched once per DVR per hour for auto-login injection
_dvr_brief_cache: dict = {}    # dvr_idx → {"brief": str, "auth": str, "ts": float}
_dvr_brief_lock = threading.Lock()
_DVR_BRIEF_TTL = 3600          # seconds

DVR_USERNAME = os.environ.get("DVR_USERNAME", "admin")
DVR_PASSWORD = os.environ.get("DVR_PASSWORD", "")


def _dvr_auth_header() -> str:
    """Return the Basic Auth header value for the DVR."""
    return "Basic " + base64.b64encode(
        f"{DVR_USERNAME}:{DVR_PASSWORD}".encode()
    ).decode()


def _dvr_get_brief(dvr_idx: int, dvr_ip: str) -> tuple:
    """Fetch Brief XML from DVR; returns (brief_xml, auth_header) or ('', '')."""
    with _dvr_brief_lock:
        cached = _dvr_brief_cache.get(dvr_idx)
        if cached and (time.time() - cached["ts"]) < _DVR_BRIEF_TTL:
            return cached["brief"], cached["auth"]

    auth = _dvr_auth_header()
    try:
        resp = _req.get(
            f"https://{dvr_ip}/cn/xbrief",
            headers={"Authorization": auth},
            verify=False,
            timeout=8,
        )
        if resp.status_code == 200:
            brief = resp.text
            with _dvr_brief_lock:
                _dvr_brief_cache[dvr_idx] = {"brief": brief, "auth": auth, "ts": time.time()}
            return brief, auth
        logger.warning("DVR%d /cn/xbrief returned %d", dvr_idx, resp.status_code)
    except Exception as exc:
        logger.error("DVR%d brief fetch error: %s", dvr_idx, exc)
    return "", ""


def _dvr_host(dvr_idx: int) -> str | None:
    """Return IP for the given DVR index (1-based) from cameras.yml."""
    for cam in _load_config().get("cameras", []):
        if cam.get("type") == "tigersecu":
            sub = cam.get("subcategory", "")
            try:
                idx = int(re.sub(r"[^\d]", "", sub))
            except ValueError:
                continue
            if idx == dvr_idx:
                return cam.get("ip")
    return None


def _dvr_inject(dvr_idx: int, channel: int) -> str:
    """JavaScript injected before </body> of every DVR HTML page served through the proxy.
    URL-rewriting (fetch/XHR/WebSocket) is handled in the <head> injection for webindex.html
    so it is in place before streaming-dvragent.js loads.  For other pages (login.html etc.)
    served via dvr_proxy_resource the head also injects the same overrides.
    This end-of-body script handles callbacks and channel routing only."""
    lskey = f"__dvr_ch_{dvr_idx}"
    return f"""<script>
(function() {{
  var DVR_IDX = {dvr_idx};
  var LS_KEY  = {json.dumps(lskey)};

  /* ── Channel tracking ─────────────────────────────────────────
     Restore channel from localStorage if sessionStorage was wiped
     by login.html's sessionStorage.clear().                       */
  var _urlCh   = new URLSearchParams(window.location.search).get('channel');
  var _stored  = sessionStorage.getItem('__dvr_channel') || localStorage.getItem(LS_KEY);
  var targetCh = _urlCh  ? parseInt(_urlCh,  10)
               : _stored ? parseInt(_stored, 10)
               : {channel};
  if (isNaN(targetCh) || targetCh < 1 || targetCh > 32) targetCh = 1;
  sessionStorage.setItem('__dvr_channel', targetCh);
  localStorage.setItem(LS_KEY, targetCh);

  /* ── webindex.html: auth bridge ────────────────────────────────
     setupPermisson() runs synchronously at page load (head injection
     provides placeholder values so it doesn't redirect) AND again
     inside dvragent_ready_cb() after WASM is ready — that second
     call decodes the values, so they must be real by then.
     We override dvragent_ready_cb to call dvr_utilities_set_permission
     first (which sets dvruser/permission/permissionChannels with real
     WASM-encoded values), then invoke the original callback.          */
  var _isWebindex = (window.location.pathname.indexOf('webindex.html') !== -1 ||
                     window.location.pathname === '/dvr-proxy/' + DVR_IDX + '/' ||
                     window.location.pathname === '/dvr-proxy/' + DVR_IDX);
  if (_isWebindex) {{
    var _origReadyCb = window.dvragent_ready_cb;
    window.dvragent_ready_cb = function() {{
      if (typeof dvr_utilities_ready === 'function' && !dvr_utilities_ready()) return;
      var _sess = sessionStorage.getItem('dvrsession');
      if (_sess && typeof dvr_utilities_set_permission === 'function') {{
        dvr_utilities_set_permission(_sess).then(function() {{
          sessionStorage.setItem('login_ok', 'OK');
          _origReadyCb && _origReadyCb();
          /* get_channels() runs async inside _origReadyCb and calls preview(16).
             Wait for it to settle, then switch to the correct single-channel view.

             do_live(mode, startCH, endCH) — when startCH is provided it is used
             directly as n0 (no cycling).  When omitted and mode changes, n0=0;
             when omitted and mode stays the same, n0 = division[0]+mode (cycles).
             So we MUST pass startCH and endCH explicitly on the second call.

             Also: do_live has an early-return guard — if n0==division[0] && n1==
             division[1] it does nothing.  After preview(1) sets division=[0,0],
             calling do_live(1,0,0) would early-return (already ch 0).  For all
             other channels the guard doesn't fire.                               */
          setTimeout(function() {{
            var _ch  = parseInt(sessionStorage.getItem('__dvr_channel') || '1', 10);
            var _idx = _ch - 1;
            if (_idx < 0) _idx = 0;
            /* Step 1: click window-1-tab → fires onClick="preview(1)" which
               switches layout to single-channel and calls do_live(1) → ch 0.    */
            var _btn1 = document.getElementById('window-1-tab');
            if (_btn1) {{
              _btn1.click();
              /* Step 2: now that preview(1) has run and division=[0,0], call
                 do_live with explicit startCH/endCH so it goes to _idx directly. */
              setTimeout(function() {{
                if (typeof do_live === 'function') do_live(1, _idx, _idx);
              }}, 300);
            }} else if (typeof do_live === 'function') {{
              do_live(1, _idx, _idx);
            }}
          }}, 1200);
        }}, function(err) {{
          console.warn('[dvr-proxy] webindex set_permission failed:', err);
          _origReadyCb && _origReadyCb();
        }});
      }} else {{
        _origReadyCb && _origReadyCb();
      }}
    }};
    /* Guard: if WASM was somehow already ready, fire now */
    if (typeof dvr_utilities_ready === 'function' && dvr_utilities_ready())
      setTimeout(function() {{ window.dvragent_ready_cb(); }}, 50);
  }}

  /* ── login.html: auto-complete the auth flow ──────────────────
     common.js setupPermisson() redirects to login.html when
     dvruser/permission/permissionChannels aren't in sessionStorage.
     Those values are only set by login_verify() → dvr_utilities_set_permission().
     In the auto-detect path login_verify() never fires because
     clickedLogin=false.  We set it true and override login_verify
     to (a) use the session from sessionStorage (set by check_brief),
     (b) redirect back to webindex.html with the correct channel.   */
  if (window.location.pathname.indexOf('login.html') !== -1) {{
    try {{ clickedLogin = true; }} catch(e) {{ window.clickedLogin = true; }}

    var _origLV = window.login_verify;
    window.login_verify = function() {{
      var _sess = sessionStorage.getItem('dvrsession');
      if (!_sess || typeof dvr_utilities_set_permission !== 'function') {{
        _origLV && _origLV(); return;
      }}
      var _ch = sessionStorage.getItem('__dvr_channel') || localStorage.getItem(LS_KEY) || '1';
      dvr_utilities_set_permission(_sess).then(function() {{
        sessionStorage.setItem('login_ok', 'OK');
        var _u   = typeof dvr_utilities_dec_web_str === 'function'
                   ? dvr_utilities_dec_web_str(sessionStorage.getItem('dvruser') || '') : '';
        var _host = window.location.hostname;
        var _go   = function() {{ window.location.href = 'webindex.html?channel=' + _ch; }};
        if (typeof dvr_utilities_cmd === 'function') {{
          dvr_utilities_cmd('<WebStream USER="' + _u + '" FROM="' + _host + '" Connect="1" />')
            .then(_go, _go);
        }} else {{ _go(); }}
      }}, function(fail) {{
        console.warn('[dvr-proxy] set_permission failed:', fail);
        _origLV && _origLV();
      }});
    }};

    /* If WASM was already ready when this script ran, fire now */
    if (typeof dvr_utilities_ready === 'function' && dvr_utilities_ready())
      setTimeout(function() {{ window.login_verify(); }}, 50);
  }}

  /* ── postMessage channel switching ─────────────────────────── */
  window.addEventListener('message', function(e) {{
    if (e.data && e.data.type === 'dvr_switch_channel') {{
      var ch = parseInt(e.data.channel, 10);
      if (ch >= 1 && ch <= 32) {{
        sessionStorage.setItem('__dvr_channel', ch);
        localStorage.setItem(LS_KEY, ch);
        var idx = ch - 1;
        if (typeof do_live === 'function') do_live(1, idx, idx, false);
      }}
    }}
  }});
}})();
</script>"""


@app.route("/dvr-proxy/<int:dvr_idx>/")
@app.route("/dvr-proxy/<int:dvr_idx>/webindex.html")
def dvr_proxy_page(dvr_idx: int):
    """Fetch DVR webindex.html, rewrite URLs, inject channel-selection script."""
    dvr_ip = _dvr_host(dvr_idx)
    if not dvr_ip:
        abort(404)

    channel = request.args.get("channel", "1")
    try:
        channel = max(1, min(32, int(channel)))
    except (ValueError, TypeError):
        channel = 1

    try:
        resp = _req.get(f"https://{dvr_ip}/webindex.html", verify=False, timeout=8,
                        allow_redirects=True)
        html = resp.text
    except Exception as exc:
        logger.error("DVR proxy page fetch error (DVR%d %s): %s", dvr_idx, dvr_ip, exc)
        abort(502)

    # Pre-authenticate with the DVR so the page never redirects to login.html.
    # The DVR uses HTTP Basic Auth; /cn/xbrief returns the "Brief" XML that
    # webindex.html expects in sessionStorage before it will display the player.
    brief_xml, auth_hdr = _dvr_get_brief(dvr_idx, dvr_ip)
    autologin_js = ""
    if brief_xml and auth_hdr:
        lskey = f"__dvr_ch_{dvr_idx}"
        autologin_js = f"""<script>
(function(){{
  /* ── Session data ─────────────────────────────────────────────
     Set these before any DVR script runs so setupPermisson() and
     WASM initialization find everything they need immediately.   */
  var ch = parseInt(new URLSearchParams(window.location.search).get('channel') || '{channel}', 10);
  if (isNaN(ch) || ch < 1 || ch > 32) ch = {channel};
  sessionStorage.setItem('__dvr_channel', ch);
  try {{ localStorage.setItem({json.dumps(lskey)}, ch); }} catch(e) {{}}
  sessionStorage.setItem('dvrsession', {json.dumps(auth_hdr)});
  sessionStorage.setItem('Brief',      {json.dumps(brief_xml)});
  sessionStorage.setItem('type',       'cn');
  /* Placeholders so synchronous setupPermisson() (runs before WASM is ready)
     doesn't redirect.  Replaced with real values by our dvragent_ready_cb
     override which calls dvr_utilities_set_permission() first.           */
  if (!sessionStorage.getItem('dvruser'))            sessionStorage.setItem('dvruser',            '__pending__');
  if (!sessionStorage.getItem('permission'))         sessionStorage.setItem('permission',         '__pending__');
  if (!sessionStorage.getItem('permissionChannels')) sessionStorage.setItem('permissionChannels', '__pending__');

  /* ── URL rewriter ─────────────────────────────────────────────
     Must live in <head> so it is in place BEFORE streaming-dvragent.js
     loads and potentially caches XHR/fetch references.
     Rewrites /cn/... and /cgi-bin/... through the Flask proxy —
     whether given as a relative path, absolute with the DVR IP,
     or absolute with our own proxy origin (how WASM resolves them). */
  var _DVR_IDX = {dvr_idx};
  var _DVR_IP  = {json.dumps(_dvr_host(dvr_idx) or "")};

  function _rewriteUrl(url) {{
    if (typeof url !== 'string') return url;
    if (url.indexOf('/cn/') === 0 || url.indexOf('/cgi-bin/') === 0)
      return '/dvr-proxy/' + _DVR_IDX + url;
    try {{
      var _u = new URL(url);
      if (_u.pathname.indexOf('/cn/') === 0 || _u.pathname.indexOf('/cgi-bin/') === 0) {{
        var _origins = [window.location.protocol + '//' + window.location.host];
        if (_DVR_IP) {{ _origins.push('https://' + _DVR_IP); _origins.push('http://' + _DVR_IP); }}
        for (var _i = 0; _i < _origins.length; _i++)
          if (url.indexOf(_origins[_i]) === 0)
            return '/dvr-proxy/' + _DVR_IDX + _u.pathname + (_u.search || '');
      }}
    }} catch(e) {{}}
    return url;
  }}

  var _origFetch = window.fetch;
  window.fetch = function(url, opts) {{
    return _origFetch.call(this, _rewriteUrl(url), opts);
  }};

  var _origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {{
    var a = Array.prototype.slice.call(arguments);
    a[1] = _rewriteUrl(url);
    return _origOpen.apply(this, a);
  }};

  var _OrigWS = window.WebSocket;
  window.WebSocket = function(url, protos) {{
    if (typeof url === 'string' && url.indexOf('/streaming') !== -1) {{
      var _proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      url = _proto + '//' + window.location.host + '/dvr-ws/' + _DVR_IDX + '/streaming';
    }}
    return protos !== undefined ? new _OrigWS(url, protos) : new _OrigWS(url);
  }};
  window.WebSocket.prototype = _OrigWS.prototype;
  window.WebSocket.CONNECTING = 0; window.WebSocket.OPEN = 1;
  window.WebSocket.CLOSING    = 2; window.WebSocket.CLOSED = 3;
}})();
</script>
"""

    # Insert <base> (so relative resource URLs resolve through our proxy)
    # and the auto-login script right at the top of <head>.
    base_tag = f'<base href="/dvr-proxy/{dvr_idx}/">'
    head_inject = f"  {base_tag}\n  {autologin_js}" if autologin_js else f"  {base_tag}"
    if "<head>" in html:
        html = html.replace("<head>", "<head>\n" + head_inject, 1)
    elif "<HEAD>" in html:
        html = html.replace("<HEAD>", "<HEAD>\n" + head_inject, 1)
    else:
        html = base_tag + "\n" + autologin_js + html

    # Inject channel-selection / WebSocket-redirect script before </body>
    snippet = _dvr_inject(dvr_idx, channel)
    html = html.replace("</body>", snippet + "\n</body>") if "</body>" in html else html + snippet

    headers = {
        "Content-Type": "text/html; charset=utf-8",
        # Required for SharedArrayBuffer (used by TigerSecu WASM streaming)
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy": "same-origin",
    }
    return html, 200, headers


@app.route("/dvr-proxy/<int:dvr_idx>/<path:res_path>",
           methods=["GET", "POST", "PUT", "OPTIONS"])
def dvr_proxy_resource(dvr_idx: int, res_path: str):
    """Proxy DVR static resources and API calls (cn/*, cgi-bin/*)."""
    dvr_ip = _dvr_host(dvr_idx)
    if not dvr_ip:
        abort(404)

    is_api = res_path.startswith("cn/") or res_path.startswith("cgi-bin/")

    # Serve static resources from cache when available
    cache_key = (dvr_idx, res_path)
    if not is_api and request.method == "GET":
        with _dvr_cache_lock:
            entry = _dvr_cache.get(cache_key)
            if entry and (time.time() - entry["ts"]) < _DVR_CACHE_TTL:
                return Response(entry["data"], status=200,
                                headers={"Content-Type": entry["ct"],
                                         "Cross-Origin-Resource-Policy": "cross-origin"})

    # Forward headers (auth for API, nothing special for static)
    fwd_hdrs = {}
    if "Authorization" in request.headers:
        fwd_hdrs["Authorization"] = request.headers["Authorization"]
    if request.content_type:
        fwd_hdrs["Content-Type"] = request.content_type

    try:
        dvr_resp = _req.request(
            method=request.method,
            url=f"https://{dvr_ip}/{res_path}",
            headers=fwd_hdrs,
            data=request.get_data() if request.method in ("POST", "PUT") else None,
            verify=False,
            timeout=10,
            allow_redirects=not is_api,
        )
    except Exception as exc:
        logger.error("DVR proxy resource error (DVR%d %s %s): %s",
                     dvr_idx, res_path, request.method, exc)
        abort(502)

    ct = dvr_resp.headers.get("Content-Type", "application/octet-stream")
    data = dvr_resp.content

    # Inject base tag + auto-login + control script into any HTML page (login.html etc.)
    if "text/html" in ct and dvr_resp.status_code == 200:
        html = data.decode("utf-8", errors="replace")
        base_tag = f'<base href="/dvr-proxy/{dvr_idx}/">'
        brief_xml, auth_hdr = _dvr_get_brief(dvr_idx, dvr_ip)
        autologin_js = ""
        if brief_xml and auth_hdr:
            _ip = _dvr_host(dvr_idx) or ""
            autologin_js = f"""<script>
(function(){{
  if (!sessionStorage.getItem('Brief')) {{
    sessionStorage.setItem('dvrsession', {json.dumps(auth_hdr)});
    sessionStorage.setItem('Brief',      {json.dumps(brief_xml)});
    sessionStorage.setItem('type',       'cn');
  }}
  /* URL-rewriting overrides — must be in <head> so they are in place
     before streaming-dvragent.js (or its blob) executes.             */
  var _DVR_IDX = {dvr_idx};
  var _DVR_IP  = {json.dumps(_ip)};
  function _rewriteUrl(url) {{
    if (typeof url !== 'string') return url;
    if (url.indexOf('/cn/') === 0 || url.indexOf('/cgi-bin/') === 0)
      return '/dvr-proxy/' + _DVR_IDX + url;
    try {{
      var _u = new URL(url);
      if (_u.pathname.indexOf('/cn/') === 0 || _u.pathname.indexOf('/cgi-bin/') === 0) {{
        var _origins = [window.location.protocol + '//' + window.location.host];
        if (_DVR_IP) {{ _origins.push('https://' + _DVR_IP); _origins.push('http://' + _DVR_IP); }}
        for (var _i = 0; _i < _origins.length; _i++)
          if (url.indexOf(_origins[_i]) === 0)
            return '/dvr-proxy/' + _DVR_IDX + _u.pathname + (_u.search || '');
      }}
    }} catch(e) {{}}
    return url;
  }}
  var _oF = window.fetch;
  window.fetch = function(u, o) {{ return _oF.call(this, _rewriteUrl(u), o); }};
  var _oX = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m, u) {{
    var a = Array.prototype.slice.call(arguments); a[1] = _rewriteUrl(u);
    return _oX.apply(this, a);
  }};
  var _oWS = window.WebSocket;
  window.WebSocket = function(url, p) {{
    if (typeof url === 'string' && url.indexOf('/streaming') !== -1) {{
      var pr = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      url = pr + '//' + window.location.host + '/dvr-ws/' + _DVR_IDX + '/streaming';
    }}
    return p !== undefined ? new _oWS(url, p) : new _oWS(url);
  }};
  window.WebSocket.prototype = _oWS.prototype;
  window.WebSocket.CONNECTING = 0; window.WebSocket.OPEN = 1;
  window.WebSocket.CLOSING    = 2; window.WebSocket.CLOSED = 3;
}})();
</script>
"""
        head_inject = f"  {base_tag}\n  {autologin_js}" if autologin_js else f"  {base_tag}"
        if "<head>" in html:
            html = html.replace("<head>", "<head>\n" + head_inject, 1)
        elif "<HEAD>" in html:
            html = html.replace("<HEAD>", "<HEAD>\n" + head_inject, 1)
        else:
            html = base_tag + "\n" + autologin_js + html
        snippet = _dvr_inject(dvr_idx, 1)   # channel=1; actual channel read from sessionStorage
        html = html.replace("</body>", snippet + "\n</body>") if "</body>" in html else html + snippet
        return Response(html, status=200,
                        headers={"Content-Type": "text/html; charset=utf-8",
                                 "Cross-Origin-Embedder-Policy": "require-corp",
                                 "Cross-Origin-Opener-Policy": "same-origin"})

    # Patch streaming-dvragent.js so the WASM binary always resolves through
    # our proxy regardless of whether the script is loaded directly (<script src>)
    # or via a Blob URL (login.html creates a blob, text-replacing
    # "streaming-dvragent.wasm" with "wasm/streaming-dvragent.wasm" first —
    # that replacement combined with our scriptDirectory patch would produce a
    # double-"wasm/" path and fetch an HTML 404 page instead of the binary).
    # Solution: prepend a Module.locateFile override that hard-codes the .wasm
    # path, and keep the scriptDirectory patch for everything else.
    if res_path.endswith("streaming-dvragent.js") and dvr_resp.status_code == 200:
        proxy_wasm_dir = f"/dvr-proxy/{dvr_idx}/wasm/"
        js_text = data.decode("utf-8", errors="replace")

        # Fix scriptDirectory for direct <script src> loading (webindex.html)
        js_text = js_text.replace(
            "scriptDirectory = document.currentScript.src;",
            f'scriptDirectory = "{proxy_wasm_dir}";'
        )

        # Prepend Module.locateFile so .wasm path is always correct — this
        # handles the blob-URL case where login.html's text replacement would
        # otherwise produce a doubled "wasm/wasm/" prefix.
        prefix = (
            f'(function(){{\n'
            f'  var Module = (typeof Module !== "undefined") ? Module : {{}};\n'
            f'  var _lf = Module.locateFile;\n'
            f'  Module.locateFile = function(path, sd) {{\n'
            f'    if (typeof path === "string" && path.indexOf(".wasm") !== -1)\n'
            f'      return "{proxy_wasm_dir}" + path.split("/").pop();\n'
            f'    return _lf ? _lf(path, sd) : (sd || "") + path;\n'
            f'  }};\n'
            f'  window.Module = Module;\n'
            f'}})();\n'
        )
        js_text = prefix + js_text
        data = js_text.encode("utf-8")
        ct = "application/javascript"

    # Cache static (non-HTML, non-API) resources
    if not is_api and request.method == "GET" and dvr_resp.status_code == 200:
        with _dvr_cache_lock:
            _dvr_cache[cache_key] = {"data": data, "ct": ct, "ts": time.time()}

    resp_headers = {
        "Content-Type": ct,
        "Cross-Origin-Resource-Policy": "cross-origin",
    }
    return Response(data, status=dvr_resp.status_code, headers=resp_headers)


# ── Routes — API ───────────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    status = _load_status()
    cfg = _load_config()

    cameras = {}
    for cam in cfg.get("cameras", []):
        name = cam["name"]
        cam_status = status.get("cameras", {}).get(name, {})
        cameras[name] = {
            "config": {
                "name": name,
                "ip": cam.get("ip", ""),
                "enabled": cam.get("enabled", True),
                "visible": cam.get("visible", True),
                "category": cam.get("category", ""),
                "subcategory": cam.get("subcategory", ""),
                "segment_duration": cam.get("segment_duration", 600),
                "type": cam.get("type", ""),
                "dvr_url": cam.get("dvr_url", ""),
                "channel": cam.get("channel", 0),
            },
            "status": cam_status.get("status", "unknown"),
            "last_frame": cam_status.get("last_frame"),
            "last_updated": cam_status.get("last_updated"),
            "current_file": cam_status.get("current_file"),
            "segments_recorded": cam_status.get("segments_recorded", 0),
            "bytes_recorded": cam_status.get("bytes_recorded", 0),
            "error": cam_status.get("error"),
            "hls_url": f"/go2rtc/api/stream.m3u8?src={name}",
            "live_url": f"/go2rtc/api/stream.mp4?src={name}",
        }

    return jsonify(
        {
            "cameras": cameras,
            "storage": status.get("storage", {}),
            "last_updated": status.get("last_updated"),
            "server_time": datetime.now().astimezone().isoformat(),
        }
    )


@app.route("/api/storage", methods=["GET", "POST"])
def api_storage():
    cfg = _load_config()
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        try:
            new_gb = float(data["max_size_gb"])
        except (KeyError, TypeError, ValueError):
            return jsonify({"error": "max_size_gb must be a number"}), 400
        if new_gb < 0:
            return jsonify({"error": "max_size_gb must be >= 0"}), 400
        cfg.setdefault("storage", {})["max_size_gb"] = new_gb
        _save_config(cfg)
        logger.info("Storage limit updated to %.1f GB via dashboard", new_gb)
        return jsonify({"success": True, "max_size_gb": new_gb})
    return jsonify(cfg.get("storage", {}))


@app.route("/api/cameras", methods=["GET"])
def api_cameras():
    cfg = _load_config()
    return jsonify(cfg.get("cameras", []))


@app.route("/api/layout", methods=["GET", "POST"])
def api_layout():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        with _config_lock:
            cfg = _load_config()
            cfg["layout"] = data
            _save_config(cfg)
        return jsonify({"success": True})
    with _config_lock:
        cfg = _load_config()
    return jsonify(cfg.get("layout", {}))


@app.route("/api/cameras/reachable")
def api_cameras_reachable():
    """Parallel TCP reachability check for all cameras. Fast (2s max)."""
    cfg = _load_config()
    results = {}

    def _check(cam):
        ip = cam.get("ip", "")
        if not ip:
            results[cam["name"]] = False
            return
        cam_type = cam.get("type", "")
        if cam_type == "tigersecu":
            ports = (443, 5000)
        elif cam_type == "swiftconnection":
            ports = (5000, 554)
        else:
            ports = (cam.get("onvif_port", 80), 554)
        for port in ports:
            try:
                with socket.create_connection((ip, port), timeout=2):
                    results[cam["name"]] = True
                    return
            except OSError:
                pass
        results[cam["name"]] = False

    threads = [threading.Thread(target=_check, args=(c,), daemon=True)
               for c in cfg.get("cameras", [])]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3)
    return jsonify(results)


@app.route("/api/cameras/<name>", methods=["PUT"])
def api_edit_camera(name):
    """Update editable fields on a camera (name, ip, rtsp_url, onvif_port, enabled, segment_duration)."""
    data = request.get_json(silent=True) or {}
    rename_msg = None
    with _config_lock:
        cfg = _load_config()
        for cam in cfg.get("cameras", []):
            if cam["name"] == name:
                new_name = data.get("name", "").strip()
                renamed = new_name and new_name != name
                if renamed:
                    if not re.match(r'^[\w\-]+$', new_name):
                        return jsonify({"error": "Name may only contain letters, numbers, hyphens and underscores"}), 400
                    if any(c["name"] == new_name for c in cfg["cameras"]):
                        return jsonify({"error": "A camera with that name already exists"}), 409
                    cam["name"] = new_name
                for field in ("ip", "rtsp_url"):
                    if field in data and str(data[field]).strip():
                        cam[field] = str(data[field]).strip()
                if "onvif_port" in data:
                    try:
                        cam["onvif_port"] = int(data["onvif_port"])
                    except (TypeError, ValueError):
                        pass
                if "enabled" in data:
                    cam["enabled"] = bool(data["enabled"])
                if "segment_duration" in data:
                    try:
                        cam["segment_duration"] = int(data["segment_duration"])
                    except (TypeError, ValueError):
                        pass
                if "category" in data:
                    cam["category"] = str(data["category"]).strip()
                if "subcategory" in data:
                    cam["subcategory"] = str(data["subcategory"]).strip()
                if "dvr_url" in data:
                    cam["dvr_url"] = str(data["dvr_url"]).strip()
                if "channel" in data:
                    try:
                        cam["channel"] = int(data["channel"])
                    except (TypeError, ValueError):
                        pass
                _save_config(cfg)
                logger.info("Camera %s updated: %s", name, cam)
                if renamed:
                    rename_msg = _rename_recordings_dir(name, new_name)
                return jsonify({"success": True, "camera": cam,
                                "rename_note": rename_msg,
                                "restart_required": True})
    return jsonify({"error": "Camera not found"}), 404


def _rename_recordings_dir(old_name: str, new_name: str) -> str:
    """
    Rename (or merge) /recordings/<old_name> → /recordings/<new_name>.
    Returns a human-readable status string.
    """
    old_dir = RECORDINGS_PATH / old_name
    new_dir = RECORDINGS_PATH / new_name

    if not old_dir.exists():
        return "No existing recordings to rename."

    if not new_dir.exists():
        try:
            old_dir.rename(new_dir)
            logger.info("Recordings renamed: %s → %s", old_name, new_name)
            return f"Recordings moved from '{old_name}' to '{new_name}'."
        except OSError as e:
            logger.error("Failed to rename recordings dir: %s", e)
            return f"Warning: could not rename recordings directory ({e})."

    # new_dir already exists — merge day by day
    merged, skipped = 0, 0
    for date_dir in old_dir.iterdir():
        if not date_dir.is_dir():
            continue
        target_date = new_dir / date_dir.name
        target_date.mkdir(exist_ok=True)
        for mp4 in date_dir.glob("*.mp4"):
            dest = target_date / mp4.name
            if dest.exists():
                skipped += 1
                continue
            try:
                mp4.rename(dest)
                merged += 1
            except OSError:
                skipped += 1
    try:
        old_dir.rmdir()   # only removes if empty
    except OSError:
        pass
    logger.info("Recordings merged %s→%s: %d moved, %d skipped", old_name, new_name, merged, skipped)
    return f"Recordings merged into '{new_name}': {merged} segments moved, {skipped} skipped."


@app.route("/api/cameras/toggle", methods=["POST"])
def api_toggle_camera():
    data = request.get_json(silent=True) or {}
    name = data.get("name")
    with _config_lock:
        cfg = _load_config()
        for cam in cfg.get("cameras", []):
            if cam["name"] == name:
                cam["enabled"] = not cam.get("enabled", True)
                _save_config(cfg)
                return jsonify({"success": True, "enabled": cam["enabled"]})
    return jsonify({"error": "Camera not found"}), 404


@app.route("/api/cameras/<name>/visible", methods=["POST"])
def api_set_camera_visible(name):
    data = request.get_json(silent=True) or {}
    with _config_lock:
        cfg = _load_config()
        for cam in cfg.get("cameras", []):
            if cam["name"] == name:
                cam["visible"] = bool(data.get("visible", True))
                _save_config(cfg)
                return jsonify({"success": True, "visible": cam["visible"]})
    return jsonify({"error": "Camera not found"}), 404


# ── Recordings API ─────────────────────────────────────────────────────────────

@app.route("/api/recordings/summary")
def api_recordings_summary():
    """Per-camera summary: available date range and total size.
    Frigate path: RECORDINGS_PATH/<date>/<hour>/<camera>/<MM.SS.mp4>
    """
    result = {}
    if not RECORDINGS_PATH.exists():
        return jsonify(result)
    # Collect data per camera by scanning all date/hour dirs
    cam_dates: dict = {}   # camera -> set of date strings
    cam_bytes: dict = {}   # camera -> total bytes
    for date_dir in sorted(RECORDINGS_PATH.iterdir()):
        if not date_dir.is_dir() or date_dir.name.startswith("."):
            continue
        try:
            datetime.strptime(date_dir.name, "%Y-%m-%d")
        except ValueError:
            continue
        for hour_dir in date_dir.iterdir():
            if not hour_dir.is_dir():
                continue
            for cam_hour_dir in hour_dir.iterdir():
                if not cam_hour_dir.is_dir():
                    continue
                cam = cam_hour_dir.name
                segs = list(cam_hour_dir.glob("*.mp4"))
                if not segs:
                    continue
                try:
                    total = sum(f.stat().st_size for f in segs)
                except OSError:
                    total = 0
                cam_dates.setdefault(cam, set()).add(date_dir.name)
                cam_bytes[cam] = cam_bytes.get(cam, 0) + total
    for cam, dates in cam_dates.items():
        sorted_dates = sorted(dates)
        result[cam] = {
            "dates": sorted_dates,
            "first_date": sorted_dates[0],
            "last_date": sorted_dates[-1],
            "size_mb": round(cam_bytes.get(cam, 0) / 1024 ** 2, 1),
        }
    return jsonify(result)


@app.route("/api/recordings/dates")
def api_recording_dates():
    """Per-camera list of dates with recording counts.
    Frigate path: RECORDINGS_PATH/<date>/<hour>/<camera>/<MM.SS.mp4>
    """
    result = {}
    if not RECORDINGS_PATH.exists():
        return jsonify(result)
    cam_date_counts: dict = {}  # camera -> {date -> count}
    for date_dir in sorted(RECORDINGS_PATH.iterdir(), reverse=True):
        if not date_dir.is_dir() or date_dir.name.startswith("."):
            continue
        try:
            datetime.strptime(date_dir.name, "%Y-%m-%d")
        except ValueError:
            continue
        for hour_dir in date_dir.iterdir():
            if not hour_dir.is_dir():
                continue
            for cam_hour_dir in hour_dir.iterdir():
                if not cam_hour_dir.is_dir():
                    continue
                cam = cam_hour_dir.name
                count = sum(1 for f in cam_hour_dir.glob("*.mp4") if f.stat().st_size > 0)
                if count:
                    cam_date_counts.setdefault(cam, {})
                    cam_date_counts[cam][date_dir.name] = (
                        cam_date_counts[cam].get(date_dir.name, 0) + count
                    )
    for cam, date_counts in cam_date_counts.items():
        result[cam] = [
            {"date": d, "segments": c}
            for d, c in sorted(date_counts.items(), reverse=True)
        ]
    return jsonify(result)


# ── VOD (on-demand playback from recordings) ──────────────────────────────────

def _ensure_ts_seg(src: Path, dst: Path) -> bool:
    """Convert one source MP4 → MPEG-TS (H.264 720p).
    Thread-safe: per-segment lock prevents duplicate conversions;
    semaphore caps concurrent ffmpeg processes at 3."""
    # Fast path — already done
    if dst.is_file() and dst.stat().st_size > 0:
        return True
    # Get or create a per-segment lock
    key = str(dst)
    with _convert_locks_mu:
        if key not in _convert_locks:
            _convert_locks[key] = threading.Lock()
        seg_lock = _convert_locks[key]
    with seg_lock:
        # Re-check inside the lock (another thread may have just finished)
        if dst.is_file() and dst.stat().st_size > 0:
            return True
        tmp = dst.with_suffix(".tmp.ts")
        try:
            with _convert_sem:   # at most 3 concurrent ffmpeg processes
                result = subprocess.run(
                    ["ffmpeg", "-y", "-i", str(src),
                     "-vf", "scale=1280:720",
                     "-c:v", "libx264", "-preset", "ultrafast", "-crf", "28",
                     "-threads", "2",
                     "-c:a", "copy",
                     "-f", "mpegts", str(tmp)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=60,
                )
            if result.returncode == 0 and tmp.is_file():
                tmp.rename(dst)
                return True
        except Exception:
            pass
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        return False


@app.route("/api/recordings/<camera>/vod", methods=["POST"])
def start_vod(camera):
    """
    Start a VOD session by concatenating source recordings into a single seekable MP4.
    Body: {"from": "<UTC ISO>", "hours": <float>}
    Returns: {"session_id", "url", "actual_start", "window_start", "window_end", "timeline"}
    """
    _cleanup_old_vod_sessions()

    if not re.match(r'^[\w\-]+$', camera):
        return jsonify({"error": "Invalid camera name"}), 400

    data = request.get_json(silent=True) or {}
    from_str = data.get("from", "")
    try:
        normalised = re.sub(r"\.\d+Z?$", "", from_str).replace("Z", "") + "+00:00"
        start_dt = datetime.fromisoformat(normalised).replace(tzinfo=None)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid 'from' datetime"}), 400

    segments, actual_start, seg_slice = _find_segments_from(camera, start_dt)

    # Exclude segments still being written by Frigate
    now_ts = time.time()
    segments = [(fp, off) for fp, off in segments if (now_ts - fp.stat().st_mtime) > 30]

    if not segments:
        return jsonify({"error": "No recordings found at or after that time"}), 404

    max_hours = min(float(data.get("hours", 12.0)), 48.0)
    max_files = max(1, int(max_hours * 360))
    segments  = segments[:max_files]

    session_id = str(uuid.uuid4())[:12]
    out_dir = VOD_PATH / session_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Build timeline immediately (no ffmpeg needed) ─────────────────────────
    fp_to_utc = {str(fp.resolve()): dt for fp, dt in seg_slice}
    durations: list[float] = []
    for i, (fp, _) in enumerate(segments):
        if i + 1 < len(segments):
            curr_dt = fp_to_utc.get(str(fp.resolve()))
            next_dt = fp_to_utc.get(str(segments[i + 1][0].resolve()))
            if curr_dt and next_dt:
                d = (next_dt - curr_dt).total_seconds()
                durations.append(round(max(1.0, min(60.0, d)), 3))
            else:
                durations.append(12.0)
        else:
            durations.append(12.0)

    timeline = []
    vid_off  = 0.0
    for i, (fp, _) in enumerate(segments):
        seg_utc = fp_to_utc.get(str(fp.resolve()))
        if seg_utc is None:
            continue
        epoch_s = int(seg_utc.replace(tzinfo=timezone.utc).timestamp())
        timeline.append([epoch_s, round(vid_off, 1)])
        vid_off += durations[i] if i < len(durations) else 12.0

    from datetime import timedelta
    win_start = actual_start if actual_start else start_dt
    win_end   = win_start + timedelta(seconds=max_hours * 3600)

    # ── Register session and kick off background ffmpeg concat ────────────────
    concat_file = out_dir / "concat.txt"
    concat_file.write_text(
        "\n".join(f"file '{fp}'" for fp, _ in segments) + "\n"
    )
    output_mp4 = out_dir / "video.mp4"

    with _vod_lock:
        _vod_sessions[session_id] = {
            "path":     str(out_dir),
            "proc":     None,
            "created":  time.time(),
            "camera":   camera,
            "building": True,
            "error":    None,
        }

    def _build():
        try:
            result = subprocess.run(
                ["ffmpeg", "-y", "-f", "concat", "-safe", "0",
                 "-i", str(concat_file),
                 "-c", "copy",
                 str(output_mp4)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=600,
            )
            ok = result.returncode == 0 and output_mp4.is_file()
            with _vod_lock:
                if session_id in _vod_sessions:
                    _vod_sessions[session_id]["building"] = False
                    if not ok:
                        _vod_sessions[session_id]["error"] = "ffmpeg failed"
            if ok:
                logger.info("VOD %s ready: %s UTC, %d segs, %.1f h, %.0f MB",
                            session_id, start_dt.isoformat(), len(segments),
                            max_hours, output_mp4.stat().st_size / 1e6)
            else:
                logger.error("VOD %s: ffmpeg concat failed", session_id)
        except Exception as exc:
            logger.error("VOD %s build error: %s", session_id, exc)
            with _vod_lock:
                if session_id in _vod_sessions:
                    _vod_sessions[session_id]["building"] = False
                    _vod_sessions[session_id]["error"] = str(exc)

    threading.Thread(target=_build, daemon=True).start()

    resp = {
        "session_id":   session_id,
        "building":     True,
        "url":          f"/vod/{session_id}/video.mp4",
        "actual_start": win_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_start": win_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_end":   win_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timeline":     timeline,
    }
    return jsonify(resp)


@app.route("/vod/<session_id>/<path:filename>")
def serve_vod_file(session_id, filename):
    """Serve a VOD HLS playlist or segment."""
    with _vod_lock:
        sess = _vod_sessions.get(session_id)
    if not sess:
        # Container restart clears _vod_sessions; fall back to on-disk session dir.
        if not re.match(r'^[0-9a-f\-]{8,36}$', session_id):
            abort(404)
        candidate = (VOD_PATH / session_id).resolve()
        try:
            candidate.relative_to(VOD_PATH.resolve())
        except ValueError:
            abort(404)
        if not candidate.is_dir():
            abort(404)
        sess = {"path": str(candidate)}

    if "/" in filename or filename.startswith("."):
        abort(403)

    target = (Path(sess["path"]) / filename).resolve()
    try:
        target.relative_to(Path(sess["path"]).resolve())
    except ValueError:
        abort(403)

    # For .ts: convert on-demand if the pre-converter hasn't reached it yet.
    if filename.endswith(".ts"):
        if not (target.is_file() and target.stat().st_size > 0):
            with _vod_lock:
                seg_map = (sess or {}).get("seg_map", {})
            src_path = seg_map.get(filename)
            if src_path:
                _ensure_ts_seg(Path(src_path), target)
        if not target.is_file():
            abort(404)
        return send_file(str(target), mimetype="video/mp2t")

    if filename.endswith(".m3u8"):
        if not target.is_file():
            abort(404)
        return send_file(str(target), mimetype="application/vnd.apple.mpegurl")

    if filename.endswith(".mp4"):
        if not target.is_file():
            abort(404)
        return send_file(str(target), mimetype="video/mp4", conditional=True)

    abort(400)


@app.route("/api/recordings/<camera>/vod/<session_id>/status")
def vod_status(camera, session_id):
    """Poll build progress. Returns {building, error, url}."""
    with _vod_lock:
        sess = _vod_sessions.get(session_id)
    if not sess:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({
        "building": sess.get("building", False),
        "error":    sess.get("error"),
        "url":      f"/vod/{session_id}/video.mp4",
    })


# ── Excerpts API ───────────────────────────────────────────────────────────────

@app.route("/api/excerpts", methods=["GET"])
def api_excerpts():
    EXCERPTS_PATH.mkdir(parents=True, exist_ok=True)
    excerpts = []
    for fp in sorted(EXCERPTS_PATH.glob("*.mp4"), key=lambda f: f.stat().st_mtime, reverse=True):
        try:
            stat = fp.stat()
            excerpts.append({
                "filename": fp.name,
                "size_mb": round(stat.st_size / 1024 ** 2, 1),
                "created": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
        except OSError:
            pass
    return jsonify(excerpts)


@app.route("/api/excerpts", methods=["POST"])
def api_create_excerpt():
    data       = request.get_json(silent=True) or {}
    source_rel = data.get("source", "").lstrip("/")
    name       = str(data.get("name", "")).strip()
    start      = data.get("start", 0)
    duration   = data.get("duration")

    if not source_rel:
        return jsonify({"error": "source is required"}), 400
    if not name:
        return jsonify({"error": "name is required"}), 400
    try:
        start = float(start)
    except (TypeError, ValueError):
        return jsonify({"error": "start must be a number"}), 400
    if duration is not None:
        try:
            duration = float(duration)
            if duration <= 0:
                duration = None
        except (TypeError, ValueError):
            return jsonify({"error": "duration must be a number or null"}), 400

    source_path = (RECORDINGS_PATH / source_rel).resolve()
    try:
        source_path.relative_to(RECORDINGS_PATH.resolve())
    except ValueError:
        return jsonify({"error": "Invalid source path"}), 403
    if not source_path.is_file():
        return jsonify({"error": "Source recording not found"}), 404

    label     = _safe_filename(name)
    cam_name  = re.sub(r"[^\w\-]", "_", source_rel.split("/")[0])
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name  = f"{label}__{cam_name}__{timestamp}.mp4"
    out_path  = EXCERPTS_PATH / out_name

    EXCERPTS_PATH.mkdir(parents=True, exist_ok=True)

    cmd = ["ffmpeg", "-y", "-i", str(source_path), "-ss", str(start)]
    if duration:
        cmd += ["-t", str(duration)]
    cmd += ["-c", "copy", str(out_path)]

    logger.info("Creating excerpt: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "FFmpeg timed out"}), 500
    except FileNotFoundError:
        return jsonify({"error": "ffmpeg not found in container"}), 500

    if result.returncode != 0:
        logger.error("FFmpeg failed: %s", result.stderr[-500:])
        return jsonify({"error": "FFmpeg failed", "detail": result.stderr[-300:]}), 500

    stat = out_path.stat()
    logger.info("Excerpt saved: %s (%.1f MB)", out_name, stat.st_size / 1024 ** 2)
    return jsonify({"success": True, "filename": out_name,
                    "size_mb": round(stat.st_size / 1024 ** 2, 1)}), 201


@app.route("/api/excerpts/from-range", methods=["POST"])
def api_create_excerpt_from_range():
    """
    Create an excerpt by absolute time range from completed recording segments.
    Body: {camera, from: "YYYY-MM-DDTHH:MM:SS" (local), to: "...", name}
    """
    data   = request.get_json(silent=True) or {}
    camera = str(data.get("camera", "")).strip()
    name   = str(data.get("name", "")).strip()
    from_s = data.get("from", "")
    to_s   = data.get("to", "")

    if not all([camera, name, from_s, to_s]):
        return jsonify({"error": "camera, name, from, to are all required"}), 400
    if not re.match(r'^[\w\-]+$', camera):
        return jsonify({"error": "Invalid camera name"}), 400

    try:
        # Parse with TZ awareness, then convert to server local time for
        # comparison against segment filenames (which use server local time).
        from_dt = datetime.fromisoformat(from_s.replace("Z", "+00:00"))
        to_dt   = datetime.fromisoformat(to_s.replace("Z",   "+00:00"))
        # Convert to local naive datetime so it matches segment filename times
        from_dt = from_dt.astimezone().replace(tzinfo=None)
        to_dt   = to_dt.astimezone().replace(tzinfo=None)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid datetime format"}), 400
    if to_dt <= from_dt:
        return jsonify({"error": "'to' must be after 'from'"}), 400

    segments, _, _seg_slice = _find_segments_from(camera, from_dt)
    now_ts = time.time()
    segments = [
        (fp, off) for fp, off in segments
        if (now_ts - fp.stat().st_mtime) > 30
    ]
    if not segments:
        return jsonify({"error": "No completed recording segments found for that time. "
                                 "The active segment is still recording — wait until it "
                                 "finishes or pick an earlier time."}), 404

    total_duration = (to_dt - from_dt).total_seconds()
    first_offset   = segments[0][1]

    label     = _safe_filename(name)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name  = f"{label}__{camera}__{timestamp}.mp4"
    out_path  = EXCERPTS_PATH / out_name
    EXCERPTS_PATH.mkdir(parents=True, exist_ok=True)

    concat_path = EXCERPTS_PATH / f".concat_{timestamp}.txt"
    try:
        with open(concat_path, "w") as fh:
            for fp, _ in segments:
                fh.write(f"file '{fp}'\n")

        cmd = [
            "ffmpeg", "-y",
            "-ss", str(first_offset),
            "-t",  str(total_duration),
            "-f", "concat", "-safe", "0", "-i", str(concat_path),
            "-c", "copy",
            str(out_path),
        ]
        logger.info("Creating time-range excerpt: %s → %s (%.0fs)", from_s, to_s, total_duration)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "FFmpeg timed out"}), 500
    except FileNotFoundError:
        return jsonify({"error": "ffmpeg not found"}), 500
    finally:
        try:
            concat_path.unlink()
        except OSError:
            pass

    if result.returncode != 0:
        logger.error("FFmpeg failed: %s", result.stderr[-500:])
        return jsonify({"error": "FFmpeg failed", "detail": result.stderr[-300:]}), 500

    stat = out_path.stat()
    logger.info("Time-range excerpt saved: %s (%.1f MB)", out_name, stat.st_size / 1024 ** 2)
    return jsonify({"success": True, "filename": out_name,
                    "size_mb": round(stat.st_size / 1024 ** 2, 1)}), 201


@app.route("/api/excerpts/<path:filename>", methods=["DELETE"])
def api_delete_excerpt(filename):
    if "/" in filename or "\\" in filename or filename.startswith("."):
        return jsonify({"error": "Invalid filename"}), 400
    target = (EXCERPTS_PATH / filename).resolve()
    try:
        target.relative_to(EXCERPTS_PATH.resolve())
    except ValueError:
        return jsonify({"error": "Forbidden"}), 403
    if not target.is_file():
        return jsonify({"error": "Not found"}), 404
    target.unlink()
    logger.info("Excerpt deleted: %s", filename)
    return jsonify({"success": True})


# ── File serving ───────────────────────────────────────────────────────────────

@app.route("/recordings/<path:filepath>")
def serve_recording(filepath):
    target = (RECORDINGS_PATH / filepath).resolve()
    try:
        target.relative_to(RECORDINGS_PATH.resolve())
    except ValueError:
        abort(403)
    if not target.is_file():
        abort(404)
    return send_file(str(target), mimetype="video/mp4", conditional=True)


@app.route("/excerpts/<path:filepath>")
def serve_excerpt(filepath):
    target = (EXCERPTS_PATH / filepath).resolve()
    try:
        target.relative_to(EXCERPTS_PATH.resolve())
    except ValueError:
        abort(403)
    if not target.is_file():
        abort(404)
    return send_file(str(target), mimetype="video/mp4", conditional=True)


@app.route("/api/recordings/<camera>", methods=["DELETE"])
def api_delete_camera_recordings(camera):
    """Delete all recordings for a camera directory (including orphaned ones)."""
    if not session.get("is_superadmin"):
        return jsonify({"error": "Unauthorized"}), 403
    # Frigate manages its own retention (continuous.days in config).
    # Manual per-camera deletion is not supported in Frigate mode.
    return jsonify({"error": "Manual deletion not supported — Frigate handles retention automatically"}), 400


@app.route("/api/recordings/orphans")
def api_orphan_recordings():
    """List recording directories that have no matching camera in config."""
    if not session.get("is_superadmin"):
        return jsonify({"error": "Unauthorized"}), 403
    cfg = _load_config()
    configured = {c["name"] for c in cfg.get("cameras", [])}
    orphans = []
    # With Frigate, find camera names that appear in recordings but not in config
    if RECORDINGS_PATH.exists():
        seen_cameras: set = set()
        for date_dir in RECORDINGS_PATH.iterdir():
            if not date_dir.is_dir() or date_dir.name.startswith("."):
                continue
            for hour_dir in date_dir.iterdir():
                if not hour_dir.is_dir():
                    continue
                for cam_dir in hour_dir.iterdir():
                    if cam_dir.is_dir():
                        seen_cameras.add(cam_dir.name)
        for cam in seen_cameras:
            if cam not in configured:
                segs = list(RECORDINGS_PATH.rglob(f"*/{cam}/*.mp4"))
                size_mb = sum(f.stat().st_size for f in segs if f.is_file()) / (1024 * 1024)
                orphans.append({"name": cam, "size_mb": round(size_mb, 1)})
    return jsonify(orphans)


@app.route("/api/recordings/<path:camera>/motion")
def api_motion(camera: str):
    """
    Return motion intensities for a camera between two UTC epoch timestamps.

    Query params:
      from  – start epoch seconds (float)
      to    – end   epoch seconds (float)

    Response: { "motion": [[start_epoch_s, end_epoch_s, motion_pixels], ...] }
    Each entry covers one recording segment where motion > 0.
    """
    try:
        from_ts = float(request.args["from"])
        to_ts   = float(request.args["to"])
    except (KeyError, ValueError):
        return jsonify({"error": "from and to query params required (epoch seconds)"}), 400

    if not FRIGATE_DB_PATH.exists():
        return jsonify({"motion": []})

    try:
        con = sqlite3.connect(f"file:{FRIGATE_DB_PATH}?mode=ro", uri=True,
                              check_same_thread=False, timeout=5)
        cur = con.execute(
            """
            SELECT start_time, end_time, motion
            FROM   recordings
            WHERE  camera     = ?
              AND  end_time   > ?
              AND  start_time < ?
              AND  motion     > 0
            ORDER  BY start_time
            """,
            (camera, from_ts, to_ts),
        )
        rows = [
            [round(r[0], 3), round(r[1], 3), int(r[2])]
            for r in cur.fetchall()
        ]
        con.close()
    except Exception as exc:
        logger.warning("motion query failed: %s", exc)
        return jsonify({"motion": []})

    return jsonify({"motion": rows})


# ── Entrypoint ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    VOD_PATH.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=_vod_cleanup_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=8080, debug=False)

"""
IP Camera System — Web Dashboard (Flask)

Serves the single-page UI and a JSON API consumed by the frontend.
All heavy lifting (recording, storage management) lives in the recorder
service; this process is read-only except for config writes.
"""

import base64
import hashlib
import hmac
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
from typing import Optional
from pathlib import Path

import bcrypt
import pymysql
import requests as _req
import urllib.parse
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

# ── Auth backend selection ──────────────────────────────────────────────────────
# Set AUTH_BACKEND=file to use config/users.yml instead of MySQL
AUTH_BACKEND = os.environ.get("AUTH_BACKEND", "file").lower()
USERS_FILE   = Path(os.environ.get("USERS_PATH", "/config/users.yml"))

# ── MySQL auth config (only used when AUTH_BACKEND=mysql) ──────────────────────
MYSQL_HOST = os.environ.get("MYSQL_HOST", "192.168.1.158")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", 3306))
MYSQL_USER = os.environ.get("MYSQL_USER", "appuser")
MYSQL_PASS = os.environ.get("MYSQL_PASS", "thereisnospoon")
MYSQL_DB   = os.environ.get("MYSQL_DB",   "Users")

# ── HMAC-signed SSO shared secret (FMS production dashboard) ────────────────────
SSO_SECRET = os.environ.get("SSO_SECRET", "fms-cam-sso-2026-K9x$mP!qW3rT")


# ── File-based auth helpers ────────────────────────────────────────────────────

def _load_users_file() -> list:
    """Load users from the YAML file."""
    if not USERS_FILE.exists():
        return []
    try:
        with open(USERS_FILE) as f:
            data = yaml.safe_load(f) or {}
        return data.get("users", [])
    except Exception as exc:
        logger.error("Failed to load users file: %s", exc)
        return []


def _save_users_file(users: list) -> None:
    """Write users back to the YAML file."""
    tmp = USERS_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        yaml.dump({"users": users}, f, default_flow_style=False, sort_keys=False)
    tmp.replace(USERS_FILE)


def _file_authenticate(username: str, password: str) -> Optional[dict]:
    """Authenticate against users.yml."""
    for u in _load_users_file():
        if u.get("username") != username:
            continue
        if not u.get("approved", False):
            return None
        stored = u.get("password", "")
        hashed_bytes = stored.replace("$2y$", "$2b$").encode()
        try:
            if not bcrypt.checkpw(password.encode(), hashed_bytes):
                return None
        except Exception:
            return None
        role = u.get("role", "Operator")
        is_sa = role == "SuperAdmin"
        return {
            "username": username,
            "role": role,
            "is_superadmin": is_sa,
            "reset": bool(u.get("reset", False)),
        }
    return None


def _file_check_superadmin(username: str, password: str) -> bool:
    """Check SuperAdmin status from users.yml."""
    result = _file_authenticate(username, password)
    return result is not None and result["is_superadmin"]


def _file_change_password(username: str, new_hash: str) -> bool:
    """Update a user's password in users.yml."""
    users = _load_users_file()
    for u in users:
        if u["username"] == username:
            u["password"] = new_hash
            u["reset"] = False
            _save_users_file(users)
            return True
    return False


# ── MySQL auth helpers ─────────────────────────────────────────────────────────

def _mysql_check_superadmin(username: str, password: str) -> bool:
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


def _mysql_authenticate(username: str, password: str) -> Optional[dict]:
    """Authenticate user against MySQL."""
    try:
        conn = pymysql.connect(
            host=MYSQL_HOST, port=MYSQL_PORT,
            user=MYSQL_USER, password=MYSQL_PASS,
            db=MYSQL_DB, connect_timeout=5,
        )
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT password, role, groups, reset FROM users WHERE username=%s AND approved=1 LIMIT 1",
                    (username,)
                )
                row = cur.fetchone()
        if not row:
            return None
        hashed, role, groups, reset = row
        hashed_bytes = hashed.replace("$2y$", "$2b$").encode()
        if not bcrypt.checkpw(password.encode(), hashed_bytes):
            return None
        is_superadmin = role == "SuperAdmin" or "SuperAdmin" in (groups or "")
        return {"username": username, "role": role, "is_superadmin": is_superadmin, "reset": bool(reset)}
    except Exception as exc:
        logger.error("MySQL auth error: %s", exc)
        return None


# ── Unified auth dispatch ──────────────────────────────────────────────────────

def _check_superadmin(username: str, password: str) -> bool:
    if AUTH_BACKEND == "mysql":
        return _mysql_check_superadmin(username, password)
    return _file_check_superadmin(username, password)


def _authenticate_user(username: str, password: str) -> Optional[dict]:
    if AUTH_BACKEND == "mysql":
        return _mysql_authenticate(username, password)
    return _file_authenticate(username, password)


def _user_can_see_camera(cam: dict, role: str) -> bool:
    """Return True if a user with *role* may view this camera."""
    allowed = cam.get("allowed_roles") or ["Supervisor"]
    # SuperAdmin-only cameras: only SuperAdmin can see them
    if "SuperAdmin" in allowed and role != "SuperAdmin":
        return False
    # Admin-only cameras: SuperAdmin and Admin can see them
    if "Admin" in allowed and role not in ("SuperAdmin", "Admin"):
        return False
    # All other cameras: SuperAdmin/Admin bypass role filtering
    if role in ("SuperAdmin", "Admin"):
        return True
    return role in allowed


RECORDINGS_PATH = Path(os.environ.get("RECORDINGS_PATH", "/recordings"))
CONFIG_PATH     = Path(os.environ.get("CONFIG_PATH", "/config/cameras.yml"))
FRIGATE_DB_PATH = Path(os.environ.get("FRIGATE_DB_PATH", "/config/frigate.db"))
FRIGATE_URL         = os.environ.get("FRIGATE_URL", "http://localhost:5000")
FRIGATE_CONFIG_PATH = Path(os.environ.get("FRIGATE_CONFIG_PATH", "/frigate-config/config.yml"))
STATUS_FILE     = RECORDINGS_PATH / ".status.json"
EXCERPTS_PATH   = Path(os.environ.get("EXCERPTS_PATH", "/excerpts"))
VOD_PATH        = Path(os.environ.get("VOD_PATH", "/tmp/vod"))
CHUNKS_PATH     = Path(os.environ.get("CHUNKS_PATH", "/chunks"))

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


# ── Pre-built hourly chunk helpers ─────────────────────────────────────────────

def _chunk_file(camera: str, date_str: str, hour_str: str) -> Path:
    return CHUNKS_PATH / camera / f"{date_str}_{hour_str}.mp4"


def _build_one_chunk(camera: str, date_str: str, hour_str: str) -> bool:
    """Concatenate one hour of raw Frigate segments into a single chunk MP4."""
    cam_hour_dir = RECORDINGS_PATH / date_str / hour_str / camera
    if not cam_hour_dir.is_dir():
        return False
    segs = sorted(cam_hour_dir.glob("*.mp4"))
    if not segs:
        return False
    out = _chunk_file(camera, date_str, hour_str)
    if out.exists() and out.stat().st_size > 0:
        return True
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp.mp4")
    concat_txt = out.with_suffix(".concat.txt")
    concat_txt.write_text("\n".join(f"file '{seg}'" for seg in segs) + "\n")
    try:
        r = subprocess.run(
            ["ffmpeg", "-y", "-f", "concat", "-safe", "0",
             "-i", str(concat_txt), "-c", "copy", str(tmp)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180,
        )
        if r.returncode == 0 and tmp.is_file():
            tmp.rename(out)
            concat_txt.unlink(missing_ok=True)
            logger.info("Chunk ready: %s %s_%s (%.0f MB)",
                        camera, date_str, hour_str, out.stat().st_size / 1e6)
            return True
    except Exception as exc:
        logger.warning("Chunk build failed %s %s_%s: %s", camera, date_str, hour_str, exc)
    for p in (tmp, concat_txt):
        try: p.unlink(missing_ok=True)
        except Exception: pass
    return False


def _chunk_builder_loop() -> None:
    """Background thread: builds hourly chunk files for all completed recording hours."""
    while True:
        try:
            now = datetime.utcnow()
            current_slot = (now.strftime("%Y-%m-%d"), now.strftime("%H"))
            if RECORDINGS_PATH.exists():
                for date_dir in sorted(RECORDINGS_PATH.iterdir(), reverse=True):
                    if not date_dir.is_dir() or date_dir.name.startswith("."):
                        continue
                    try:
                        datetime.strptime(date_dir.name, "%Y-%m-%d")
                    except ValueError:
                        continue
                    for hour_dir in sorted(date_dir.iterdir()):
                        if not hour_dir.is_dir():
                            continue
                        if (date_dir.name, hour_dir.name) == current_slot:
                            continue  # still being written by Frigate
                        for cam_dir in hour_dir.iterdir():
                            if not cam_dir.is_dir():
                                continue
                            if not _chunk_file(cam_dir.name, date_dir.name, hour_dir.name).exists():
                                _build_one_chunk(cam_dir.name, date_dir.name, hour_dir.name)
                                time.sleep(0.5)
        except Exception as exc:
            logger.warning("Chunk builder error: %s", exc)
        time.sleep(300)  # re-scan every 5 minutes


def _resolve_vod_inputs(camera: str, segments: list, fp_to_utc: dict) -> list:
    """Return list of file paths for ffmpeg concat, substituting hourly chunk files
    where available instead of thousands of raw segment files."""
    result = []
    i = 0
    while i < len(segments):
        fp, _ = segments[i]
        seg_dt = fp_to_utc.get(str(fp.resolve()))
        if seg_dt is None:
            result.append(str(fp))
            i += 1
            continue
        date_str = seg_dt.strftime("%Y-%m-%d")
        hour_str = seg_dt.strftime("%H")
        chunk = _chunk_file(camera, date_str, hour_str)
        if chunk.exists() and chunk.stat().st_size > 0:
            result.append(str(chunk))
            # Skip all raw segments belonging to this same hour
            while i < len(segments):
                fp2, _ = segments[i]
                dt2 = fp_to_utc.get(str(fp2.resolve()))
                if dt2 and dt2.strftime("%Y-%m-%d_%H") == f"{date_str}_{hour_str}":
                    i += 1
                else:
                    break
        else:
            result.append(str(fp))
            i += 1
    return result


# ── VOD cache ──────────────────────────────────────────────────────────────────
_VOD_CACHE_TTL = 86400  # 24 hours


def _vod_cache_path(camera: str, start_dt: datetime, hours: float) -> Path:
    key = f"{camera}_{start_dt.strftime('%Y%m%d_%H%M')}_{int(hours)}h.mp4"
    return CHUNKS_PATH / "_cache" / key


def _cleanup_vod_cache() -> None:
    cache_dir = CHUNKS_PATH / "_cache"
    if not cache_dir.exists():
        return
    cutoff = time.time() - _VOD_CACHE_TTL
    for f in cache_dir.glob("*.mp4"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                logger.info("VOD cache expired: %s", f.name)
        except Exception:
            pass


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
    """Background thread that periodically evicts expired VOD sessions and cache."""
    while True:
        time.sleep(300)  # every 5 minutes
        try:
            _cleanup_old_vod_sessions()
            _cleanup_vod_cache()
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


def _frigate_segments(camera: str, from_date: str = None) -> list:
    """
    Return [(Path, datetime), ...] for all non-empty Frigate recordings of
    camera, sorted chronologically.

    Frigate path: RECORDINGS_PATH/<YYYY-MM-DD>/<HH>/<camera>/<MM.SS.mp4>
    Directory names and filenames are in UTC; datetimes returned are naive UTC.

    If from_date is given (YYYY-MM-DD string), only scan that date and later
    to avoid walking the entire recording tree.
    """
    segs = []
    if not RECORDINGS_PATH.is_dir():
        return segs
    try:
        date_dirs = sorted(os.scandir(RECORDINGS_PATH), key=lambda e: e.name)
    except OSError:
        return segs
    for date_entry in date_dirs:
        if not date_entry.is_dir() or date_entry.name.startswith("."):
            continue
        if from_date and date_entry.name < from_date:
            continue
        try:
            seg_date = datetime.strptime(date_entry.name, "%Y-%m-%d").date()
        except ValueError:
            continue
        try:
            hour_dirs = sorted(os.scandir(date_entry.path), key=lambda e: e.name)
        except OSError:
            continue
        for hour_entry in hour_dirs:
            if not hour_entry.is_dir():
                continue
            try:
                hour = int(hour_entry.name)
            except ValueError:
                continue
            cam_hour_dir = Path(hour_entry.path) / camera
            if not cam_hour_dir.is_dir():
                continue
            try:
                files = sorted(os.scandir(str(cam_hour_dir)), key=lambda e: e.name)
            except OSError:
                continue
            for f in files:
                if not f.name.endswith(".mp4") or not f.is_file():
                    continue
                try:
                    if f.stat(follow_symlinks=False).st_size == 0:
                        continue
                    parts = f.name[:-4].split(".")
                    minute = int(parts[0])
                    second = int(parts[1]) if len(parts) > 1 else 0
                    seg_dt_utc = datetime(
                        seg_date.year, seg_date.month, seg_date.day,
                        hour, minute, second,
                    )
                    segs.append((Path(f.path), seg_dt_utc))
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
    # Only scan from the requested date onward (skip irrelevant older dirs)
    from_date = start_dt.strftime("%Y-%m-%d")
    all_segs = _frigate_segments(camera, from_date=from_date)

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
    if not session.get("user_role"):
        return redirect(url_for("login", next=request.url))
    return render_template("index.html",
                           username=session.get("username", ""),
                           is_superadmin=session.get("is_superadmin", False))


@app.route("/recordings")
def recordings_page():
    if not session.get("user_role"):
        return redirect(url_for("login", next=request.url))
    return render_template("recordings.html",
                           username=session.get("username", ""),
                           is_superadmin=session.get("is_superadmin", False))


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
            session["user_role"]  = "SuperAdmin"
            session["username"]   = username
            return redirect(url_for("admin"))
        error = "Invalid credentials or insufficient permissions."
    return render_template("admin_login.html", error=error)


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


DOCS_PATH = Path(os.environ.get("DOCS_PATH", "/docs"))

@app.route("/guide")
@app.route("/guide/")
def user_guide():
    guide_file = DOCS_PATH / "user_guide.html"
    if not guide_file.exists():
        abort(404)
    return send_file(str(guide_file), mimetype="text/html")

@app.route("/guide/screenshots/<path:filename>")
def guide_screenshot(filename):
    p = DOCS_PATH / "screenshots" / filename
    if not p.exists() or not p.suffix in (".png", ".jpg", ".jpeg", ".gif", ".webp"):
        abort(404)
    return send_file(str(p), mimetype="image/png")


@app.route("/auto-login")
def auto_login():
    """Token-based SSO entry point. The PHP dashboard creates a short-lived token
    in the ipcam_sso_tokens MySQL table and redirects here with ?token=<token>."""
    token = request.args.get("token", "").strip()
    next_url = request.args.get("next", "")
    if not token:
        return redirect(url_for("login"))
    try:
        conn = pymysql.connect(
            host=MYSQL_HOST, port=MYSQL_PORT,
            user=MYSQL_USER, password=MYSQL_PASS,
            db=MYSQL_DB, connect_timeout=5,
            cursorclass=pymysql.cursors.DictCursor,
        )
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT username, role, is_superadmin FROM ipcam_sso_tokens "
                    "WHERE token=%s AND used=0 AND expires_at > NOW() LIMIT 1",
                    (token,)
                )
                row = cur.fetchone()
                if row:
                    cur.execute("UPDATE ipcam_sso_tokens SET used=1 WHERE token=%s", (token,))
                    conn.commit()
                    session["user_role"]    = row["role"]
                    session["username"]     = row["username"]
                    session["is_superadmin"] = bool(row["is_superadmin"])
                    return redirect(next_url or url_for("index"))
    except Exception as exc:
        logger.error("SSO auto-login error: %s", exc)
    return redirect(url_for("login"))


@app.route("/auth/token")
def sso_token():
    """HMAC-signed SSO entry point used by the FMS production dashboard.

    Token format: <base64-JSON-payload>.<hmac-sha256-hex-signature>
    Payload: {"user": "...", "role": "...", "ts": <unix>, "exp": <unix>}
    """
    token = request.args.get("t", "").strip()
    try:
        parts = token.split(".", 1)
        if len(parts) != 2:
            raise ValueError("malformed token")
        payload_b64, signature = parts
        # Pad base64 if needed
        payload_raw = base64.b64decode(payload_b64 + "==")
        expected_sig = hmac.new(
            SSO_SECRET.encode(), payload_raw, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            raise ValueError("bad signature")
        payload = json.loads(payload_raw)
        if payload.get("exp", 0) < time.time():
            raise ValueError("token expired")
        role = payload.get("role", "")
        session["username"]     = payload["user"]
        session["user_role"]    = role
        session["is_superadmin"] = (role == "SuperAdmin")
        logger.info("SSO /auth/token login: user=%s role=%s", payload["user"], role)
        return redirect(url_for("index"))
    except Exception as exc:
        logger.warning("SSO /auth/token rejected: %s", exc)
        return redirect(url_for("login") + "?error=sso_failed")


@app.route("/auth/fms-redirect")
def fms_redirect():
    """Generate a signed SSO token and redirect the user back to the FMS production dashboard.

    Mirrors /auth/token but in the reverse direction — camera dashboard → FMS.
    """
    if not session.get("user_role"):
        return redirect("http://192.168.1.158/dashboard/dash.php")
    now = int(time.time())
    payload = json.dumps({
        "user": session["username"],
        "role": session.get("user_role", ""),
        "ts":   now,
        "exp":  now + 30,
    }).encode()
    b64 = base64.b64encode(payload).decode()
    sig = hmac.new(SSO_SECRET.encode(), payload, hashlib.sha256).hexdigest()
    token = b64 + "." + sig
    dest = "http://192.168.1.158/dashboard/api/fms_token.php?t=" + urllib.parse.quote(token, safe="")
    logger.info("SSO /auth/fms-redirect: user=%s → FMS", session["username"])
    return redirect(dest)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_role"):
        return redirect(url_for("index"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = _authenticate_user(username, password)
        if user:
            session["user_role"]      = user["role"]
            session["username"]       = user["username"]
            session["is_superadmin"]  = user["is_superadmin"]
            if user.get("reset"):
                return redirect(url_for("change_password"))
            next_url = request.args.get("next") or url_for("index")
            return redirect(next_url)
        error = "Invalid credentials or account not approved."
    return render_template("login.html", error=error)


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if not session.get("user_role"):
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        new_pw  = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if len(new_pw) < 8:
            error = "Password must be at least 8 characters."
        elif new_pw != confirm:
            error = "Passwords do not match."
        else:
            try:
                new_hash = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                if AUTH_BACKEND == "file":
                    if _file_change_password(session["username"], new_hash):
                        return redirect(url_for("index"))
                    else:
                        error = "User not found."
                else:
                    hashed_mysql = new_hash.replace("$2b$", "$2y$")
                    conn = pymysql.connect(
                        host=MYSQL_HOST, port=MYSQL_PORT,
                        user=MYSQL_USER, password=MYSQL_PASS,
                        db=MYSQL_DB, connect_timeout=5,
                    )
                    with conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "UPDATE users SET password=%s, reset=0 WHERE username=%s",
                                (hashed_mysql, session["username"])
                            )
                        conn.commit()
                    return redirect(url_for("index"))
            except Exception as exc:
                logger.error("Password change error: %s", exc)
                error = "Failed to update password. Please try again."
    return render_template("change_password.html", error=error,
                           username=session.get("username", ""))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))



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
                "allowed_roles": cam.get("allowed_roles", ["Supervisor"]),
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

    role = session.get("user_role", "")
    if role:  # only filter if logged in (API could be called without session in some contexts)
        cameras = {n: d for n, d in cameras.items()
                   if _user_can_see_camera(d["config"], role)}

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
    cameras = cfg.get("cameras", [])
    result = []
    for cam in cameras:
        cam_out = dict(cam)
        if "allowed_roles" not in cam_out:
            cam_out["allowed_roles"] = ["Supervisor"]
        result.append(cam_out)
    return jsonify(result)


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
                if "allowed_roles" in data:
                    cam["allowed_roles"] = [r for r in data["allowed_roles"] if isinstance(r, str)]
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


# ── Camera time / ONVIF sync ───────────────────────────────────────────────────

@app.route("/api/cameras/<name>/time")
def api_camera_time(name):
    if not session.get("is_superadmin"):
        return jsonify({"error": "Unauthorized"}), 403
    cfg = _load_config()
    cam = next((c for c in cfg.get("cameras", []) if c["name"] == name), None)
    if not cam:
        return jsonify({"error": "Camera not found"}), 404
    ip = cam.get("ip", "")
    port = cam.get("onvif_port", 80)
    username, password = _onvif_creds(cam)
    try:
        resp = _onvif_soap(ip, port, username, password,
                           "<tds:GetSystemDateAndTime/>")
        if resp.status_code != 200:
            return jsonify({"error": f"Camera returned HTTP {resp.status_code}"}), 502
        txt = resp.text
        def _tag(t):
            m = re.search(rf"<(?:[^:>]+:)?{t}>(\d+)</", txt)
            return int(m.group(1)) if m else None
        year, month, day = _tag("Year"), _tag("Month"), _tag("Day")
        hour, minute, second = _tag("Hour"), _tag("Minute"), _tag("Second")
        if None in (year, month, day, hour, minute, second):
            return jsonify({"error": "Could not parse camera time"}), 502
        from zoneinfo import ZoneInfo
        eastern = ZoneInfo("America/New_York")
        cam_dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
        est_dt = cam_dt.astimezone(eastern)
        return jsonify({"local": est_dt.strftime("%Y-%m-%d %H:%M:%S %Z")})
    except Exception as exc:
        logger.error("ONVIF GetSystemDateAndTime error (%s): %s", name, exc)
        return jsonify({"error": str(exc)}), 502


@app.route("/api/cameras/<name>/time/sync", methods=["POST"])
def api_camera_time_sync(name):
    if not session.get("is_superadmin"):
        return jsonify({"error": "Unauthorized"}), 403
    cfg = _load_config()
    cam = next((c for c in cfg.get("cameras", []) if c["name"] == name), None)
    if not cam:
        return jsonify({"error": "Camera not found"}), 404
    ip = cam.get("ip", "")
    port = cam.get("onvif_port", 80)
    username, password = _onvif_creds(cam)
    from zoneinfo import ZoneInfo
    eastern = ZoneInfo("America/New_York")
    now_utc = datetime.now(tz=timezone.utc)
    is_dst = bool(now_utc.astimezone(eastern).dst())
    body = f"""<tds:SetSystemDateAndTime>
      <tds:DateTimeType>Manual</tds:DateTimeType>
      <tds:DaylightSavings>{'true' if is_dst else 'false'}</tds:DaylightSavings>
      <tds:TimeZone><tt:TZ>EST5EDT,M3.2.0,M11.1.0</tt:TZ></tds:TimeZone>
      <tds:UTCDateTime>
        <tt:Time>
          <tt:Hour>{now_utc.hour}</tt:Hour>
          <tt:Minute>{now_utc.minute}</tt:Minute>
          <tt:Second>{now_utc.second}</tt:Second>
        </tt:Time>
        <tt:Date>
          <tt:Year>{now_utc.year}</tt:Year>
          <tt:Month>{now_utc.month}</tt:Month>
          <tt:Day>{now_utc.day}</tt:Day>
        </tt:Date>
      </tt:UTCDateTime>
    </tds:SetSystemDateAndTime>"""
    try:
        resp = _onvif_soap(ip, port, username, password, body)
        if resp.status_code == 200 and "SetSystemDateAndTimeResponse" in resp.text:
            est_now = now_utc.astimezone(eastern)
            return jsonify({"success": True,
                            "set_to": est_now.strftime("%Y-%m-%d %H:%M:%S %Z")})
        return jsonify({"error": f"Camera returned HTTP {resp.status_code}"}), 502
    except Exception as exc:
        logger.error("ONVIF SetSystemDateAndTime error (%s): %s", name, exc)
        return jsonify({"error": str(exc)}), 502


# ── Pending cameras API ────────────────────────────────────────────────────────

def _onvif_soap(ip: str, port: int, username: str, password: str, body_xml: str) -> "requests.Response":
    """Send an ONVIF SOAP request with WS-Security digest auth."""
    nonce = os.urandom(16)
    nonce_b64 = base64.b64encode(nonce).decode()
    created = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    digest = base64.b64encode(
        hashlib.sha1(nonce + created.encode() + password.encode()).digest()
    ).decode()
    envelope = f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tt="http://www.onvif.org/ver10/schema"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
        <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>{body_xml}</s:Body>
</s:Envelope>"""
    return _req.post(
        f"http://{ip}:{port}/onvif/device_service",
        data=envelope,
        headers={"Content-Type": "application/soap+xml"},
        timeout=8,
        verify=False,
    )


def _onvif_creds(cam: dict) -> tuple[str, str]:
    """Extract ONVIF credentials from camera's RTSP URL, falling back to env vars."""
    from urllib.parse import urlparse
    try:
        p = urlparse(cam.get("rtsp_url", ""))
        if p.username:
            return p.username, p.password or ""
    except Exception:
        pass
    return (os.environ.get("ONVIF_USERNAME", "admin"),
            os.environ.get("ONVIF_PASSWORD", ""))


def _onvif_set_static_ip(current_ip: str, onvif_port: int,
                          username: str, password: str,
                          new_ip: str, prefix_length: int = 24) -> bool:
    """Set a camera to a static IP via ONVIF WS-Security. Returns True on success."""
    import hashlib as _hl, base64 as _b64, os as _os2, datetime as _dt2
    nonce = _os2.urandom(16)
    nonce_b64 = _b64.b64encode(nonce).decode()
    created = _dt2.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    digest = _b64.b64encode(
        _hl.sha1(nonce + created.encode() + password.encode()).digest()
    ).decode()
    body = f"""<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:tt="http://www.onvif.org/ver10/schema"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>{username}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
        <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <tds:SetNetworkInterfaces>
      <tds:InterfaceToken>eth0</tds:InterfaceToken>
      <tds:NetworkInterface>
        <tt:IPv4>
          <tt:Enabled>true</tt:Enabled>
          <tt:Manual>
            <tt:Address>{new_ip}</tt:Address>
            <tt:PrefixLength>{prefix_length}</tt:PrefixLength>
          </tt:Manual>
          <tt:DHCP>false</tt:DHCP>
        </tt:IPv4>
      </tds:NetworkInterface>
    </tds:SetNetworkInterfaces>
  </s:Body>
</s:Envelope>"""
    try:
        resp = _req.post(
            f"http://{current_ip}:{onvif_port}/onvif/device_service",
            data=body,
            headers={"Content-Type": "application/soap+xml"},
            timeout=10,
            verify=False,
        )
        return resp.status_code == 200 and "SetNetworkInterfacesResponse" in resp.text
    except Exception as exc:
        logger.error("ONVIF set IP error: %s", exc)
        return False


def _add_to_frigate_config(name: str, rtsp_url: str) -> bool:
    """Add camera to Frigate's config.yml and trigger a Frigate restart."""
    try:
        if not FRIGATE_CONFIG_PATH.exists():
            logger.warning("Frigate config not found at %s", FRIGATE_CONFIG_PATH)
            return False

        with open(FRIGATE_CONFIG_PATH) as fh:
            fcfg = yaml.safe_load(fh) or {}

        fcfg.setdefault("go2rtc", {}).setdefault("streams", {})[name] = [
            f"ffmpeg:{rtsp_url}#video=h264#audio=copy"
        ]
        fcfg.setdefault("cameras", {})[name] = {
            "ffmpeg": {
                "inputs": [{"path": rtsp_url, "roles": ["record"]}]
            },
            "record":    {"enabled": True},
            "detect":    {"enabled": False, "width": 1920, "height": 1080},
            "snapshots": {"enabled": True},
        }

        tmp = FRIGATE_CONFIG_PATH.with_suffix(".tmp")
        with open(tmp, "w") as fh:
            yaml.dump(fcfg, fh, default_flow_style=False, sort_keys=False)
        tmp.replace(FRIGATE_CONFIG_PATH)

        # Ask Frigate to restart so it picks up the new config
        try:
            _req.post(f"{FRIGATE_URL}/api/restart", timeout=5)
            logger.info("Frigate restart requested after adding %s", name)
        except Exception as exc:
            logger.warning("Frigate restart request failed: %s", exc)

        return True
    except Exception as exc:
        logger.error("Failed to update Frigate config: %s", exc)
        return False


@app.route("/api/cameras/pending")
def api_pending_cameras():
    if not session.get("is_superadmin"):
        return jsonify({"error": "Unauthorized"}), 403
    cfg = _load_config()
    return jsonify(cfg.get("pending_cameras", []))


@app.route("/api/cameras/pending/configure", methods=["POST"])
def api_configure_pending():
    if not session.get("is_superadmin"):
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    current_ip  = data.get("current_ip", "").strip()
    static_ip   = data.get("static_ip", "").strip()
    name        = data.get("name", "").strip()
    category    = data.get("category", "").strip()
    subcategory = data.get("subcategory", "").strip()
    onvif_port  = int(data.get("onvif_port", 80))
    username    = data.get("username", "admin").strip()
    password    = data.get("password", "").strip()

    if not all([current_ip, static_ip, name]):
        return jsonify({"error": "current_ip, static_ip, and name are required"}), 400

    # Set static IP via ONVIF if the IP is changing
    if current_ip != static_ip:
        if not _onvif_set_static_ip(current_ip, onvif_port, username, password, static_ip):
            return jsonify({"error": f"Failed to set static IP on camera at {current_ip}"}), 500

    with _config_lock:
        cfg = _load_config()
        pending = cfg.get("pending_cameras", [])
        pending_cam = next((p for p in pending if p.get("ip") == current_ip), {})

        # Build RTSP URL — swap old IP for new static IP
        rtsp_url = pending_cam.get("rtsp_url") or f"rtsp://{username}:{password}@{static_ip}:554/stream0"
        rtsp_url = rtsp_url.replace(current_ip, static_ip)

        cfg["pending_cameras"] = [p for p in pending if p.get("ip") != current_ip]
        cfg.setdefault("cameras", []).append({
            "name":             name,
            "ip":               static_ip,
            "rtsp_url":         rtsp_url,
            "onvif_port":       onvif_port,
            "enabled":          True,
            "visible":          True,
            "category":         category,
            "subcategory":      subcategory,
            "segment_duration": 600,
            "allowed_roles":    ["Supervisor"],
        })
        _save_config(cfg)
        _summary_cache["ts"] = 0.0

    _add_to_frigate_config(name, rtsp_url)
    return jsonify({"success": True})


@app.route("/api/cameras/pending/<path:ip>", methods=["DELETE"])
def api_dismiss_pending(ip):
    if not session.get("is_superadmin"):
        return jsonify({"error": "Unauthorized"}), 403
    with _config_lock:
        cfg = _load_config()
        cfg["pending_cameras"] = [p for p in cfg.get("pending_cameras", []) if p.get("ip") != ip]
        _save_config(cfg)
    return jsonify({"success": True})


@app.route("/api/cameras/pending/manual", methods=["POST"])
def api_manual_pending():
    """Manually queue a camera IP as pending for configuration."""
    if not session.get("is_superadmin"):
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400
    with _config_lock:
        cfg = _load_config()
        cameras = cfg.get("cameras", [])
        pending = cfg.setdefault("pending_cameras", [])
        if any(c.get("ip") == ip for c in cameras):
            return jsonify({"error": "Camera with this IP already exists"}), 409
        if any(p.get("ip") == ip for p in pending):
            return jsonify({"error": "Already pending"}), 409
        pending.append({"ip": ip, "rtsp_url": "", "onvif_port": 80,
                         "device_name": "", "discovered_at": ""})
        _save_config(cfg)
    return jsonify({"success": True})


# ── Recordings API ─────────────────────────────────────────────────────────────

# ── Recording summary/dates — fast cached approach ─────────────────────────────
# Build the index once in a background thread using only directory listing (no stat),
# then refresh every 5 minutes. API endpoints return instantly from cache.

_rec_index: dict = {
    "summary": {},       # cam -> {dates, first_date, last_date, size_mb}
    "dates":   {},       # cam -> [{date, segments}]
    "ready":   False,
    "lock":    threading.Lock(),
}


def _build_rec_index() -> None:
    """Walk the Frigate recording tree once and populate both summary + dates caches.
    Uses scandir for speed — avoids stat() on individual files where possible."""
    cam_dates: dict = {}     # cam -> set(date_str)
    cam_date_count: dict = {}  # cam -> {date_str -> segment_count}
    cam_bytes: dict = {}     # cam -> total_bytes (estimated)

    if not RECORDINGS_PATH.is_dir():
        return

    try:
        for date_entry in sorted(os.scandir(RECORDINGS_PATH), key=lambda e: e.name):
            if not date_entry.is_dir() or date_entry.name.startswith("."):
                continue
            try:
                datetime.strptime(date_entry.name, "%Y-%m-%d")
            except ValueError:
                continue
            date_str = date_entry.name
            for hour_entry in os.scandir(date_entry.path):
                if not hour_entry.is_dir():
                    continue
                for cam_entry in os.scandir(hour_entry.path):
                    if not cam_entry.is_dir():
                        continue
                    cam = cam_entry.name
                    # Count mp4 files using scandir (no per-file stat needed for count)
                    count = 0
                    size_est = 0
                    for f in os.scandir(cam_entry.path):
                        if f.name.endswith(".mp4") and f.is_file():
                            count += 1
                            try:
                                size_est += f.stat(follow_symlinks=False).st_size
                            except OSError:
                                pass
                    if count:
                        cam_dates.setdefault(cam, set()).add(date_str)
                        cam_date_count.setdefault(cam, {})[date_str] = (
                            cam_date_count.get(cam, {}).get(date_str, 0) + count
                        )
                        cam_bytes[cam] = cam_bytes.get(cam, 0) + size_est
    except OSError as exc:
        logger.warning("Recording index scan error: %s", exc)

    summary = {}
    for cam, dates in cam_dates.items():
        sorted_dates = sorted(dates)
        summary[cam] = {
            "dates": sorted_dates,
            "first_date": sorted_dates[0],
            "last_date": sorted_dates[-1],
            "size_mb": round(cam_bytes.get(cam, 0) / 1024 ** 2, 1),
        }

    dates_result = {}
    for cam, dc in cam_date_count.items():
        dates_result[cam] = [
            {"date": d, "segments": c}
            for d, c in sorted(dc.items(), reverse=True)
        ]

    with _rec_index["lock"]:
        _rec_index["summary"] = summary
        _rec_index["dates"] = dates_result
        _rec_index["ready"] = True


def _rec_index_loop() -> None:
    """Background thread: rebuild the recording index periodically."""
    while True:
        try:
            t0 = time.time()
            _build_rec_index()
            elapsed = time.time() - t0
            logger.info("Recording index built in %.1fs (%d cameras)",
                        elapsed, len(_rec_index["summary"]))
        except Exception as exc:
            logger.warning("Recording index error: %s", exc)
        time.sleep(300)  # refresh every 5 minutes


@app.route("/api/recordings/summary")
def api_recordings_summary():
    """Per-camera summary — returns instantly from background-built cache."""
    with _rec_index["lock"]:
        result = dict(_rec_index["summary"])

    if not result and not _rec_index["ready"]:
        # First request before background thread finishes — build synchronously once
        _build_rec_index()
        with _rec_index["lock"]:
            result = dict(_rec_index["summary"])

    role = session.get("user_role", "")
    if role:
        cfg = _load_config()
        cam_map = {c["name"]: c for c in cfg.get("cameras", []) if "name" in c}
        result = {k: v for k, v in result.items()
                  if _user_can_see_camera(cam_map.get(k, {}), role)}

    return jsonify(result)


@app.route("/api/recordings/dates")
def api_recording_dates():
    """Per-camera date list — returns instantly from background-built cache."""
    with _rec_index["lock"]:
        result = dict(_rec_index["dates"])

    if not result and not _rec_index["ready"]:
        _build_rec_index()
        with _rec_index["lock"]:
            result = dict(_rec_index["dates"])

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


@app.route("/api/recordings/<camera>/instant-vod", methods=["POST"])
def instant_vod(camera):
    """Instant VOD: generates an HLS playlist on the fly from raw Frigate segments.
    No ffmpeg, no concat, no waiting — playback starts immediately.

    Body: {"from": "<UTC ISO>", "hours": <float>}
    Returns: {"url": "...m3u8", "actual_start", "window_start", "window_end", "timeline"}
    """
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
    now_ts = time.time()
    segments = [(fp, off) for fp, off in segments if (now_ts - fp.stat().st_mtime) > 10]

    if not segments:
        return jsonify({"error": "No recordings found at or after that time"}), 404

    max_hours = min(float(data.get("hours", 12.0)), 48.0)
    max_files = max(1, int(max_hours * 360))
    segments = segments[:max_files]

    # Build timeline — separate content durations (for HLS) from wall-clock gaps
    fp_to_utc = {str(fp.resolve()): dt for fp, dt in seg_slice}

    # Content duration: actual video length per segment (~10s for Frigate)
    # Use gap-to-next capped at 15s; gaps larger than that are recording breaks
    content_durs = []
    for i, (fp, _) in enumerate(segments):
        if i + 1 < len(segments):
            curr_dt = fp_to_utc.get(str(fp.resolve()))
            next_dt = fp_to_utc.get(str(segments[i + 1][0].resolve()))
            if curr_dt and next_dt:
                gap = (next_dt - curr_dt).total_seconds()
                content_durs.append(round(max(0.5, min(15.0, gap)), 3))
            else:
                content_durs.append(10.0)
        else:
            content_durs.append(10.0)

    # Timeline: maps wall-clock → video offset (cumulative content durations)
    timeline = []
    vid_off = 0.0
    for i, (fp, _) in enumerate(segments):
        seg_utc = fp_to_utc.get(str(fp.resolve()))
        if seg_utc is None:
            continue
        epoch_s = int(seg_utc.replace(tzinfo=timezone.utc).timestamp())
        timeline.append([epoch_s, round(vid_off, 1), round(content_durs[i], 1)])
        vid_off += content_durs[i]

    from datetime import timedelta
    win_start = actual_start if actual_start else start_dt
    win_end = win_start + timedelta(seconds=max_hours * 3600)

    # Build M3U8 playlist referencing on-demand TS segments
    session_id = str(uuid.uuid4())[:12]
    out_dir = VOD_PATH / session_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # Store segment mapping so serve endpoint can convert on-demand
    seg_map = {}
    max_dur = max(content_durs) if content_durs else 10.0
    lines = [
        "#EXTM3U",
        "#EXT-X-VERSION:3",
        f"#EXT-X-TARGETDURATION:{int(max_dur) + 1}",
        "#EXT-X-PLAYLIST-TYPE:VOD",
        "#EXT-X-MEDIA-SEQUENCE:0",
    ]
    for i, (fp, _) in enumerate(segments):
        dur = content_durs[i] if i < len(content_durs) else 10.0
        ts_name = f"seg_{i:05d}.ts"
        seg_map[ts_name] = str(fp)
        lines.append("#EXT-X-DISCONTINUITY")
        lines.append(f"#EXTINF:{dur:.3f},")
        lines.append(ts_name)
    lines.append("#EXT-X-ENDLIST")
    lines.append("")

    playlist = out_dir / "playlist.m3u8"
    playlist.write_text("\n".join(lines))

    with _vod_lock:
        _vod_sessions[session_id] = {
            "path": str(out_dir), "proc": None,
            "created": time.time(), "camera": camera,
            "building": False, "error": None,
            "seg_map": seg_map,
        }

    logger.info("Instant VOD %s: %s, %d segments, %.1f h",
                session_id, camera, len(segments), max_hours)

    return jsonify({
        "session_id":   session_id,
        "building":     False,
        "url":          f"/vod/{session_id}/playlist.m3u8",
        "hls":          True,
        "actual_start": win_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_start": win_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "window_end":   win_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "timeline":     timeline,
    })


@app.route("/api/recordings/<camera>/vod", methods=["POST"])
def start_vod(camera):
    """
    Fallback VOD: concatenates recordings into a single seekable MP4.
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

    # ── Check VOD cache ───────────────────────────────────────────────────────
    cache_mp4 = _vod_cache_path(camera, win_start, max_hours)
    if cache_mp4.exists() and cache_mp4.stat().st_size > 0:
        # Serve from cache — register a lightweight session pointing at cache file
        session_id = str(uuid.uuid4())[:12]
        # Symlink or copy into a fresh session dir so serve_vod_file works
        out_dir = VOD_PATH / session_id
        out_dir.mkdir(parents=True, exist_ok=True)
        output_mp4 = out_dir / "video.mp4"
        try:
            output_mp4.symlink_to(cache_mp4)
        except Exception:
            shutil.copy2(str(cache_mp4), str(output_mp4))
        with _vod_lock:
            _vod_sessions[session_id] = {
                "path": str(out_dir), "proc": None,
                "created": time.time(), "camera": camera,
                "building": False, "error": None,
            }
        logger.info("VOD %s served from cache (%s)", session_id, cache_mp4.name)
        resp = {
            "session_id": session_id, "building": False,
            "url": f"/vod/{session_id}/video.mp4",
            "actual_start": win_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window_start": win_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window_end":   win_end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "timeline": timeline,
        }
        return jsonify(resp)

    # ── Resolve inputs: use hourly chunks where available ─────────────────────
    input_files = _resolve_vod_inputs(camera, segments, fp_to_utc)
    all_chunks = all(
        str(f).startswith(str(CHUNKS_PATH)) for f in input_files
    )

    # ── Register session and kick off background ffmpeg concat ────────────────
    concat_file = out_dir / "concat.txt"
    concat_file.write_text("\n".join(f"file '{f}'" for f in input_files) + "\n")
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

    src_desc = f"{len(input_files)} chunks" if all_chunks else f"{len(input_files)} inputs ({len(segments)} segs)"

    def _build():
        try:
            result = subprocess.run(
                ["ffmpeg", "-y", "-f", "concat", "-safe", "0",
                 "-i", str(concat_file), "-c", "copy", str(output_mp4)],
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
                logger.info("VOD %s ready: %s, %.1f h, %.0f MB, %s",
                            session_id, start_dt.isoformat(), max_hours,
                            output_mp4.stat().st_size / 1e6, src_desc)
                # Save to cache for future requests
                try:
                    cache_mp4.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(str(output_mp4), str(cache_mp4))
                except Exception as ce:
                    logger.warning("VOD cache write failed: %s", ce)
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

    # For .ts: convert MP4→TS on-demand (HEVC→H.264 for browser compatibility)
    if filename.endswith(".ts"):
        if not (target.is_file() and target.stat().st_size > 0):
            with _vod_lock:
                seg_map = (sess or {}).get("seg_map", {})
            src_path = seg_map.get(filename)
            if src_path and Path(src_path).is_file():
                tmp = target.with_suffix(".tmp.ts")
                try:
                    # Probe codec to decide: stream-copy if H.264, transcode if HEVC
                    probe = subprocess.run(
                        ["ffprobe", "-v", "quiet", "-select_streams", "v:0",
                         "-show_entries", "stream=codec_name", "-of", "csv=p=0",
                         src_path],
                        capture_output=True, text=True, timeout=5,
                    )
                    codec = probe.stdout.strip()
                    if codec == "h264":
                        cmd = ["ffmpeg", "-y", "-i", src_path,
                               "-c", "copy", "-f", "mpegts", str(tmp)]
                    else:
                        # Transcode HEVC→H.264, scale to 720p for speed
                        cmd = ["ffmpeg", "-y", "-i", src_path,
                               "-vf", "scale=-2:720",
                               "-c:v", "libx264", "-preset", "ultrafast",
                               "-crf", "23", "-an",
                               "-f", "mpegts", str(tmp)]
                    subprocess.run(cmd,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=60,
                    )
                    if tmp.is_file() and tmp.stat().st_size > 0:
                        tmp.rename(target)
                except Exception:
                    tmp.unlink(missing_ok=True)
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
    """Poll build progress. Returns {building, error, url, playable}.
    With fragmented MP4, the file is playable before the build finishes."""
    with _vod_lock:
        sess = _vod_sessions.get(session_id)
    if not sess:
        return jsonify({"error": "Session not found"}), 404
    # Fragmented MP4 is playable as soon as ffmpeg writes the first fragments
    playable = False
    try:
        mp4 = Path(sess["path"]) / "video.mp4"
        playable = mp4.is_file() and mp4.stat().st_size > 4096
    except Exception:
        pass
    return jsonify({
        "building": sess.get("building", False),
        "playable": playable,
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
    CHUNKS_PATH.mkdir(parents=True, exist_ok=True)
    (CHUNKS_PATH / "_cache").mkdir(parents=True, exist_ok=True)
    threading.Thread(target=_vod_cleanup_loop, daemon=True).start()
    threading.Thread(target=_chunk_builder_loop, daemon=True).start()
    threading.Thread(target=_rec_index_loop, daemon=True, name="rec-index").start()
    app.run(host="0.0.0.0", port=8080, debug=False)

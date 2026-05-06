"""
Background thread that relocates the moov atom to the start of completed
MP4 recording segments so browsers can begin playback immediately.

FFmpeg's -movflags +faststart is silently ignored when using -f segment,
so we post-process each file after it is written.
"""

import logging
import struct
import subprocess
import threading
import time
from pathlib import Path

log = logging.getLogger("faststart")

# Only process files that haven't been modified for this many seconds
# (ensures FFmpeg is done writing the segment).
_SETTLE_SECONDS = 30


def _needs_faststart(path: Path) -> bool:
    """Return True if the MP4 file has its moov atom after mdat."""
    try:
        with open(path, "rb") as f:
            pos = 0
            while True:
                f.seek(pos)
                hdr = f.read(8)
                if len(hdr) < 8:
                    break
                size = struct.unpack(">I", hdr[:4])[0]
                box = hdr[4:8]
                if box == b"moov":
                    return False  # moov before mdat — already fast-start
                if box == b"mdat":
                    return True   # mdat before moov — needs fix
                if size < 8:
                    break
                pos += size
    except Exception:
        pass
    return False


def _fix_file(path: Path) -> bool:
    """Remux the file with moov at the start. Returns True on success."""
    tmp = path.with_suffix(".faststart.tmp")
    try:
        r = subprocess.run(
            [
                "ffmpeg", "-y",
                "-i", str(path),
                "-c", "copy",
                "-movflags", "+faststart",
                str(tmp),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=120,
        )
        if r.returncode != 0:
            tmp.unlink(missing_ok=True)
            return False
        # Atomic replace
        tmp.replace(path)
        return True
    except Exception as exc:
        log.debug("faststart fix failed for %s: %s", path.name, exc)
        tmp.unlink(missing_ok=True)
        return False


def _scan_and_fix(recordings_root: Path) -> int:
    """Scan for MP4 files needing faststart fix. Returns count of fixed files."""
    now = time.time()
    fixed = 0
    try:
        for mp4 in recordings_root.rglob("*.mp4"):
            # Skip temp files
            if ".faststart." in mp4.name:
                continue
            # Only process files that have settled (FFmpeg done writing)
            try:
                age = now - mp4.stat().st_mtime
            except OSError:
                continue
            if age < _SETTLE_SECONDS:
                continue
            # Only fix recent files (last 2 hours) to avoid re-scanning old ones forever
            if age > 7200:
                continue
            if _needs_faststart(mp4):
                if _fix_file(mp4):
                    fixed += 1
                    log.info("Fixed moov position: %s", mp4)
    except Exception as exc:
        log.debug("Scan error: %s", exc)
    return fixed


def start_background_thread(recordings_root: Path, interval: int = 30) -> threading.Thread:
    """Start a daemon thread that periodically fixes new recordings."""
    def _loop():
        log.info("Faststart fixer started (scanning every %ds)", interval)
        while True:
            try:
                _scan_and_fix(recordings_root)
            except Exception as exc:
                log.debug("Faststart scan error: %s", exc)
            time.sleep(interval)

    t = threading.Thread(target=_loop, daemon=True, name="faststart-fixer")
    t.start()
    return t

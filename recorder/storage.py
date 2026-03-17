"""
Circular-buffer storage manager.

Polls the recordings directory at a configurable interval.
When usage exceeds max_size_bytes, it deletes the oldest MP4 segments
one by one until usage is back under the limit.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("storage")


def _dir_size(path: Path) -> int:
    """Return total byte size of all files under *path*."""
    total = 0
    try:
        for entry in path.rglob("*"):
            if entry.is_file():
                try:
                    total += entry.stat().st_size
                except OSError:
                    pass
    except Exception as exc:
        logger.error("Error calculating directory size: %s", exc)
    return total


def _oldest_mp4(recordings_path: Path) -> Optional[Path]:
    """Return the oldest .mp4 file inside *recordings_path* or None."""
    oldest: Optional[Path] = None
    oldest_mtime = float("inf")

    for cam_dir in recordings_path.iterdir():
        if not cam_dir.is_dir() or cam_dir.name.startswith("."):
            continue
        for fp in cam_dir.rglob("*.mp4"):
            try:
                mtime = fp.stat().st_mtime
                if mtime < oldest_mtime:
                    oldest_mtime = mtime
                    oldest = fp
            except OSError:
                pass

    return oldest


def _prune_empty_dirs(start: Path, stop_at: Path) -> None:
    """Walk up from *start* removing empty directories until *stop_at*."""
    current = start
    while current != stop_at:
        try:
            if current.is_dir() and not any(current.iterdir()):
                current.rmdir()
                current = current.parent
            else:
                break
        except OSError:
            break


class StorageManager:
    """
    Enforces a maximum recordings size by deleting the oldest segments
    whenever the limit is exceeded (circular buffer behaviour).
    """

    def __init__(
        self,
        recordings_path: Path,
        max_size_gb: float,
        check_interval: int,
        status_file: Path,
    ) -> None:
        self.recordings_path = recordings_path
        self.check_interval = check_interval
        self.status_file = status_file
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.set_limit(max_size_gb)

    # ── Public API ────────────────────────────────────────────────────────────

    def set_limit(self, max_size_gb: float) -> None:
        with self._lock:
            self.max_size_bytes = int(max_size_gb * 1024 ** 3) if max_size_gb > 0 else 0
        logger.info(
            "Storage limit set to %s",
            f"{max_size_gb:.1f} GB" if max_size_gb > 0 else "unlimited",
        )

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="storage-manager"
        )
        self._thread.start()
        logger.info("Storage manager started")

    def stop(self) -> None:
        self._running = False

    def current_usage(self) -> dict:
        used = _dir_size(self.recordings_path)
        max_b = self.max_size_bytes
        return {
            "used_bytes": used,
            "used_gb": round(used / 1024 ** 3, 2),
            "max_bytes": max_b,
            "max_gb": round(max_b / 1024 ** 3, 2) if max_b else 0,
            "percent_used": round(used / max_b * 100, 1) if max_b else 0.0,
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while self._running:
            try:
                self._check_and_cleanup()
            except Exception as exc:
                logger.error("Storage manager error: %s", exc)

            # Sleep in 1-second ticks so shutdown is responsive
            for _ in range(self.check_interval):
                if not self._running:
                    break
                time.sleep(1)

    def _check_and_cleanup(self) -> None:
        max_b = self.max_size_bytes
        if max_b == 0:
            # Unlimited — just update the status file
            used = _dir_size(self.recordings_path)
            self._write_status(used, max_b)
            return

        used = _dir_size(self.recordings_path)
        deleted = 0

        while used > max_b:
            oldest = _oldest_mp4(self.recordings_path)
            if oldest is None:
                logger.warning(
                    "Storage over limit (%s / %s GB) but no files to delete",
                    used / 1024 ** 3,
                    max_b / 1024 ** 3,
                )
                break

            try:
                size = oldest.stat().st_size
                oldest.unlink()
                _prune_empty_dirs(oldest.parent, self.recordings_path)
                used -= size
                deleted += 1
                logger.info(
                    "Circular-buffer: deleted %s (%s MB)",
                    oldest,
                    round(size / 1024 ** 2, 1),
                )
            except OSError as exc:
                logger.error("Could not delete %s: %s", oldest, exc)
                break

        if deleted:
            used = _dir_size(self.recordings_path)
            logger.info(
                "Cleanup complete: %d segments removed, %.2f GB now used",
                deleted,
                used / 1024 ** 3,
            )

        self._write_status(used, max_b)

    def _write_status(self, used_bytes: int, max_bytes: int) -> None:
        try:
            existing: dict = {}
            if self.status_file.exists():
                with open(self.status_file) as fh:
                    existing = json.load(fh)

            existing["storage"] = {
                "used_bytes": used_bytes,
                "used_gb": round(used_bytes / 1024 ** 3, 2),
                "max_bytes": max_bytes,
                "max_gb": round(max_bytes / 1024 ** 3, 2) if max_bytes else 0,
                "percent_used": (
                    round(used_bytes / max_bytes * 100, 1) if max_bytes else 0.0
                ),
                "last_updated": datetime.now().isoformat(),
            }

            tmp = self.status_file.with_suffix(".tmp")
            with open(tmp, "w") as fh:
                json.dump(existing, fh, indent=2)
            tmp.replace(self.status_file)
        except Exception as exc:
            logger.debug("Status write error: %s", exc)

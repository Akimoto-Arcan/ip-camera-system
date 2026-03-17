"""
Per-camera FFmpeg manager.

A single FFmpeg process handles one camera and simultaneously:
  1. Writes continuous 10-minute MP4 recording segments  →  /recordings/<name>/
  2. Generates a live HLS stream                          →  /hls/<name>/

Both outputs use stream-copy (no re-encoding), so CPU usage per camera
is minimal even for 17+ cameras.

The recorder restarts automatically on RTSP disconnect with exponential
back-off (5 s → 10 s → … → 60 s cap), then resets to 5 s on success.
"""

import json
import logging
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


class CameraRecorder:
    def __init__(
        self,
        config: dict,
        recordings_root: Path,
        hls_root: Path,
        status_file: Path,
    ) -> None:
        self.name: str = config["name"]
        self.rtsp_url: str = config["rtsp_url"]
        self.segment_duration: int = int(config.get("segment_duration", 600))
        self.enabled: bool = bool(config.get("enabled", True))

        self.recordings_dir = recordings_root / self.name
        self.hls_dir = hls_root / self.name
        self.status_file = status_file

        self._running = False
        self._process: Optional[subprocess.Popen] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        self._segments_recorded = 0
        self._bytes_recorded = 0

        self.log = logging.getLogger(f"camera.{self.name}")

    # ── Public ────────────────────────────────────────────────────────────────

    def start(self) -> None:
        if not self.enabled:
            self._update_status("disabled")
            return
        self._running = True
        self.recordings_dir.mkdir(parents=True, exist_ok=True)
        self.hls_dir.mkdir(parents=True, exist_ok=True)
        self._thread = threading.Thread(
            target=self._record_loop, daemon=True, name=f"rec-{self.name}"
        )
        self._thread.start()
        self.log.info("Recording thread started")

    def stop(self) -> None:
        self._running = False
        with self._lock:
            proc = self._process
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self._update_status("stopped")
        self.log.info("Stopped")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _record_loop(self) -> None:
        retry_delay = 5
        max_delay = 60

        while self._running:
            ok = self._run_ffmpeg()
            if ok:
                retry_delay = 5
            else:
                self.log.warning("Stream lost — retrying in %ds", retry_delay)
                self._update_status("offline")
                for _ in range(retry_delay):
                    if not self._running:
                        return
                    time.sleep(1)
                retry_delay = min(retry_delay * 2, max_delay)

    def _run_ffmpeg(self) -> bool:
        """
        Run one FFmpeg session that writes segments + HLS until it exits.
        Returns True if it ran for at least `segment_duration` seconds
        (i.e. was actually streaming), False on quick failure.
        """
        now = datetime.now()
        # Let FFmpeg resolve both date and time via strftime so that midnight-
        # crossing sessions automatically create the correct date subdirectory
        # instead of putting next-day segments into the session-start directory.
        self.recordings_dir.mkdir(parents=True, exist_ok=True)
        # Pre-create today's date directory (FFmpeg cannot create intermediate dirs).
        # Each _run_ffmpeg call creates it fresh, so midnight-crossing sessions get
        # the correct directory on the next retry.
        (self.recordings_dir / now.strftime("%Y-%m-%d")).mkdir(exist_ok=True)
        seg_pattern = str(self.recordings_dir / "%Y-%m-%d" / "%H-%M-%S.mp4")

        # HLS output
        hls_playlist = str(self.hls_dir / "index.m3u8")
        hls_segment = str(self.hls_dir / "seg%05d.ts")

        cmd = [
            "ffmpeg", "-y",
            # --- Input ---
            "-rtsp_transport", "tcp",
            "-stimeout", "10000000",      # 10 s connection timeout (µs)
            "-i", self.rtsp_url,
            # --- Recording output (video only → MP4 segments) ---
            "-c:v", "copy",
            "-an",
            "-f", "segment",
            "-segment_time", str(self.segment_duration),
            "-segment_format", "mp4",
            "-strftime", "1",
            "-reset_timestamps", "1",
            "-movflags", "+faststart",
            seg_pattern,
            # --- Live HLS output (H.264 for browser compatibility) ---
            "-vf", "scale=1280:-2",
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-g", "50",              # keyframe every 2 s at 25 fps → clean cuts
            "-an",
            "-f", "hls",
            "-hls_time", "2",
            "-hls_list_size", "6",
            "-hls_flags", "delete_segments+discont_start",
            "-hls_segment_filename", hls_segment,
            hls_playlist,
        ]

        self._update_status("connecting", current_file=seg_pattern)
        started_at = time.monotonic()

        with self._lock:
            if not self._running:
                return False
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )

        proc = self._process
        self._update_status("recording", current_file=seg_pattern)

        # Consume stderr in a background thread so the pipe never blocks
        stderr_lines: list[bytes] = []
        def _read_stderr():
            for line in proc.stderr:
                stderr_lines.append(line)
        threading.Thread(target=_read_stderr, daemon=True).start()

        proc.wait()
        elapsed = time.monotonic() - started_at

        # Count newly created segments for this session (today's date dir)
        try:
            today_dir = self.recordings_dir / now.strftime("%Y-%m-%d")
            segs = list(today_dir.glob("*.mp4")) if today_dir.exists() else []
            self._segments_recorded += len(segs)
            self._bytes_recorded += sum(s.stat().st_size for s in segs if s.exists())
        except OSError:
            pass

        if proc.returncode == 0 or elapsed >= self.segment_duration * 0.9:
            self._update_status(
                "recording",
                last_frame=datetime.now().isoformat(),
                segments_recorded=self._segments_recorded,
                bytes_recorded=self._bytes_recorded,
            )
            return True

        # Quick failure — log the last few stderr lines
        error_tail = b"".join(stderr_lines[-10:]).decode("utf-8", errors="replace")
        self.log.error("FFmpeg exited quickly (rc=%d): ...%s", proc.returncode, error_tail[-400:])
        self._update_status(
            "error",
            error=error_tail[-300:],
            segments_recorded=self._segments_recorded,
        )
        return False

    # ── Status helpers ────────────────────────────────────────────────────────

    def _update_status(self, status: str, **kwargs) -> None:
        entry = {
            "status": status,
            "last_updated": datetime.now().isoformat(),
            **kwargs,
        }
        # Keep existing keys that weren't overridden
        try:
            existing_cam: dict = {}
            if self.status_file.exists():
                with open(self.status_file) as fh:
                    data = json.load(fh)
                existing_cam = data.get("cameras", {}).get(self.name, {})
            entry = {**existing_cam, **entry}
        except Exception:
            pass

        self._write_camera_status(entry)

    def _write_camera_status(self, cam_entry: dict) -> None:
        try:
            existing: dict = {}
            if self.status_file.exists():
                with open(self.status_file) as fh:
                    existing = json.load(fh)
            existing.setdefault("cameras", {})[self.name] = cam_entry
            existing["last_updated"] = datetime.now().isoformat()

            tmp = self.status_file.with_suffix(".tmp")
            with open(tmp, "w") as fh:
                json.dump(existing, fh, indent=2)
            tmp.replace(self.status_file)
        except Exception as exc:
            self.log.debug("Status write error: %s", exc)

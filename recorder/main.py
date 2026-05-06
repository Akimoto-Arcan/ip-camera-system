"""
IP Camera Recording System — Main Orchestrator

Reads cameras.yml, starts a CameraRecorder for every enabled camera,
starts the StorageManager, and periodically reloads the config to:
  • pick up cameras added by the ONVIF scanner
  • apply updated storage limits changed via the dashboard
"""

import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Dict

import yaml

from camera import CameraRecorder
from faststart import start_background_thread as start_faststart_fixer
from storage import StorageManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("main")

CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/config/cameras.yml"))
CONFIG_RELOAD_INTERVAL = 30   # seconds between config re-checks


def load_config() -> dict:
    with open(CONFIG_PATH) as fh:
        return yaml.safe_load(fh) or {}


class RecorderManager:
    def __init__(self) -> None:
        self._recorders: Dict[str, CameraRecorder] = {}
        self._storage_manager: StorageManager | None = None
        self._running = False

        cfg = load_config()
        storage_cfg = cfg.get("storage", {})

        self.recordings_path = Path(storage_cfg.get("recordings_path", "/recordings"))
        self.hls_path = Path(os.environ.get("HLS_PATH", "/hls"))
        self.status_file = self.recordings_path / ".status.json"

        self.recordings_path.mkdir(parents=True, exist_ok=True)
        self.hls_path.mkdir(parents=True, exist_ok=True)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._running = True
        cfg = load_config()
        storage_cfg = cfg.get("storage", {})

        self._storage_manager = StorageManager(
            recordings_path=self.recordings_path,
            max_size_gb=float(storage_cfg.get("max_size_gb", 500)),
            check_interval=int(storage_cfg.get("check_interval", 60)),
            status_file=self.status_file,
        )
        self._storage_manager.start()

        self._sync_cameras(cfg.get("cameras", []))
        logger.info("RecorderManager started with %d cameras", len(self._recorders))

    def stop(self) -> None:
        self._running = False
        for rec in list(self._recorders.values()):
            rec.stop()
        if self._storage_manager:
            self._storage_manager.stop()
        logger.info("RecorderManager stopped")

    def run_forever(self) -> None:
        """Block until stopped, reloading config every CONFIG_RELOAD_INTERVAL."""
        while self._running:
            for _ in range(CONFIG_RELOAD_INTERVAL):
                if not self._running:
                    return
                time.sleep(1)
            self._reload_config()

    # ── Config reload ─────────────────────────────────────────────────────────

    def _reload_config(self) -> None:
        try:
            cfg = load_config()
        except Exception as exc:
            logger.warning("Config reload failed: %s", exc)
            return

        # Update storage limit if changed
        storage_cfg = cfg.get("storage", {})
        new_limit = float(storage_cfg.get("max_size_gb", 500))
        if self._storage_manager:
            current = self._storage_manager.max_size_bytes / 1024 ** 3
            if abs(current - new_limit) > 0.01:
                logger.info("Storage limit changed → %.1f GB", new_limit)
                self._storage_manager.set_limit(new_limit)

        self._sync_cameras(cfg.get("cameras", []))

    def _sync_cameras(self, cam_configs: list) -> None:
        """Start recorders for new cameras; stop recorders for removed ones."""
        seen_names: set[str] = set()

        for cam_cfg in cam_configs:
            name = cam_cfg.get("name", "")
            if not name or not cam_cfg.get("rtsp_url", ""):
                continue
            seen_names.add(name)

            if name not in self._recorders:
                rec = CameraRecorder(
                    config=cam_cfg,
                    recordings_root=self.recordings_path,
                    hls_root=self.hls_path,
                    status_file=self.status_file,
                )
                self._recorders[name] = rec
                rec.start()
                time.sleep(0.5)   # stagger starts to reduce simultaneous RTSP load
                logger.info("Started recorder for %s (%s)", name, cam_cfg.get("ip", ""))

        # Stop recorders whose cameras were removed from config
        for name in list(self._recorders.keys()):
            if name not in seen_names:
                logger.info("Camera %s removed from config — stopping recorder", name)
                self._recorders.pop(name).stop()


def main() -> None:
    manager = RecorderManager()

    def _shutdown(sig, frame):
        logger.info("Signal %s received — shutting down", sig)
        manager.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    manager.start()
    start_faststart_fixer(manager.recordings_path, interval=30)
    manager.run_forever()


if __name__ == "__main__":
    main()

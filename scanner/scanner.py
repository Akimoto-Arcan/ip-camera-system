"""
ONVIF WS-Discovery Camera Scanner

Probes configured subnets for ONVIF-compatible cameras.
Newly discovered cameras are placed in a pending_cameras queue in
cameras.yml rather than being added automatically — an admin must
configure the name, static IP, category, and subcategory via the
dashboard before they are activated.

Discovery strategy:
  1. WS-Discovery multicast probe (finds cameras that broadcast themselves)
  2. Unicast ONVIF probe to every IP in each subnet (catches cameras that
     don't respond to multicast, e.g. across VLANs or with multicast disabled)
"""

import datetime
import ipaddress
import logging
import os
import signal
import sys
import time
import threading
from pathlib import Path
from typing import Optional

import requests
import yaml
from wsdiscovery import WSDiscovery
from onvif import ONVIFCamera, exceptions as onvif_exc

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("scanner")

CONFIG_PATH    = Path(os.environ.get("CONFIG_PATH", "/config/cameras.yml"))
ONVIF_USERNAME = os.environ.get("ONVIF_USERNAME", "admin")
ONVIF_PASSWORD = os.environ.get("ONVIF_PASSWORD", "")

# Comma-separated list of subnets to scan, e.g. "192.168.100.0/24,192.168.1.0/24"
_SUBNET_ENV    = os.environ.get("CAMERA_SUBNET", "192.168.100.0/24")
CAMERA_SUBNETS = [s.strip() for s in _SUBNET_ENV.split(",") if s.strip()]

ONVIF_PORTS    = [80, 8080, 8000, 2020]   # common ONVIF HTTP ports
CONNECT_TIMEOUT = 3                         # seconds per IP probe


# ── YAML helpers ──────────────────────────────────────────────────────────────

def _load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as fh:
            return yaml.safe_load(fh) or {}
    return {}


def _save_config(cfg: dict) -> None:
    tmp = CONFIG_PATH.with_suffix(".tmp")
    with open(tmp, "w") as fh:
        yaml.dump(cfg, fh, default_flow_style=False, sort_keys=False)
    tmp.replace(CONFIG_PATH)


# ── ONVIF probe helpers ───────────────────────────────────────────────────────

def _check_onvif_port(ip: str, port: int) -> bool:
    """Return True if the ONVIF device service is reachable."""
    try:
        resp = requests.get(
            f"http://{ip}:{port}/onvif/device_service",
            timeout=CONNECT_TIMEOUT,
        )
        return resp.status_code in (200, 400, 401, 500)  # any response = ONVIF present
    except Exception:
        return False


def _get_rtsp_url(ip: str, port: int, username: str, password: str) -> Optional[str]:
    """Connect to an ONVIF camera and return the primary RTSP stream URL."""
    try:
        cam = ONVIFCamera(ip, port, username, password)
        media = cam.create_media_service()
        profiles = media.GetProfiles()
        if not profiles:
            return None

        token = profiles[0].token
        req = media.create_type("GetStreamUri")
        req.StreamSetup = {
            "Stream": "RTP-Unicast",
            "Transport": {"Protocol": "RTSP"},
        }
        req.ProfileToken = token
        uri_resp = media.GetStreamUri(req)
        return uri_resp.Uri
    except onvif_exc.ONVIFError as exc:
        logger.debug("ONVIF error at %s:%d — %s", ip, port, exc)
    except Exception as exc:
        logger.debug("Error probing %s:%d — %s", ip, port, exc)
    return None


def _get_device_name(ip: str, port: int, username: str, password: str) -> str:
    """Try to retrieve a human-readable device name."""
    try:
        cam = ONVIFCamera(ip, port, username, password)
        device = cam.create_devicemgmt_service()
        info = device.GetDeviceInformation()
        return f"{info.Manufacturer}_{info.Model}".replace(" ", "_")
    except Exception:
        return ""


def _probe_ip(ip: str, username: str, password: str) -> Optional[dict]:
    """Try each known ONVIF port on *ip*. Return a camera dict or None."""
    for port in ONVIF_PORTS:
        if not _check_onvif_port(ip, port):
            continue
        rtsp_url = _get_rtsp_url(ip, port, username, password)
        if rtsp_url:
            device_name = _get_device_name(ip, port, username, password)
            return {
                "ip": ip,
                "onvif_port": port,
                "rtsp_url": rtsp_url,
                "device_name": device_name,
            }
    return None


# ── Queue discovered cameras as pending ───────────────────────────────────────

def _queue_pending(cfg: dict, discovered: list[dict]) -> bool:
    """
    Add newly discovered cameras to cfg["pending_cameras"].
    Skips IPs already in cameras or already pending.
    Returns True if any change was made.
    """
    cameras: list = cfg.get("cameras", [])
    pending: list = cfg.setdefault("pending_cameras", [])

    existing_ips = {c["ip"] for c in cameras if "ip" in c}
    pending_ips  = {c["ip"] for c in pending  if "ip" in c}
    changed = False

    for found in discovered:
        ip = found["ip"]
        if ip in existing_ips or ip in pending_ips:
            continue

        entry = {
            "ip":           ip,
            "rtsp_url":     found.get("rtsp_url", ""),
            "onvif_port":   found.get("onvif_port", 80),
            "device_name":  found.get("device_name", ""),
            "discovered_at": datetime.datetime.utcnow().isoformat(timespec="seconds"),
        }
        pending.append(entry)
        logger.info(
            "Pending camera queued: %s  (%s)",
            ip, found.get("device_name") or "unknown device",
        )
        changed = True

    return changed


# ── Discovery routines ────────────────────────────────────────────────────────

def _ws_discovery_scan(username: str, password: str) -> list[dict]:
    """WS-Discovery multicast probe — returns list of camera dicts."""
    found = []
    try:
        wsd = WSDiscovery()
        wsd.start()
        services = wsd.searchServices()
        wsd.stop()

        for svc in services:
            for xaddr in svc.getXAddrs():
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(xaddr)
                    ip = parsed.hostname
                    port = parsed.port or 80
                    if not ip:
                        continue
                    rtsp = _get_rtsp_url(ip, port, username, password)
                    if rtsp:
                        found.append({
                            "ip": ip,
                            "onvif_port": port,
                            "rtsp_url": rtsp,
                            "device_name": _get_device_name(ip, port, username, password),
                        })
                        logger.info("WS-Discovery found %s:%d", ip, port)
                except Exception as exc:
                    logger.debug("WS-Discovery xaddr parse error: %s", exc)
    except Exception as exc:
        logger.warning("WS-Discovery error: %s", exc)
    return found


def _subnet_scan(subnet: str, username: str, password: str) -> list[dict]:
    """Unicast probe every IP in *subnet* — finds cameras that don't multicast."""
    found = []
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts())
    logger.info("Unicast scanning %d IPs in %s …", len(hosts), subnet)

    results: list[Optional[dict]] = [None] * len(hosts)

    def probe(idx: int, ip: str) -> None:
        results[idx] = _probe_ip(ip, username, password)

    threads = [
        threading.Thread(target=probe, args=(i, str(h)), daemon=True)
        for i, h in enumerate(hosts)
    ]
    chunk = 32
    for start in range(0, len(threads), chunk):
        batch = threads[start : start + chunk]
        for t in batch:
            t.start()
        for t in batch:
            t.join(timeout=CONNECT_TIMEOUT + 2)

    for r in results:
        if r:
            found.append(r)
    return found


# ── Main loop ─────────────────────────────────────────────────────────────────

def run_scan(username: str, password: str, subnets: list[str]) -> None:
    logger.info("Starting camera scan on %s", ", ".join(subnets))

    discovered: list[dict] = []

    # 1. WS-Discovery (fast, catches most cameras)
    ws_found = _ws_discovery_scan(username, password)
    discovered.extend(ws_found)
    logger.info("WS-Discovery found %d camera(s)", len(ws_found))

    # 2. Unicast fallback across all configured subnets
    known_ips = {d["ip"] for d in discovered}
    for subnet in subnets:
        unicast_found = [
            d for d in _subnet_scan(subnet, username, password)
            if d["ip"] not in known_ips
        ]
        discovered.extend(unicast_found)
        known_ips.update(d["ip"] for d in unicast_found)
        logger.info("Unicast scan found %d additional camera(s) on %s", len(unicast_found), subnet)

    if not discovered:
        logger.info("No new cameras found")
        return

    cfg = _load_config()
    if _queue_pending(cfg, discovered):
        _save_config(cfg)
        logger.info("cameras.yml updated with pending cameras")
    else:
        logger.info("No new cameras to add")


def main() -> None:
    scan_interval = int(
        (_load_config().get("scanner") or {}).get("scan_interval", 300)
    )

    def _shutdown(sig, frame):
        logger.info("Shutdown signal received")
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    while True:
        try:
            cfg = _load_config()
            scanner_cfg = cfg.get("scanner") or {}
            username = scanner_cfg.get("onvif_username", ONVIF_USERNAME)
            password = scanner_cfg.get("onvif_password", ONVIF_PASSWORD)
            # Support per-config subnet list or fall back to env var
            subnet_val = scanner_cfg.get("subnet", _SUBNET_ENV)
            subnets = [s.strip() for s in str(subnet_val).split(",") if s.strip()]
            scan_interval = int(scanner_cfg.get("scan_interval", 300))

            run_scan(username, password, subnets)
        except Exception as exc:
            logger.error("Scan error: %s", exc)

        logger.info("Next scan in %d seconds", scan_interval)
        time.sleep(scan_interval)


if __name__ == "__main__":
    main()

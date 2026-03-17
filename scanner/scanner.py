"""
ONVIF WS-Discovery Camera Scanner

Probes the configured subnet for ONVIF-compatible cameras.
Discovered cameras are merged into cameras.yml without overwriting
any user customisations (credentials, segment_duration, etc.).

Discovery strategy:
  1. WS-Discovery multicast probe (finds cameras that broadcast themselves)
  2. Unicast ONVIF probe to every IP in the subnet (catches cameras that
     don't respond to multicast, e.g. across VLANs or with multicast disabled)
"""

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

CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", "/config/cameras.yml"))
ONVIF_USERNAME = os.environ.get("ONVIF_USERNAME", "admin")
ONVIF_PASSWORD = os.environ.get("ONVIF_PASSWORD", "")
CAMERA_SUBNET = os.environ.get("CAMERA_SUBNET", "192.168.100.0/24")

ONVIF_PORTS = [80, 8080, 8000, 2020]   # common ONVIF HTTP ports
CONNECT_TIMEOUT = 3                      # seconds per IP probe


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


def _probe_ip(
    ip: str, username: str, password: str
) -> Optional[dict]:
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


# ── Merge discovered cameras into config ──────────────────────────────────────

def _make_camera_name(ip: str, existing_names: set, device_name: str = "") -> str:
    """Generate a unique camera name from the IP (and optional device name)."""
    octets = ip.split(".")
    base = f"camera_{octets[-1]}"
    if device_name:
        safe = device_name[:20].replace(" ", "_").lower()
        base = f"{safe}_{octets[-1]}"

    name = base
    suffix = 1
    while name in existing_names:
        name = f"{base}_{suffix}"
        suffix += 1
    return name


def _merge_cameras(cfg: dict, discovered: list[dict]) -> bool:
    """
    Merge *discovered* camera dicts into cfg["cameras"].
    Returns True if any change was made.
    """
    cameras: list = cfg.setdefault("cameras", [])
    existing_ips = {c["ip"] for c in cameras if "ip" in c}
    existing_names = {c["name"] for c in cameras if "name" in c}
    changed = False

    for found in discovered:
        ip = found["ip"]
        if ip in existing_ips:
            continue   # already configured — don't touch user settings

        name = _make_camera_name(ip, existing_names, found.get("device_name", ""))
        existing_names.add(name)
        existing_ips.add(ip)

        cameras.append(
            {
                "name": name,
                "ip": ip,
                "rtsp_url": found["rtsp_url"],
                "onvif_port": found["onvif_port"],
                "enabled": True,
                "segment_duration": 600,
            }
        )
        logger.info("Added camera %s at %s  →  %s", name, ip, found["rtsp_url"])
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
                # Extract IP from xaddr like http://192.168.100.10:80/...
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
    # Run up to 32 probes in parallel to keep the scan fast
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

def run_scan(username: str, password: str, subnet: str) -> None:
    logger.info("Starting camera scan on %s", subnet)

    discovered: list[dict] = []

    # 1. WS-Discovery (fast, catches most cameras)
    ws_found = _ws_discovery_scan(username, password)
    discovered.extend(ws_found)
    logger.info("WS-Discovery found %d camera(s)", len(ws_found))

    # 2. Unicast fallback — skip IPs already found via WS-Discovery
    known_ips = {d["ip"] for d in discovered}
    unicast_found = [
        d for d in _subnet_scan(subnet, username, password)
        if d["ip"] not in known_ips
    ]
    discovered.extend(unicast_found)
    logger.info("Unicast scan found %d additional camera(s)", len(unicast_found))

    if not discovered:
        logger.info("No new cameras found")
        return

    cfg = _load_config()
    if _merge_cameras(cfg, discovered):
        _save_config(cfg)
        logger.info("cameras.yml updated")
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
            # Re-read config each cycle in case credentials/subnet changed
            cfg = _load_config()
            scanner_cfg = cfg.get("scanner") or {}
            username = scanner_cfg.get("onvif_username", ONVIF_USERNAME)
            password = scanner_cfg.get("onvif_password", ONVIF_PASSWORD)
            subnet = scanner_cfg.get("subnet", CAMERA_SUBNET)
            scan_interval = int(scanner_cfg.get("scan_interval", 300))

            run_scan(username, password, subnet)
        except Exception as exc:
            logger.error("Scan error: %s", exc)

        logger.info("Next scan in %d seconds", scan_interval)
        time.sleep(scan_interval)


if __name__ == "__main__":
    main()

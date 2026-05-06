<div align="center">

# IP Camera System

### Enterprise-grade camera surveillance, recording & playback — fully self-hosted

[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![Frigate](https://img.shields.io/badge/Frigate-NVR-00C7B7)](https://frigate.video/)
[![Flask](https://img.shields.io/badge/Flask-API-000000?logo=flask)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-Private-red)]()

---

**Live Streams** &bull; **24/7 Recording** &bull; **Instant Playback** &bull; **Motion Detection** &bull; **ONVIF Auto-Discovery** &bull; **SSO Authentication**

</div>

---

## What It Does

A complete IP camera management platform that turns any network of RTSP cameras into a centralized surveillance system with live viewing, continuous recording, and instant DVR-style playback — all running on a single server with Docker.

### Key Features

| Feature | Description |
|---------|-------------|
| **Live Dashboard** | Real-time camera feeds with multi-camera grid view, zoom controls, and fullscreen support |
| **Continuous Recording** | 24/7 recording via Frigate NVR with configurable retention and automatic storage management |
| **Instant Playback** | DVR-style recording playback — click any time on the timeline and video starts in seconds |
| **Motion Timeline** | Visual motion activity overlay on the playback timeline — instantly see when something happened |
| **ONVIF Auto-Discovery** | Automatically finds cameras on your network — no manual IP configuration needed |
| **Camera Time Sync** | One-click ONVIF time synchronization across all cameras |
| **Role-Based Access** | Users see only the cameras they're authorized to view (SuperAdmin, Supervisor, Operator, etc.) |
| **SSO Integration** | HMAC-signed token auth for seamless single sign-on with external systems |
| **Stall Detection** | Auto-reconnects frozen streams without user intervention |
| **Deep Linking** | URL parameters to link directly to specific camera groups from external apps |
| **Clip Export** | Save recording clips to permanent storage for incident review |

---

## Architecture

```
                    +------------------+
                    |   Web Browser    |
                    +--------+---------+
                             |
                    +--------+---------+
                    |   Nginx (:80)    |  Reverse proxy + static file serving
                    +--+----+----+-----+
                       |    |    |
          +------------+    |    +-------------+
          |                 |                  |
+---------+------+  +------+--------+  +------+------+
| Flask Dashboard|  | Frigate NVR   |  | go2rtc      |
|   (:8080)      |  | (:5000)       |  | (:1984)     |
|                |  |               |  |             |
| - Camera UI    |  | - Recording   |  | - Live      |
| - VOD playback |  | - Detection   |  |   streams   |
| - Admin panel  |  | - Storage     |  | - WebRTC    |
| - REST API     |  |   management  |  | - MSE/MP4   |
+----------------+  +-------+-------+  +------+------+
                            |                  |
                    +-------+------------------+------+
                    |     RTSP Cameras (network)      |
                    +---------------------------------+
```

### Containers

| Container | Purpose | Port |
|-----------|---------|------|
| `ipcam-nginx` | Reverse proxy, static files, VOD serving | 80 |
| `ipcam-dashboard` | Flask web app, REST API, VOD builder | 8080 (internal) |
| `ipcam-frigate` | Frigate NVR — recording, detection, go2rtc | 5000, 1984 (host) |
| `ipcam-scanner` | ONVIF auto-discovery daemon | — |

---

## Quick Start

### Prerequisites

- Linux server (RHEL, Ubuntu, Debian)
- Docker & Docker Compose
- Network access to IP cameras (RTSP)
- Storage drive for recordings (recommended: dedicated disk)

### 1. Clone & Configure

```bash
git clone https://github.com/Akimoto-Arcan/ip-camera-system.git
cd ip-camera-system
cp .env.example .env
```

Edit `.env` with your settings:

```env
# Storage paths — point these to your large storage drive
RECORDINGS_DIR=/mnt/ipcam-storage/recordings
VOD_DIR=/mnt/ipcam-storage/vod
EXCERPTS_DIR=/mnt/ipcam-storage/excerpts
HLS_DIR=/mnt/ipcam-storage/hls

# Network
HTTP_PORT=80
CAMERA_SUBNET=192.168.100.0/24

# ONVIF credentials (for auto-discovery)
ONVIF_USERNAME=admin
ONVIF_PASSWORD=yourpassword

# Timezone
TIMEZONE=America/New_York
```

### 2. Create Storage Directories

```bash
sudo mkdir -p /mnt/ipcam-storage/{recordings,vod,chunks,excerpts,hls}
sudo chmod 777 /mnt/ipcam-storage/{recordings,vod,chunks,excerpts,hls}
```

### 3. Start the System

```bash
docker compose up -d
```

### 4. Set Up Users

```bash
# Copy the example users file
cp config/users.yml.example config/users.yml

# Or add users via CLI after containers start
docker exec ipcam-dashboard python3 /app/manage_users.py add admin --role SuperAdmin --password yourpassword
```

The example file includes a default `admin` account (password: `changeme`). **Change this immediately.**

> To use MySQL instead of the file, set `AUTH_BACKEND=mysql` in `.env` — see [Authentication](#authentication).

### 5. Access the Dashboard

Open `http://<server-ip>` in your browser and log in.

---

## Camera Configuration

### Automatic Discovery

The ONVIF scanner automatically discovers cameras on your configured subnets. New cameras appear in the Admin panel for approval.

### Manual Setup

Edit `config/cameras.yml`:

```yaml
cameras:
  - name: Warehouse_Cam1
    ip: 192.168.100.10
    rtsp_url: rtsp://admin:password@192.168.100.10:554/stream0
    onvif_port: 80
    enabled: true
    visible: true
    category: Building 1
    subcategory: Warehouse
    segment_duration: 600
    allowed_roles:
      - SuperAdmin
      - Supervisor
```

### Camera Organization

Cameras are organized into **categories** and **subcategories** with drag-and-drop reordering in the Admin panel. The dashboard renders cameras grouped by these hierarchies.

---

## Recording & Playback

### How Recording Works

- Frigate records continuously in small ~10-second MP4 segments
- Segments are organized by date/hour: `recordings/YYYY-MM-DD/HH/CameraName/MM.SS.mp4`
- Storage management with configurable retention limits

### Instant VOD Playback

When you select a recording to play:

1. An HLS playlist is generated instantly (no waiting)
2. Each segment is transcoded on-demand (HEVC to H.264 for browser compatibility)
3. Segments are cached after first transcode — subsequent plays are instant
4. Timeline shows motion activity so you can jump to events

### Hourly Chunks

A background process pre-builds hourly chunk files from raw segments, making VOD requests for recent recordings even faster.

---

## Authentication

The system supports two authentication backends — choose whichever fits your setup.

### Option A: File-Based Users (default)

No database required. Users are stored in `config/users.yml` with bcrypt-hashed passwords.

**Quick setup:**

```bash
# Copy the example file
cp config/users.yml.example config/users.yml

# Add users via CLI
docker exec ipcam-dashboard python3 /app/manage_users.py add admin --role SuperAdmin --password yourpassword
docker exec ipcam-dashboard python3 /app/manage_users.py add operator1 --role Operator --password op123456
```

**Manage users:**

```bash
docker exec ipcam-dashboard python3 /app/manage_users.py list
docker exec ipcam-dashboard python3 /app/manage_users.py reset-password admin --password newpass
docker exec ipcam-dashboard python3 /app/manage_users.py set-role operator1 --role Supervisor
docker exec ipcam-dashboard python3 /app/manage_users.py delete operator1
```

**Manage roles:**

Roles are defined in `config/users.yml` with three permission levels:

| Level | Access |
|-------|--------|
| `admin` | Full access: admin panel, all cameras, system settings |
| `manager` | All cameras visible, limited admin |
| `viewer` | Only cameras explicitly assigned to their role |

```bash
# List roles
docker exec ipcam-dashboard python3 /app/manage_users.py roles

# Add custom roles for your organization
docker exec ipcam-dashboard python3 /app/manage_users.py add-role "Security Director" --level admin
docker exec ipcam-dashboard python3 /app/manage_users.py add-role "Security Guard" --level viewer
docker exec ipcam-dashboard python3 /app/manage_users.py add-role "Plant Manager" --level manager

# Rename a role (automatically updates all users with that role)
docker exec ipcam-dashboard python3 /app/manage_users.py rename-role Operator --name "Floor Worker"

# Remove a role (fails if users are still assigned to it)
docker exec ipcam-dashboard python3 /app/manage_users.py remove-role Operator
```

Or edit `config/users.yml` directly:

```yaml
roles:
  - name: IT Admin
    level: admin
  - name: Plant Manager
    level: manager
  - name: Security Guard
    level: viewer
  - name: Maintenance
    level: viewer
```

Then assign cameras to roles in `config/cameras.yml`:

```yaml
cameras:
  - name: Front_Gate
    allowed_roles:
      - Security Guard
      - Plant Manager
```

Set in `.env`:
```env
AUTH_BACKEND=file
```

### Option B: MySQL Database

For integration with existing user management systems. Users authenticate against a MySQL `users` table with bcrypt-hashed passwords.

Set in `.env`:
```env
AUTH_BACKEND=mysql
MYSQL_HOST=192.168.1.158
MYSQL_PORT=3306
MYSQL_USER=appuser
MYSQL_PASS=yourpassword
MYSQL_DB=Users
```

Expected table schema:
```sql
CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,     -- bcrypt hash ($2y$ or $2b$ prefix)
  role VARCHAR(50) DEFAULT 'Operator',
  groups VARCHAR(255) DEFAULT '',     -- comma-separated (e.g. "SuperAdmin,Supervisor")
  approved TINYINT(1) DEFAULT 0,
  reset TINYINT(1) DEFAULT 0
);
```

### SSO Integration (optional)

The system supports HMAC-SHA256 signed token authentication for seamless single sign-on with external applications:

**Incoming SSO** (external app → camera dashboard):
```
GET /auth/token?t=<base64-payload>.<hmac-signature>
```

**Outgoing SSO** (camera dashboard → external app):
```
GET /auth/fms-redirect → generates token → redirects to external app
```

Tokens are single-use with 30-second expiry. Configure the shared secret via the `SSO_SECRET` environment variable.

---

## Admin Panel

Access at `/admin` (SuperAdmin only):

- **Camera Management** — add, edit, rename, configure cameras
- **Category Organizer** — drag-and-drop camera organization
- **Clock Sync** — sync all camera clocks via ONVIF with one click
- **ONVIF Scanner** — trigger network camera discovery
- **Storage Monitoring** — view recording sizes and manage retention

---

## Storage Layout

```
/mnt/ipcam-storage/
  recordings/          # Frigate raw recording segments
    2026-04-29/
      10/
        CameraName/
          05.30.mp4    # segment at HH:MM.SS
  chunks/              # Pre-built hourly concatenations
    CameraName/
      2026-04-29_10.mp4
    _cache/            # VOD session cache
  vod/                 # Temporary VOD session files
  excerpts/            # Permanently saved clips
  hls/                 # Live HLS stream segments
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_BACKEND` | `file` | Auth mode: `file` (users.yml) or `mysql` |
| `RECORDINGS_DIR` | `/mnt/ipcam-storage/recordings` | Recording storage path |
| `VOD_DIR` | `/mnt/ipcam-storage/vod` | VOD session temp files |
| `EXCERPTS_DIR` | `/mnt/ipcam-storage/excerpts` | Permanent clip storage |
| `HTTP_PORT` | `80` | Web UI port |
| `TIMEZONE` | `America/New_York` | System timezone |
| `CAMERA_SUBNET` | `192.168.100.0/24` | ONVIF discovery subnets |
| `ONVIF_USERNAME` | `admin` | Default ONVIF username |
| `ONVIF_PASSWORD` | — | Default ONVIF password |
| `MYSQL_HOST` | `192.168.1.158` | Auth database host (mysql backend only) |
| `MYSQL_DB` | `Users` | Auth database name (mysql backend only) |
| `SSO_SECRET` | — | HMAC shared secret for SSO tokens |
| `SECRET_KEY` | — | Flask session signing key |
| `MAX_STORAGE_GB` | `3500` | Max recording storage before rotation |

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Camera shows "offline" | Check RTSP URL, verify camera is reachable (`ping <ip>`) |
| Stream freezes | Auto-reconnect handles this; check camera stability |
| Recordings slow to load | Ensure VOD/chunks are on fast storage, not root partition |
| HEVC playback fails | System auto-transcodes to H.264; first load takes a few seconds |
| SSO not working | Verify shared secret matches on both systems, check token expiry |

---

## Tech Stack

- **Backend**: Python / Flask
- **Frontend**: Vanilla JS, HLS.js, HTML5 Canvas
- **NVR**: Frigate + go2rtc
- **Proxy**: Nginx with mp4 module
- **Auth**: MySQL + bcrypt + HMAC-SHA256 SSO
- **Container**: Docker Compose
- **Camera Protocol**: RTSP, ONVIF

---

<div align="center">

Built for manufacturing floor surveillance at scale.

</div>

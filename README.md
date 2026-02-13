# WiFi Topology Viewer

Local-only prototype that scans nearby Wi-Fi access points, computes weighted RSSI correlations, embeds APs in a 3D spherical space, and streams snapshots to a Three.js Matrix-style visualization.

## What it does

- Scans networks continuously (default every `1000ms`).
- Scanner priority (auto-detected by OS):
  - macOS:
    1. `airport -s`
    2. native CoreWLAN helper CLI (auto-built from `backend/native/wifi_scan.m`)
    3. `system_profiler SPAirPortDataType -json` fallback
  - Windows:
    1. optional native WLAN helper (`backend/bin/windows_wlan_scan.exe`) if present
    2. `netsh wlan show networks mode=bssid`
  - Linux:
    1. `nmcli --terse --fields BSSID,SSID,SIGNAL,CHAN,SECURITY dev wifi list`
    2. `iw dev <iface> scan` fallback
    3. `iwctl station <iface> get-networks` fallback
- Maintains rolling RSSI history and weighted quality history per AP.
- Computes weighted Pearson correlations and renders strongest edges.
- Computes 3D positions with classical MDS + smoothing.
- Computes cluster IDs from correlation graph and uses cluster coloring in scene/HUD.
- Streams snapshots over `ws://localhost:8787/ws`.
- Supports runtime controls from the HUD:
  - scan interval
  - window size
  - edge threshold
  - minimum overlap
  - minimal mode toggle (hide edges/grid/coverage spheres for a cleaner view)
  - subtle motion toggle (optional, low-amplitude node drift)
- Supports local recording and replay:
  - record snapshots to NDJSON
  - replay NDJSON snapshots at configurable speed/loop

## Visual Modes Preview

![Default collapsed view](docs/screenshots/01-default-collapsed.png)

![Full visual mode](docs/screenshots/02-full-visual.png)

![Minimal mode](docs/screenshots/03-minimal-mode.png)

## Requirements

- Node.js 18+
- Platform support:
  - macOS:
    - Command Line Tools (for building native CoreWLAN helper via `clang`)
  - Windows:
    - `netsh` available (default on modern Windows)
    - optional: drop a compatible `backend/bin/windows_wlan_scan.exe` helper for higher-fidelity scans
    - Location access enabled for terminal apps if Wi-Fi scan visibility is restricted by policy
  - Linux:
    - `nmcli` (NetworkManager) recommended
    - `iw` optional fallback
    - `iwctl` optional fallback (`iwd` environments)

## Run

```bash
cd wifi-topology-viewer
npm install
npm run dev
```

Then open:

- Frontend: `http://127.0.0.1:5173`
- Backend health: `http://localhost:8787/health`

## Stop/kill commands

- Normal stop: `Ctrl + C` from `npm run dev`
- Force-kill mapper processes on app ports:

```bash
npm run kill
```

(`npm run stop` is an alias to `npm run kill`.)

## Runtime HTTP API

- `GET /health`
- `GET /config`
- `PUT /config`
- `GET /record/status`
- `POST /record/start`
- `POST /record/stop`
- `GET /replay/status`
- `POST /replay/start`
- `POST /replay/stop`

Example config update:

```bash
curl -X PUT http://localhost:8787/config \
  -H 'Content-Type: application/json' \
  -d '{"scanIntervalMs":1200,"windowSize":40,"edgeThreshold":0.65,"minOverlap":10}'
```

Example recording start:

```bash
curl -X POST http://localhost:8787/record/start \
  -H 'Content-Type: application/json' \
  -d '{"path":"recordings/my-session.ndjson"}'
```

Example replay start:

```bash
curl -X POST http://localhost:8787/replay/start \
  -H 'Content-Type: application/json' \
  -d '{"path":"recordings/my-session.ndjson","speed":1.5,"loop":true}'
```

## Environment variables (backend)

- `PORT` (default `8787`)
- `SCAN_INTERVAL_MS` (default `1000`)
- `WINDOW_SIZE` (default `30`)
- `EVICT_AFTER_MS` (default `30000`)
- `MAX_APS` (default `40`)
- `SNAPSHOT_EVERY_TICKS` (default `1`)
- `SCAN_TIMEOUT_MS` (default `5000`)
- `MIN_OVERLAP` (default `8`)
- `EDGE_THRESHOLD` (default `0.6`)
- `MAX_EDGES` (default `120`)
- `AIRPORT_PATH` (default built-in macOS airport path)
- `RECORDINGS_DIR` (default `./recordings`)

## Packet shape

`type: "snapshot"` with:

- `t`: epoch ms
- `aps`: AP list with latest RSSI/stats/cluster metadata
- `positions`: `{ [bssid]: { x, y, z } }`
- `edges`: strongest weighted-correlation edges
- `meta`: runtime config + scan source + mode metadata

## Troubleshooting

- macOS:
  - `airport -s` returns only deprecation warning on macOS 15+:
    - expected; backend auto-falls back to CoreWLAN helper, then `system_profiler`.
  - SSID/BSSID missing in CoreWLAN scans:
    - grant Location Services to your terminal app.
  - `scanSource=system_profiler` caveat:
    - many APs may not include real RSSI; app estimates missing RSSI and marks rows with `~`.
- Windows:
  - `scanSource=windows_none`:
    - ensure Wi-Fi is enabled and `WLAN AutoConfig` service is running.
    - if scan results are unexpectedly empty, verify system location/privacy settings for desktop apps.
- Linux:
  - `scanSource=linux_none`:
    - install/enable NetworkManager (`nmcli`) or provide `iw`/`iwctl`.
    - `iw` scans can require elevated privileges depending on distro policy.
- General:
  - First startup delay on macOS:
    - native helper may compile on first run.
  - No frontend updates:
    - verify backend is running on `8787` and WebSocket path `/ws`.

## Privacy

- Data stays in local memory unless you explicitly start recording.
- Recording writes local NDJSON files only.
- No external transmission.

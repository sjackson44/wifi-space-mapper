# WiFi Topology Viewer

Local-only Wi-Fi topology viewer that scans nearby access points, computes rolling signal relationships, and renders a lightweight 3D correlation space.

## What it does

- Scans nearby Wi-Fi networks continuously (default every `1000ms`).
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
- Maintains rolling RSSI history and sample quality history per AP.
- Computes weighted Pearson correlations and renders strongest edges.
- Computes 3D positions with classical MDS + smoothing.
- Computes AP clusters from the correlation graph and uses cluster tinting.
- Computes per-AP stability score (`0.00` to `1.00`) from rolling variance + sample confidence.
- Streams snapshots over `ws://localhost:8787/ws`.
- Sidebar controls include:
  - visual toggles (`minimal mode`, `subtle motion`)
  - runtime tuning (`scan interval`, `window`, `edge threshold`, `min overlap`)
  - recording/replay controls
  - network-list room slider
  - channel density section (`2.4GHz` + `5GHz`) with compact bars
  - `Export report` button (downloads Markdown from current in-memory state)
- Supports local recording/replay (NDJSON snapshots).
- Supports headless diagnostics:
  - `wifi-topology-viewer --analyze --duration <seconds>`

## Visual Modes Preview

![Default collapsed view](docs/screenshots/01.png)

![Full visual mode](docs/screenshots/02.png)

![Minimal mode](docs/screenshots/03.png)


## Platform Support

**Primary platform:** macOS  
Fully supported and actively tested using:

- `airport -s`
- Native CoreWLAN helper
- `system_profiler` fallback

**Experimental support:**

- Windows (via `netsh wlan show networks`)
- Linux (via `nmcli`, `iw`, `iwctl` fallbacks)

Windows and Linux paths rely on native OS tools and have not been extensively validated across hardware/drivers.

If you use those platforms and encounter issues, contributions and reports are welcome.

## Requirements

- Node.js 18+
- Platform support:
  - macOS:
    - Command Line Tools (for building native CoreWLAN helper via `clang`)
  - Windows:
    - `netsh` available (default on modern Windows)
    - optional: drop a compatible `backend/bin/windows_wlan_scan.exe` helper for higher-fidelity scans
    - location access enabled for terminal apps if Wi-Fi scan visibility is restricted by policy
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

## Headless Analyze CLI

The package exposes a CLI entrypoint:

```bash
npx wifi-topology-viewer --analyze --duration 30
```

Options:

- `--duration <seconds>`: analyze duration (default `120`)
- `--json`: print machine-readable JSON summary to stdout
- `--out <path>`: write report output to a file
  - default markdown path: `./wifi-topology-report-YYYYMMDD-HHMMSS.md`
  - default json path: `./wifi-topology-report-YYYYMMDD-HHMMSS.json`
- `--no-server`: skip temporary HTTP server startup during analyze mode
- `--scan-interval <ms>`: override analyze scan interval only

Examples:

```bash
npx wifi-topology-viewer --analyze --duration 30 --no-server
npx wifi-topology-viewer --analyze --duration 45 --json
npx wifi-topology-viewer --analyze --duration 60 --out ./output/run-01.md
```

Analyze output includes:

- APs observed (unique BSSID) and tracked
- cluster count and top cluster sizes (when available)
- channel density (`2.4GHz` / `5GHz`)
- strongest APs
- most volatile APs
- low-congestion channel recommendations (heuristic)

Exit behavior:

- exit code `0` on success
- non-zero on fatal errors or if no networks were observed

## Report Export

You can export a Markdown report in two ways:

- UI: click `Export report` in the sidebar
- API: `GET /report.md`

The report includes:

- timestamp, OS, scan source, mode
- rolling-window context (or duration in analyze mode)
- AP observed/tracked counts
- channel density table with bars
- top clusters summary
- top 5 strongest APs
- top 5 most volatile APs
- notes about topology and distance interpretation

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
- `GET /report.md`

Example config update:

```bash
curl -X PUT http://localhost:8787/config \
  -H 'Content-Type: application/json' \
  -d '{"scanIntervalMs":1200,"windowSize":40,"edgeThreshold":0.65,"minOverlap":10}'
```

Example report download:

```bash
curl -L http://localhost:8787/report.md -o wifi-topology-report.md
```

## Stability Score

Stability is visual/diagnostic metadata only. It does not change clustering or topology layout.

Formula used per AP:

```text
varNorm = clamp(variance / VAR_REF, 0, 1)
countBoost = clamp(sampleCount / COUNT_REF, 0, 1)
stability = clamp((1 - varNorm) * countBoost, 0, 1)
```

Current constants:

- `VAR_REF = 100`
- `COUNT_REF = windowSize`

Interpretation:

- closer to `1.00` => more stable signal over the window
- closer to `0.00` => higher volatility and/or low sample confidence

## Environment Variables (Backend)

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

## Packet Shape

`type: "snapshot"` with:

- `t`: epoch ms
- `aps`: AP list with RSSI/stats/cluster metadata (`stability` included)
- `positions`: `{ [bssid]: { x, y, z } }`
- `edges`: strongest weighted-correlation edges
- `meta`: runtime config + scan source + mode metadata

## Manual Test Checklist

1. `npm run dev` still works; UI loads, WebSocket connects, and minimal mode default is unchanged.
2. Sidebar shows `Channel density` and updates as snapshots arrive.
3. Network rows show stability values in `0.00..1.00` and they look reasonable.
4. `Export report` downloads a Markdown report from current snapshot/state.
5. `npx wifi-topology-viewer --analyze --duration 30` prints summary and exits.
6. `npx wifi-topology-viewer --analyze --duration 30 --json` prints machine-readable JSON.
7. `--out` writes report files successfully.

## Troubleshooting

- macOS:
  - `airport -s` returns only deprecation warning on macOS 15+: expected; backend falls back automatically.
  - missing SSID/BSSID in CoreWLAN scans: grant Location Services to terminal app.
  - `scanSource=system_profiler` can include estimated RSSI entries (shown with `~`).
- Windows:
  - `scanSource=windows_none`: ensure Wi-Fi is enabled and `WLAN AutoConfig` is running.
- Linux:
  - `scanSource=linux_none`: install/enable `nmcli`, or provide `iw`/`iwctl`.
- General:
  - first startup on macOS can be slower due to native helper build.
  - if frontend has no updates, verify backend is running on `8787` and `/ws`.

## Privacy

- Data stays local unless recording is explicitly started.
- Recording writes local NDJSON only.
- No telemetry, cloud sync, or external transmission.

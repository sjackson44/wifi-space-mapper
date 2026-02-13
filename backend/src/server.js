import { createWriteStream } from 'node:fs';
import { mkdir, readFile } from 'node:fs/promises';
import http from 'node:http';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import cors from 'cors';
import express from 'express';
import { WebSocket, WebSocketServer } from 'ws';

import { embedPositions } from './mds.js';
import { buildSnapshotPacket, positionMapToObject } from './schema.js';
import {
  buildCorrelationMatrix,
  buildTopCorrelationEdges,
  correlationToDistance,
  mean,
  variance,
} from './stats.js';
import { DEFAULT_AIRPORT_PATH, getLastScanSource, scanWifiNetworks } from './wifiScanner.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = resolve(__dirname, '..', '..');

const PORT = parsePositiveInt(process.env.PORT, 8787);
const AIRPORT_PATH = process.env.AIRPORT_PATH || DEFAULT_AIRPORT_PATH;
const RECORDINGS_DIR = process.env.RECORDINGS_DIR || join(projectRoot, 'recordings');
const HIDDEN_SSID = '<hidden>';

const runtimeConfig = {
  scanIntervalMs: parsePositiveInt(process.env.SCAN_INTERVAL_MS, 1000),
  windowSize: parsePositiveInt(process.env.WINDOW_SIZE, 30),
  evictAfterMs: parsePositiveInt(process.env.EVICT_AFTER_MS, 30_000),
  maxAps: parsePositiveInt(process.env.MAX_APS, 40),
  snapshotEveryTicks: parsePositiveInt(process.env.SNAPSHOT_EVERY_TICKS, 1),
  scanTimeoutMs: parsePositiveInt(process.env.SCAN_TIMEOUT_MS, 5000),
  minOverlap: parsePositiveInt(process.env.MIN_OVERLAP, 8),
  edgeThreshold: parseBoundedFloat(process.env.EDGE_THRESHOLD, 0.6, 0.05, 0.98),
  maxEdges: parsePositiveInt(process.env.MAX_EDGES, 120),
};

const appState = {
  tickCount: 0,
  scanInFlight: false,
  mode: 'live',
  lastSnapshot: null,
};

const recordState = {
  enabled: false,
  path: null,
  stream: null,
  count: 0,
  startedAt: 0,
};

const replayState = {
  active: false,
  path: null,
  snapshots: [],
  index: 0,
  total: 0,
  speed: 1,
  loop: false,
  startedAt: 0,
  timer: null,
};

const apState = new Map();
const positionState = new Map();

let scanTimer = null;
let shuttingDown = false;

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    now: Date.now(),
    scanPlatform: process.platform,
    mode: appState.mode,
    connectedClients: wss.clients.size,
    trackedAps: appState.lastSnapshot?.aps?.length ?? apState.size,
    scanIntervalMs: runtimeConfig.scanIntervalMs,
    scanSource: getLastScanSource(),
    recording: getRecordingStatus(),
    replay: getReplayStatus(),
  });
});

app.get('/config', (_req, res) => {
  res.json(getRuntimeConfig());
});

app.put('/config', (req, res) => {
  const incoming = req.body ?? {};
  const updates = {};

  if (incoming.scanIntervalMs !== undefined) {
    updates.scanIntervalMs = parseBoundedInt(incoming.scanIntervalMs, 300, 10_000, 'scanIntervalMs');
  }
  if (incoming.windowSize !== undefined) {
    updates.windowSize = parseBoundedInt(incoming.windowSize, 8, 240, 'windowSize');
  }
  if (incoming.edgeThreshold !== undefined) {
    updates.edgeThreshold = parseBoundedFloat(incoming.edgeThreshold, runtimeConfig.edgeThreshold, 0.05, 0.98, 'edgeThreshold');
  }
  if (incoming.minOverlap !== undefined) {
    updates.minOverlap = parseBoundedInt(incoming.minOverlap, 4, 80, 'minOverlap');
  }

  const previousInterval = runtimeConfig.scanIntervalMs;

  Object.assign(runtimeConfig, updates);

  if (updates.windowSize !== undefined) {
    trimWindowForAllRecords(runtimeConfig.windowSize);
  }

  if (updates.scanIntervalMs !== undefined && updates.scanIntervalMs !== previousInterval) {
    scheduleNextScan(0);
  }

  res.json(getRuntimeConfig());
});

app.get('/record/status', (_req, res) => {
  res.json(getRecordingStatus());
});

app.post('/record/start', async (req, res, next) => {
  try {
    const pathInput = req.body?.path;
    const status = await startRecording(pathInput);
    res.json(status);
  } catch (error) {
    next(error);
  }
});

app.post('/record/stop', async (_req, res, next) => {
  try {
    const status = await stopRecording();
    res.json(status);
  } catch (error) {
    next(error);
  }
});

app.get('/replay/status', (_req, res) => {
  res.json(getReplayStatus());
});

app.post('/replay/start', async (req, res, next) => {
  try {
    const pathInput = req.body?.path;
    if (!pathInput || typeof pathInput !== 'string') {
      res.status(400).json({ error: 'path is required' });
      return;
    }

    const speed = parseBoundedFloat(req.body?.speed, 1, 0.2, 8, 'speed');
    const loop = Boolean(req.body?.loop);

    const status = await startReplay({
      pathInput,
      speed,
      loop,
    });

    res.json(status);
  } catch (error) {
    next(error);
  }
});

app.post('/replay/stop', async (_req, res, next) => {
  try {
    const status = await stopReplay();
    res.json(status);
  } catch (error) {
    next(error);
  }
});

app.use((error, _req, res, _next) => {
  const message = error?.message || 'internal error';
  const status = /required|invalid|must be/i.test(message) ? 400 : 500;
  res.status(status).json({ error: message });
});

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (socket) => {
  if (appState.lastSnapshot) {
    socket.send(JSON.stringify(appState.lastSnapshot));
  }
});

server.listen(PORT, () => {
  console.log(`[server] listening on http://localhost:${PORT}`);
  console.log(`[scan] airport path ${AIRPORT_PATH}`);
  console.log(
    `[scan] interval=${runtimeConfig.scanIntervalMs}ms window=${runtimeConfig.windowSize} maxAps=${runtimeConfig.maxAps}`,
  );

  scheduleNextScan(0);
});

process.on('SIGINT', () => {
  void shutdown();
});
process.on('SIGTERM', () => {
  void shutdown();
});

async function scanTick() {
  if (appState.mode !== 'live' || replayState.active || appState.scanInFlight || shuttingDown) {
    return;
  }

  appState.scanInFlight = true;

  try {
    const now = Date.now();
    const scanResults = await scanWifiNetworks({
      airportPath: AIRPORT_PATH,
      timeoutMs: runtimeConfig.scanTimeoutMs,
      enableSystemProfilerFallback: true,
    });

    applyScanResults(scanResults, now);

    appState.tickCount += 1;
    if (appState.tickCount % runtimeConfig.snapshotEveryTicks === 0) {
      const snapshot = buildSnapshot(now, 'live');
      appState.lastSnapshot = snapshot;
      broadcastSnapshot(snapshot, { allowRecord: true });
    }
  } catch (error) {
    console.error('[scan] error:', error.message);
  } finally {
    appState.scanInFlight = false;
  }
}

function applyScanResults(results, now) {
  for (const ap of results) {
    if (!Number.isFinite(ap.rssi)) {
      continue;
    }

    let record = apState.get(ap.bssid);

    if (!record) {
      record = {
        bssid: ap.bssid,
        ssid: ap.ssid,
        ssidHistory: [ap.ssid],
        samples: [],
        sampleWeights: [],
        sampleEstimated: [],
        lastSeen: now,
        latestRssi: ap.rssi,
        latestWeight: deriveSampleWeight(ap),
        rssiEstimated: Boolean(ap.rssiEstimated),
        scanSource: ap.scanSource || 'airport',
        channel: ap.channel,
        band: ap.band,
        security: ap.security,
      };
      apState.set(ap.bssid, record);
    }

    record.lastSeen = now;
    record.latestRssi = ap.rssi;
    record.latestWeight = deriveSampleWeight(ap);
    record.rssiEstimated = Boolean(ap.rssiEstimated);
    record.scanSource = ap.scanSource || 'airport';
    record.channel = ap.channel;
    record.band = ap.band;
    record.security = ap.security;

    if (shouldReplaceSsid(record.ssid, ap.ssid)) {
      record.ssid = ap.ssid;
      if (!record.ssidHistory.includes(ap.ssid)) {
        record.ssidHistory.push(ap.ssid);
        if (record.ssidHistory.length > 5) {
          record.ssidHistory.shift();
        }
      }
    }

    record.samples.push(ap.rssi);
    record.sampleWeights.push(record.latestWeight);
    record.sampleEstimated.push(Boolean(ap.rssiEstimated));

    if (record.samples.length > runtimeConfig.windowSize) {
      record.samples.shift();
      record.sampleWeights.shift();
      record.sampleEstimated.shift();
    }
  }

  for (const [bssid, record] of apState.entries()) {
    if (now - record.lastSeen > runtimeConfig.evictAfterMs) {
      apState.delete(bssid);
      positionState.delete(bssid);
    }
  }
}

function buildSnapshot(now, mode = 'live') {
  const activeRecords = Array.from(apState.values())
    .filter((record) => now - record.lastSeen <= runtimeConfig.evictAfterMs)
    .sort((a, b) => b.latestRssi - a.latestRssi)
    .slice(0, runtimeConfig.maxAps);

  const ids = activeRecords.map((record) => record.bssid);
  const sampleSeries = activeRecords.map((record) => record.samples);
  const sampleWeightSeries = activeRecords.map((record) => record.sampleWeights);

  const corrMatrix = buildCorrelationMatrix(sampleSeries, sampleWeightSeries, runtimeConfig.minOverlap);
  const distanceMatrix = corrMatrix.map((row) => row.map((corr) => correlationToDistance(corr)));

  const nextPositions = embedPositions({
    ids,
    distanceMatrix,
    previousPositions: positionState,
    radius: 50,
    smoothing: 0.2,
  });

  positionState.clear();
  for (const [id, position] of nextPositions.entries()) {
    positionState.set(id, position);
  }

  const edges = buildTopCorrelationEdges(
    ids,
    corrMatrix,
    2,
    runtimeConfig.edgeThreshold,
    runtimeConfig.maxEdges,
  );

  const clusters = buildClusters(ids, edges, runtimeConfig.edgeThreshold);

  const aps = activeRecords.map((record) => ({
    bssid: record.bssid,
    ssid: record.ssid,
    rssi: record.latestRssi,
    channel: record.channel,
    band: record.band,
    security: record.security,
    scanSource: record.scanSource,
    rssiEstimated: record.rssiEstimated,
    sampleQuality: round(mean(record.sampleWeights), 2),
    sampleCount: record.samples.length,
    meanRssi: round(mean(record.samples), 2),
    variance: round(variance(record.samples), 2),
    clusterId: clusters.clusterById.get(record.bssid) || 0,
    clusterSize: clusters.clusterSizeById.get(record.bssid) || 1,
    lastSeen: record.lastSeen,
  }));

  return buildSnapshotPacket({
    t: now,
    aps,
    positions: positionMapToObject(nextPositions),
    edges,
    meta: {
      mode,
      scanPlatform: process.platform,
      scanSource: getLastScanSource(),
      scanIntervalMs: runtimeConfig.scanIntervalMs,
      windowSize: runtimeConfig.windowSize,
      edgeThreshold: runtimeConfig.edgeThreshold,
      minOverlap: runtimeConfig.minOverlap,
      maxAps: runtimeConfig.maxAps,
      activeApCount: activeRecords.length,
      airportPath: AIRPORT_PATH,
      clusterCount: clusters.summary.length,
      clusterSizes: clusters.summary,
      recording: recordState.enabled,
      replay: replayState.active,
    },
  });
}

function broadcastSnapshot(snapshot, { allowRecord = true } = {}) {
  const payload = JSON.stringify(snapshot);

  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }

  if (allowRecord && recordState.enabled && recordState.stream?.writable) {
    recordState.stream.write(`${payload}\n`);
    recordState.count += 1;
  }
}

function deriveSampleWeight(ap) {
  if (ap.rssiEstimated) {
    return 0.12;
  }
  if (ap.scanSource === 'system_profiler') {
    return 0.45;
  }
  if (ap.bssidSynthetic) {
    return 0.35;
  }
  return 1;
}

function shouldReplaceSsid(existingSsid, incomingSsid) {
  if (existingSsid === incomingSsid) {
    return false;
  }

  return !(isHiddenSsid(incomingSsid) && !isHiddenSsid(existingSsid));
}

function isHiddenSsid(value) {
  return String(value || '').trim() === HIDDEN_SSID;
}

function trimWindowForAllRecords(windowSize) {
  for (const record of apState.values()) {
    if (record.samples.length > windowSize) {
      record.samples = record.samples.slice(record.samples.length - windowSize);
    }
    if (record.sampleWeights.length > windowSize) {
      record.sampleWeights = record.sampleWeights.slice(record.sampleWeights.length - windowSize);
    }
    if (record.sampleEstimated.length > windowSize) {
      record.sampleEstimated = record.sampleEstimated.slice(record.sampleEstimated.length - windowSize);
    }
  }
}

function scheduleNextScan(delayMs = runtimeConfig.scanIntervalMs) {
  if (shuttingDown) {
    return;
  }

  clearTimeout(scanTimer);
  scanTimer = setTimeout(async () => {
    await scanTick();
    scheduleNextScan(runtimeConfig.scanIntervalMs);
  }, Math.max(40, delayMs));
}

async function startRecording(pathInput) {
  if (recordState.enabled) {
    return getRecordingStatus();
  }

  const recordPath = resolveOutputPath(pathInput);
  await mkdir(dirname(recordPath), { recursive: true });

  const stream = createWriteStream(recordPath, { flags: 'a' });
  await new Promise((resolvePromise, rejectPromise) => {
    stream.once('open', resolvePromise);
    stream.once('error', rejectPromise);
  });

  stream.on('error', (error) => {
    console.error('[record] stream error:', error.message);
    void stopRecording();
  });

  recordState.enabled = true;
  recordState.path = recordPath;
  recordState.stream = stream;
  recordState.count = 0;
  recordState.startedAt = Date.now();

  return getRecordingStatus();
}

async function stopRecording() {
  if (!recordState.enabled && !recordState.stream) {
    return getRecordingStatus();
  }

  const stream = recordState.stream;

  recordState.enabled = false;
  recordState.path = null;
  recordState.stream = null;
  recordState.startedAt = 0;
  recordState.count = 0;

  if (stream) {
    await new Promise((resolvePromise) => {
      stream.end(resolvePromise);
    });
  }

  return getRecordingStatus();
}

async function startReplay({ pathInput, speed, loop }) {
  const replayPath = isAbsolute(pathInput) ? pathInput : resolve(projectRoot, pathInput);
  const text = await readFile(replayPath, 'utf8');
  const snapshots = text
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter((snapshot) => snapshot && snapshot.type === 'snapshot');

  if (!snapshots.length) {
    throw new Error('Replay file has no snapshot lines');
  }

  await stopReplay();

  replayState.active = true;
  replayState.path = replayPath;
  replayState.snapshots = snapshots;
  replayState.index = 0;
  replayState.total = snapshots.length;
  replayState.speed = speed;
  replayState.loop = loop;
  replayState.startedAt = Date.now();

  appState.mode = 'replay';

  scheduleReplayTick(0);
  return getReplayStatus();
}

async function stopReplay() {
  clearTimeout(replayState.timer);
  replayState.timer = null;

  replayState.active = false;
  replayState.path = null;
  replayState.snapshots = [];
  replayState.index = 0;
  replayState.total = 0;
  replayState.speed = 1;
  replayState.loop = false;
  replayState.startedAt = 0;

  appState.mode = 'live';

  return getReplayStatus();
}

function scheduleReplayTick(delayMs) {
  clearTimeout(replayState.timer);
  replayState.timer = setTimeout(() => {
    void emitReplayTick();
  }, Math.max(20, delayMs));
}

async function emitReplayTick() {
  if (!replayState.active || shuttingDown) {
    return;
  }

  if (replayState.index >= replayState.total) {
    if (replayState.loop) {
      replayState.index = 0;
    } else {
      await stopReplay();
      return;
    }
  }

  const current = replayState.snapshots[replayState.index];
  const next = replayState.snapshots[replayState.index + 1];

  replayState.index += 1;

  const snapshot = {
    ...current,
    type: 'snapshot',
    t: Date.now(),
    meta: {
      ...(current.meta || {}),
      mode: 'replay',
      replay: true,
      replayPath: replayState.path,
      replayIndex: replayState.index,
      replayTotal: replayState.total,
      replaySpeed: replayState.speed,
      recording: recordState.enabled,
    },
  };

  appState.lastSnapshot = snapshot;
  broadcastSnapshot(snapshot, { allowRecord: false });

  const delayMs = computeReplayDelayMs(current, next, replayState.speed, runtimeConfig.scanIntervalMs);
  scheduleReplayTick(delayMs);
}

function computeReplayDelayMs(current, next, speed, fallbackMs) {
  if (!next) {
    return fallbackMs;
  }

  const raw = Number(next.t) - Number(current.t);
  const base = Number.isFinite(raw) && raw > 40 ? raw : fallbackMs;
  return clamp(Math.round(base / Math.max(speed, 0.1)), 40, 15_000);
}

function buildClusters(ids, edges, minCorr) {
  const graph = new Map(ids.map((id) => [id, new Set()]));

  for (const edge of edges) {
    if (edge.corr < minCorr) {
      continue;
    }
    graph.get(edge.a)?.add(edge.b);
    graph.get(edge.b)?.add(edge.a);
  }

  const visited = new Set();
  const clusterById = new Map(ids.map((id) => [id, 0]));
  const clusterSizeById = new Map(ids.map((id) => [id, 1]));
  const summary = [];

  let clusterId = 1;

  for (const id of ids) {
    if (visited.has(id)) {
      continue;
    }

    const stack = [id];
    const members = [];
    visited.add(id);

    while (stack.length) {
      const node = stack.pop();
      members.push(node);
      for (const neighbor of graph.get(node) || []) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          stack.push(neighbor);
        }
      }
    }

    if (members.length > 1) {
      for (const member of members) {
        clusterById.set(member, clusterId);
        clusterSizeById.set(member, members.length);
      }
      summary.push(members.length);
      clusterId += 1;
    }
  }

  summary.sort((a, b) => b - a);

  return {
    clusterById,
    clusterSizeById,
    summary,
  };
}

function getRuntimeConfig() {
  return {
    ...runtimeConfig,
    mode: appState.mode,
  };
}

function getRecordingStatus() {
  return {
    enabled: recordState.enabled,
    path: recordState.path,
    count: recordState.count,
    startedAt: recordState.startedAt,
  };
}

function getReplayStatus() {
  return {
    active: replayState.active,
    path: replayState.path,
    index: replayState.index,
    total: replayState.total,
    speed: replayState.speed,
    loop: replayState.loop,
    startedAt: replayState.startedAt,
  };
}

function resolveOutputPath(pathInput) {
  if (typeof pathInput === 'string' && pathInput.trim()) {
    return isAbsolute(pathInput) ? pathInput : resolve(projectRoot, pathInput.trim());
  }

  const timestamp = new Date().toISOString().replace(/[:.]/gu, '-');
  return join(RECORDINGS_DIR, `wifi-space-${timestamp}.ndjson`);
}

async function shutdown() {
  if (shuttingDown) {
    return;
  }

  shuttingDown = true;
  clearTimeout(scanTimer);
  clearTimeout(replayState.timer);

  await stopReplay();
  await stopRecording();

  for (const client of wss.clients) {
    client.terminate();
  }

  wss.close();

  await new Promise((resolvePromise) => {
    server.close(resolvePromise);
  });

  process.exit(0);
}

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(value ?? '', 10);
  if (Number.isFinite(parsed) && parsed > 0) {
    return parsed;
  }
  return fallback;
}

function parseBoundedInt(value, min, max, label = 'value') {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${label} must be an integer`);
  }
  if (parsed < min || parsed > max) {
    throw new Error(`${label} must be between ${min} and ${max}`);
  }
  return parsed;
}

function parseBoundedFloat(value, fallback, min, max, label = 'value') {
  const parsed = Number.parseFloat(value ?? '');
  if (!Number.isFinite(parsed)) {
    if (label === 'value') {
      return fallback;
    }
    throw new Error(`${label} must be a number`);
  }
  if (parsed < min || parsed > max) {
    throw new Error(`${label} must be between ${min} and ${max}`);
  }
  return parsed;
}

function round(value, precision = 2) {
  const factor = 10 ** precision;
  return Math.round(value * factor) / factor;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

import { execFile } from 'node:child_process';
import { constants as fsConstants } from 'node:fs';
import { access, mkdir, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  parseAirportOutput,
  parseIwScanOutput,
  parseNetshOutput,
  parseNmcliOutput,
  parseSystemProfilerOutput,
} from './parser.js';

const execFileAsync = promisify(execFile);
const BSSID_PATTERN = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/u;
const HIDDEN_SSID = '<hidden>';
const MIN_COREWLAN_IDENTIFIED_APS = 3;
const MIN_COREWLAN_IDENTIFIED_RATIO = 0.18;

export const DEFAULT_AIRPORT_PATH =
  '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport';

const SYSTEM_PROFILER_PATH = '/usr/sbin/system_profiler';
const CLANG_PATH = '/usr/bin/clang';
const NETSH_COMMANDS = ['netsh'];
const NMCLI_COMMANDS = ['/usr/bin/nmcli', '/bin/nmcli', 'nmcli'];
const IW_COMMANDS = ['/usr/sbin/iw', '/sbin/iw', '/usr/bin/iw', 'iw'];
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const backendRoot = join(__dirname, '..');
const nativeSourcePath = join(backendRoot, 'native', 'wifi_scan.m');
const nativeBinaryDir = join(backendRoot, 'bin');
const nativeBinaryPath = join(nativeBinaryDir, 'corewlan_scan');
const windowsNativeBinaryPath = join(nativeBinaryDir, 'windows_wlan_scan.exe');
const IWCTL_COMMANDS = ['/usr/bin/iwctl', '/bin/iwctl', 'iwctl'];

const inferredRssiCache = new Map();
let nativeBuildPromise = null;
let nativeBuildAttempted = false;
let lastScanSource = 'none';

export function getLastScanSource() {
  return lastScanSource;
}

export async function scanWifiNetworks({
  airportPath = DEFAULT_AIRPORT_PATH,
  timeoutMs = 5000,
  enableSystemProfilerFallback = true,
} = {}) {
  if (process.platform === 'darwin') {
    return scanDarwin({
      airportPath,
      timeoutMs,
      enableSystemProfilerFallback,
    });
  }

  if (process.platform === 'win32') {
    return scanWindows({ timeoutMs });
  }

  if (process.platform === 'linux') {
    return scanLinux({ timeoutMs });
  }

  lastScanSource = `unsupported:${process.platform}`;
  return [];
}

async function scanDarwin({
  airportPath,
  timeoutMs,
  enableSystemProfilerFallback,
}) {
  const airportNetworks = await tryAirportScan(airportPath, timeoutMs);
  if (airportNetworks.length) {
    lastScanSource = 'airport';
    return withScanSource(airportNetworks, 'airport');
  }

  const coreWlanNetworks = await tryCoreWlanScan(timeoutMs);
  const coreWlanUsable = isCoreWlanScanUsable(coreWlanNetworks);
  if (coreWlanNetworks.length && (!enableSystemProfilerFallback || coreWlanUsable)) {
    lastScanSource = 'corewlan';
    return withScanSource(coreWlanNetworks, 'corewlan');
  }

  if (enableSystemProfilerFallback) {
    const profilerNetworks = await trySystemProfilerScan(timeoutMs);
    if (profilerNetworks.length) {
      lastScanSource = 'system_profiler';
      return withScanSource(profilerNetworks, 'system_profiler');
    }
  }

  if (coreWlanNetworks.length) {
    lastScanSource = 'corewlan';
    return withScanSource(coreWlanNetworks, 'corewlan');
  }

  lastScanSource = 'mac_none';
  return [];
}

async function scanWindows({ timeoutMs }) {
  const nativeNetworks = await tryWindowsNativeScan(timeoutMs);
  if (nativeNetworks.length) {
    lastScanSource = 'windows_native';
    return withScanSource(nativeNetworks, 'windows_native');
  }

  const netshNetworks = await tryNetshScan(timeoutMs);
  if (netshNetworks.length) {
    lastScanSource = 'windows_netsh';
    return withScanSource(netshNetworks, 'windows_netsh');
  }

  lastScanSource = 'windows_none';
  return [];
}

async function scanLinux({ timeoutMs }) {
  const nmcliNetworks = await tryNmcliScan(timeoutMs);
  if (nmcliNetworks.length) {
    lastScanSource = 'linux_nmcli';
    return withScanSource(nmcliNetworks, 'linux_nmcli');
  }

  const iwNetworks = await tryIwScan(timeoutMs);
  if (iwNetworks.length) {
    lastScanSource = 'linux_iw';
    return withScanSource(iwNetworks, 'linux_iw');
  }

  const iwctlNetworks = await tryIwctlScan(timeoutMs);
  if (iwctlNetworks.length) {
    lastScanSource = 'linux_iwctl';
    return withScanSource(iwctlNetworks, 'linux_iwctl');
  }

  lastScanSource = 'linux_none';
  return [];
}

async function tryAirportScan(airportPath, timeoutMs) {
  try {
    const { stdout } = await execFileAsync(airportPath, ['-s'], {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024,
    });

    return parseAirportOutput(stdout).map((network) => ({
      ...network,
      rssiEstimated: false,
    }));
  } catch {
    return [];
  }
}

async function tryCoreWlanScan(timeoutMs) {
  try {
    await ensureNativeScannerBinary();

    const { stdout } = await execFileAsync(nativeBinaryPath, [], {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024,
    });

    return parseCoreWlanOutput(stdout);
  } catch {
    return [];
  }
}

async function trySystemProfilerScan(timeoutMs) {
  try {
    const profilerTimeout = Math.max(timeoutMs * 3, 12_000);
    const { stdout } = await execFirstAvailable(
      [SYSTEM_PROFILER_PATH],
      SYSTEM_PROFILER_PATH,
      ['SPAirPortDataType', '-json'],
      {
        timeout: profilerTimeout,
        maxBuffer: 4 * 1024 * 1024,
      },
    );

    const networks = parseSystemProfilerOutput(stdout);
    return applyEstimatedRssi(networks);
  } catch {
    return [];
  }
}

async function tryNetshScan(timeoutMs) {
  try {
    const { stdout } = await execFirstAvailable(
      NETSH_COMMANDS,
      'netsh',
      ['wlan', 'show', 'networks', 'mode=bssid'],
      {
        timeout: Math.max(timeoutMs, 5_000),
        maxBuffer: 4 * 1024 * 1024,
        windowsHide: true,
      },
    );
    return parseNetshOutput(stdout);
  } catch {
    return [];
  }
}

async function tryWindowsNativeScan(timeoutMs) {
  try {
    const { stdout } = await execFirstAvailable(
      [windowsNativeBinaryPath],
      'windows-native',
      [],
      {
        timeout: Math.max(timeoutMs, 5_000),
        maxBuffer: 4 * 1024 * 1024,
        windowsHide: true,
      },
    );
    return parseWindowsNativeOutput(stdout);
  } catch {
    return [];
  }
}

async function tryNmcliScan(timeoutMs) {
  try {
    const { stdout } = await execFirstAvailable(
      NMCLI_COMMANDS,
      'nmcli',
      ['--terse', '--fields', 'BSSID,SSID,SIGNAL,CHAN,SECURITY', 'dev', 'wifi', 'list'],
      {
        timeout: Math.max(timeoutMs, 6_000),
        maxBuffer: 4 * 1024 * 1024,
      },
    );
    return parseNmcliOutput(stdout);
  } catch {
    return [];
  }
}

async function tryIwScan(timeoutMs) {
  const interfaces = await listIwInterfaces(timeoutMs);
  if (!interfaces.length) {
    return [];
  }

  const networks = [];
  for (const iface of interfaces.slice(0, 4)) {
    try {
      const { stdout } = await execFirstAvailable(
        IW_COMMANDS,
        'iw',
        ['dev', iface, 'scan'],
        {
          timeout: Math.max(timeoutMs * 2, 8_000),
          maxBuffer: 8 * 1024 * 1024,
        },
      );
      networks.push(...parseIwScanOutput(stdout));
    } catch {
      // Continue to next interface.
    }
  }

  return dedupeByStrongestRssi(networks);
}

async function tryIwctlScan(timeoutMs) {
  const devices = await listIwctlDevices(timeoutMs);
  if (!devices.length) {
    return [];
  }

  const networks = [];
  for (const device of devices.slice(0, 4)) {
    try {
      const { stdout } = await execFirstAvailable(
        IWCTL_COMMANDS,
        'iwctl',
        ['station', device, 'get-networks'],
        {
          timeout: Math.max(timeoutMs, 6_000),
          maxBuffer: 1024 * 1024,
        },
      );
      networks.push(...parseIwctlStationOutput(stdout, device));
    } catch {
      // Continue to next device.
    }
  }

  return dedupeByStrongestRssi(networks);
}

async function listIwInterfaces(timeoutMs) {
  try {
    const { stdout } = await execFirstAvailable(
      IW_COMMANDS,
      'iw',
      ['dev'],
      {
        timeout: Math.max(timeoutMs, 4_000),
        maxBuffer: 1024 * 1024,
      },
    );

    const interfaces = [];
    for (const match of stdout.matchAll(/^\s*Interface\s+([^\s]+)\s*$/gmu)) {
      interfaces.push(match[1]);
    }
    return interfaces;
  } catch {
    return [];
  }
}

async function listIwctlDevices(timeoutMs) {
  try {
    const { stdout } = await execFirstAvailable(
      IWCTL_COMMANDS,
      'iwctl',
      ['device', 'list'],
      {
        timeout: Math.max(timeoutMs, 5_000),
        maxBuffer: 1024 * 1024,
      },
    );

    const devices = [];
    for (const rawLine of stdout.split(/\r?\n/u)) {
      const line = rawLine.trim();
      if (!line) {
        continue;
      }
      if (/^(Name|Devices|---)/iu.test(line)) {
        continue;
      }

      const firstToken = line.split(/\s+/u)[0];
      if (!/^[a-zA-Z0-9_.:-]+$/u.test(firstToken)) {
        continue;
      }
      devices.push(firstToken);
    }

    return Array.from(new Set(devices));
  } catch {
    return [];
  }
}

function parseCoreWlanOutput(rawOutput) {
  if (!rawOutput || !rawOutput.trim()) {
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(rawOutput);
  } catch {
    return [];
  }

  if (!Array.isArray(parsed)) {
    return [];
  }

  const seen = new Set();
  const occurrenceByFingerprint = new Map();
  const deduped = [];

  for (const network of parsed) {
    const ssid = String(network?.ssid || '').trim() || HIDDEN_SSID;
    const channel = String(network?.channel ?? '').trim();
    const security = String(network?.security || 'UNKNOWN').trim() || 'UNKNOWN';
    const rssi = Number.parseInt(String(network?.rssi ?? ''), 10);

    if (!Number.isFinite(rssi)) {
      continue;
    }

    const bssidRaw = String(network?.bssid || '').trim().toLowerCase();
    const fingerprint = `${ssid}::${channel}::${security}`;
    const occurrence = (occurrenceByFingerprint.get(fingerprint) ?? 0) + 1;
    occurrenceByFingerprint.set(fingerprint, occurrence);

    const bssid = BSSID_PATTERN.test(bssidRaw)
      ? bssidRaw
      : syntheticBssid(`${fingerprint}::${occurrence}`);

    if (seen.has(bssid)) {
      continue;
    }
    seen.add(bssid);

    deduped.push({
      bssid,
      ssid,
      rssi,
      channel,
      band: inferBand(channel),
      security,
      scanSource: 'corewlan',
      rssiEstimated: false,
      bssidSynthetic: !BSSID_PATTERN.test(bssidRaw),
    });
  }

  return deduped;
}

function parseWindowsNativeOutput(rawOutput) {
  if (!rawOutput || !rawOutput.trim()) {
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(rawOutput);
  } catch {
    return [];
  }

  if (!Array.isArray(parsed)) {
    return [];
  }

  const networks = [];

  for (let index = 0; index < parsed.length; index += 1) {
    const item = parsed[index];
    const ssid = String(item?.ssid || '').trim() || HIDDEN_SSID;
    const channel = String(item?.channel ?? '').trim();
    const security = String(item?.security || 'UNKNOWN').trim() || 'UNKNOWN';
    const rssi = Number.parseInt(String(item?.rssi ?? ''), 10);
    if (!Number.isFinite(rssi)) {
      continue;
    }

    const bssidRaw = String(item?.bssid || '').trim().toLowerCase();
    const bssid = BSSID_PATTERN.test(bssidRaw)
      ? bssidRaw
      : syntheticBssid(`${ssid}::${channel || '?'}::${security}::${index + 1}`);

    networks.push({
      bssid,
      ssid,
      rssi,
      channel,
      band: inferBand(channel),
      security,
      rssiEstimated: false,
      bssidSynthetic: !BSSID_PATTERN.test(bssidRaw),
    });
  }

  return dedupeByStrongestRssi(networks);
}

function parseIwctlStationOutput(rawOutput, deviceName) {
  if (!rawOutput || !rawOutput.trim()) {
    return [];
  }

  const networks = [];
  let rowIndex = 0;

  for (const rawLine of rawOutput.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }
    if (/^(Available|Network name|Name|---|No networks)/iu.test(line)) {
      continue;
    }

    const cleaned = line.replace(/^[>\*\s]+/u, '').trim();
    const columns = cleaned.split(/\s{2,}/u).map((value) => value.trim()).filter(Boolean);
    if (columns.length < 2) {
      continue;
    }

    const ssid = columns[0] || HIDDEN_SSID;
    const security = String(columns[1] || 'UNKNOWN').toUpperCase();
    const signalToken = columns[columns.length - 1];
    const signalStars = (signalToken.match(/\*/gu) || []).length;
    if (signalStars <= 0) {
      continue;
    }

    rowIndex += 1;
    const rssi = starSignalToRssi(signalStars);
    const bssid = syntheticBssid(`${deviceName}::${ssid}::${security}::${rowIndex}`);

    networks.push({
      bssid,
      ssid,
      rssi,
      channel: '',
      band: 'unknown',
      security,
      rssiEstimated: true,
      bssidSynthetic: true,
    });
  }

  return dedupeByStrongestRssi(networks);
}

function applyEstimatedRssi(networks) {
  const now = Date.now();
  const seenThisScan = new Set();

  const normalized = networks.map((network) => {
    seenThisScan.add(network.bssid);

    let rssi = network.rssi;
    let rssiEstimated = Boolean(network.rssiEstimated);

    if (!Number.isFinite(rssi)) {
      rssiEstimated = true;
      const cached = inferredRssiCache.get(network.bssid);
      const base = cached?.value ?? estimateBaselineRssi(network);
      const drift = Math.round(Math.sin(now / 3000 + phaseFromId(network.bssid)) * 2);
      rssi = clamp(Math.round(base + drift), -92, -45);
    } else {
      rssi = clamp(Math.round(rssi), -95, -20);
    }

    inferredRssiCache.set(network.bssid, { value: rssi, updatedAt: now });

    return {
      ...network,
      rssi,
      rssiEstimated,
      scanSource: 'system_profiler',
    };
  });

  for (const [bssid, entry] of inferredRssiCache.entries()) {
    if (seenThisScan.has(bssid)) {
      continue;
    }
    if (now - entry.updatedAt > 5 * 60_000) {
      inferredRssiCache.delete(bssid);
    }
  }

  return normalized;
}

function estimateBaselineRssi(network) {
  const baseByBand = {
    '2.4ghz': -74,
    '5ghz': -68,
    '6ghz': -64,
  };
  const base = baseByBand[network.band] ?? -72;
  const variance = (hashCode(network.bssid) % 10) - 5;
  return base + variance;
}

function phaseFromId(id) {
  return (hashCode(id) % 360) * (Math.PI / 180);
}

function inferBand(channelText) {
  const match = String(channelText || '').match(/\d+/u);
  if (!match) {
    return 'unknown';
  }

  const channel = Number.parseInt(match[0], 10);
  if (channel >= 1 && channel <= 14) {
    return '2.4ghz';
  }
  if (channel >= 32 && channel <= 177) {
    return '5ghz';
  }
  return '6ghz';
}

function syntheticBssid(seed) {
  const hashA = hashCode(seed);
  const hashB = hashCode(`${seed}::corewlan`);
  const bytes = [
    hashA & 0xff,
    (hashA >>> 8) & 0xff,
    (hashA >>> 16) & 0xff,
    (hashA >>> 24) & 0xff,
    hashB & 0xff,
    (hashB >>> 8) & 0xff,
  ];

  bytes[0] = (bytes[0] | 0x02) & 0xfe;
  return bytes.map((value) => value.toString(16).padStart(2, '0')).join(':');
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function hashCode(value) {
  let hash = 2166136261;
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function starSignalToRssi(stars) {
  const clamped = Math.max(1, Math.min(5, Number(stars) || 1));
  return -90 + clamped * 9;
}

function dedupeByStrongestRssi(networks) {
  const byBssid = new Map();
  for (const network of networks) {
    if (!network) {
      continue;
    }
    const existing = byBssid.get(network.bssid);
    if (!existing || network.rssi > existing.rssi) {
      byBssid.set(network.bssid, network);
    }
  }
  return Array.from(byBssid.values());
}

function withScanSource(networks, scanSource) {
  return networks.map((network) => ({
    ...network,
    scanSource,
    rssiEstimated: Boolean(network.rssiEstimated),
  }));
}

async function execFirstAvailable(candidates, fallbackName, args, options) {
  let lastError = null;

  for (const command of candidates) {
    try {
      return await execFileAsync(command, args, options);
    } catch (error) {
      lastError = error;
      if (error?.code === 'ENOENT') {
        continue;
      }
      throw error;
    }
  }

  if (lastError) {
    throw lastError;
  }

  throw new Error(`${fallbackName}-not-found`);
}

function isCoreWlanScanUsable(networks) {
  if (!networks.length) {
    return false;
  }

  const identified = networks.filter(
    (network) => (!network.bssidSynthetic || network.ssid !== HIDDEN_SSID),
  ).length;

  if (identified >= MIN_COREWLAN_IDENTIFIED_APS) {
    return true;
  }

  return identified / networks.length >= MIN_COREWLAN_IDENTIFIED_RATIO;
}

async function ensureNativeScannerBinary() {
  if (!nativeBuildPromise) {
    nativeBuildPromise = buildNativeScannerIfNeeded();
  }

  try {
    await nativeBuildPromise;
    nativeBuildAttempted = true;
  } finally {
    nativeBuildPromise = null;
  }

  if (!nativeBuildAttempted) {
    throw new Error('corewlan-native-build-failed');
  }
}

async function buildNativeScannerIfNeeded() {
  const needsBuild = await shouldBuildNativeScanner();
  if (!needsBuild) {
    nativeBuildAttempted = true;
    return;
  }

  await mkdir(nativeBinaryDir, { recursive: true });
  await execFileAsync(CLANG_PATH, [
    '-fobjc-arc',
    '-framework',
    'Foundation',
    '-framework',
    'CoreWLAN',
    nativeSourcePath,
    '-o',
    nativeBinaryPath,
  ]);

  await access(nativeBinaryPath, fsConstants.X_OK);
  nativeBuildAttempted = true;
}

async function shouldBuildNativeScanner() {
  try {
    await access(nativeSourcePath, fsConstants.R_OK);
  } catch {
    return false;
  }

  try {
    await access(nativeBinaryPath, fsConstants.X_OK);
  } catch {
    return true;
  }

  try {
    const [sourceStat, binaryStat] = await Promise.all([
      stat(nativeSourcePath),
      stat(nativeBinaryPath),
    ]);
    return sourceStat.mtimeMs > binaryStat.mtimeMs;
  } catch {
    return true;
  }
}

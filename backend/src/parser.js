const BSSID_PATTERN = /(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}/;
const EXACT_BSSID_PATTERN = /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/u;
const LINE_PATTERN = /^(?<ssid>.*?)\s+(?<bssid>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\s+(?<rssi>-?\d+)\s+(?<channel>\S+)\s*(?<rest>.*)$/;

export function parseAirportOutput(rawOutput) {
  if (!rawOutput || !rawOutput.trim()) {
    return [];
  }

  const lines = rawOutput
    .split(/\r?\n/u)
    .map((line) => line.trimEnd())
    .filter((line) => line.trim().length > 0);

  if (!lines.length) {
    return [];
  }

  const headerIndex = lines.findIndex(
    (line) => line.includes('BSSID') && line.includes('RSSI'),
  );

  const columnStarts = headerIndex >= 0 ? inferColumnStarts(lines[headerIndex]) : null;
  const dataLines = headerIndex >= 0 ? lines.slice(headerIndex + 1) : lines;

  const byBssid = new Map();

  for (const line of dataLines) {
    const parsed = parseLine(line, columnStarts);
    if (!parsed) {
      continue;
    }

    const existing = byBssid.get(parsed.bssid);
    if (!existing || parsed.rssi > existing.rssi) {
      byBssid.set(parsed.bssid, parsed);
    }
  }

  return Array.from(byBssid.values());
}

export function parseSystemProfilerOutput(rawOutput) {
  if (!rawOutput || !rawOutput.trim()) {
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(rawOutput);
  } catch {
    return [];
  }

  const sections = parsed?.SPAirPortDataType;
  if (!Array.isArray(sections)) {
    return [];
  }

  const interfaces = sections.flatMap((section) =>
    Array.isArray(section?.spairport_airport_interfaces)
      ? section.spairport_airport_interfaces
      : [],
  );

  const wifiInterface =
    interfaces.find((item) => item?._name === 'en0') ||
    interfaces.find((item) =>
      Array.isArray(item?.spairport_airport_other_local_wireless_networks),
    ) ||
    interfaces[0];

  if (!wifiInterface) {
    return [];
  }

  const seenByKey = new Map();
  const parsedNetworks = [];

  if (wifiInterface.spairport_current_network_information) {
    const current = parseSystemProfilerNetwork(
      wifiInterface.spairport_current_network_information,
      seenByKey,
    );
    if (current) {
      parsedNetworks.push(current);
    }
  }

  const others = wifiInterface.spairport_airport_other_local_wireless_networks;
  if (Array.isArray(others)) {
    for (const network of others) {
      const parsedNetwork = parseSystemProfilerNetwork(network, seenByKey);
      if (parsedNetwork) {
        parsedNetworks.push(parsedNetwork);
      }
    }
  }

  const byBssid = new Map();
  for (const network of parsedNetworks) {
    const existing = byBssid.get(network.bssid);
    if (!existing) {
      byBssid.set(network.bssid, network);
      continue;
    }

    if (existing.rssi == null && network.rssi != null) {
      byBssid.set(network.bssid, network);
    }
  }

  return Array.from(byBssid.values());
}

export function parseNetshOutput(rawOutput) {
  if (!rawOutput || !rawOutput.trim()) {
    return [];
  }

  const lines = rawOutput.split(/\r?\n/u).map((line) => line.trimEnd());
  const parsedEntries = [];

  let ssidBlock = null;
  let bssidBlock = null;
  let syntheticIndex = 0;

  function flushSsidBlock() {
    if (!ssidBlock) {
      return;
    }

    const security = formatNetshSecurity(ssidBlock.auth, ssidBlock.encryption);

    if (!ssidBlock.bssids.length) {
      const rssi = signalPercentToRssi(ssidBlock.signalPercent);
      if (Number.isFinite(rssi)) {
        syntheticIndex += 1;
        parsedEntries.push(
          buildNormalizedNetwork({
            bssid: null,
            syntheticSeed: `${ssidBlock.ssid}::${ssidBlock.channel || '?'}::${security}::${syntheticIndex}`,
            ssid: ssidBlock.ssid,
            rssi,
            channel: ssidBlock.channel,
            bandText: ssidBlock.bandText,
            security,
          }),
        );
      }
      ssidBlock = null;
      bssidBlock = null;
      return;
    }

    for (const entry of ssidBlock.bssids) {
      const rssi = signalPercentToRssi(entry.signalPercent ?? ssidBlock.signalPercent);
      if (!Number.isFinite(rssi)) {
        continue;
      }

      parsedEntries.push(
        buildNormalizedNetwork({
          bssid: entry.bssid,
          syntheticSeed: `${ssidBlock.ssid}::${entry.channel || ssidBlock.channel || '?'}::${security}::${entry.index}`,
          ssid: ssidBlock.ssid,
          rssi,
          channel: entry.channel || ssidBlock.channel,
          bandText: entry.bandText || ssidBlock.bandText,
          security,
        }),
      );
    }

    ssidBlock = null;
    bssidBlock = null;
  }

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    const ssidMatch = trimmed.match(/^SSID\s+\d+\s*:\s*(.*)$/iu);
    if (ssidMatch) {
      flushSsidBlock();
      ssidBlock = {
        ssid: ssidMatch[1].trim() || '<hidden>',
        auth: '',
        encryption: '',
        channel: '',
        bandText: '',
        signalPercent: null,
        bssids: [],
      };
      continue;
    }

    if (!ssidBlock) {
      continue;
    }

    const authMatch = trimmed.match(/^Authentication\s*:\s*(.*)$/iu);
    if (authMatch) {
      ssidBlock.auth = authMatch[1].trim();
      continue;
    }

    const encryptionMatch = trimmed.match(/^Encryption\s*:\s*(.*)$/iu);
    if (encryptionMatch) {
      ssidBlock.encryption = encryptionMatch[1].trim();
      continue;
    }

    const bssidMatch = trimmed.match(/^BSSID\s+(\d+)\s*:\s*(.*)$/iu);
    if (bssidMatch) {
      bssidBlock = {
        index: Number.parseInt(bssidMatch[1], 10) || ssidBlock.bssids.length + 1,
        bssid: bssidMatch[2].trim(),
        signalPercent: null,
        channel: '',
        bandText: '',
      };
      ssidBlock.bssids.push(bssidBlock);
      continue;
    }

    const signalMatch = trimmed.match(/^Signal\s*:\s*(\d+)\s*%/iu);
    if (signalMatch) {
      const signalPercent = Number.parseInt(signalMatch[1], 10);
      if (Number.isFinite(signalPercent)) {
        if (bssidBlock) {
          bssidBlock.signalPercent = signalPercent;
        } else {
          ssidBlock.signalPercent = signalPercent;
        }
      }
      continue;
    }

    const channelMatch = trimmed.match(/^Channel\s*:\s*(\d+)/iu);
    if (channelMatch) {
      const channel = channelMatch[1].trim();
      if (bssidBlock) {
        bssidBlock.channel = channel;
      } else {
        ssidBlock.channel = channel;
      }
      continue;
    }

    const bandMatch = trimmed.match(/^Band\s*:\s*(.*)$/iu);
    if (bandMatch) {
      const bandText = bandMatch[1].trim();
      if (bssidBlock) {
        bssidBlock.bandText = bandText;
      } else {
        ssidBlock.bandText = bandText;
      }
    }
  }

  flushSsidBlock();
  return dedupeByStrongestRssi(parsedEntries);
}

export function parseNmcliOutput(rawOutput) {
  if (!rawOutput || !rawOutput.trim()) {
    return [];
  }

  const lines = rawOutput
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  const parsedEntries = [];

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const fields = splitEscapedFields(line, ':');
    if (fields.length < 5) {
      continue;
    }

    const [bssidField, ssidField, signalField, channelField, ...securityParts] = fields;
    const signalPercent = Number.parseInt(signalField, 10);
    const rssi = signalPercentToRssi(signalPercent);
    if (!Number.isFinite(rssi)) {
      continue;
    }

    parsedEntries.push(
      buildNormalizedNetwork({
        bssid: bssidField,
        syntheticSeed: `${ssidField || '<hidden>'}::${channelField || '?'}::${index + 1}`,
        ssid: ssidField,
        rssi,
        channel: channelField,
        security: securityParts.join(':').trim() || 'UNKNOWN',
      }),
    );
  }

  return dedupeByStrongestRssi(parsedEntries);
}

export function parseIwScanOutput(rawOutput) {
  if (!rawOutput || !rawOutput.trim()) {
    return [];
  }

  const lines = rawOutput.split(/\r?\n/u);
  const parsedEntries = [];
  let current = null;
  let sequence = 0;

  function flushCurrent() {
    if (!current || !Number.isFinite(current.rssi)) {
      current = null;
      return;
    }

    sequence += 1;
    const channel = current.channel || frequencyToChannel(current.frequency);
    const security = current.security || (current.privacyEnabled ? 'WEP/UNKNOWN' : 'OPEN');

    parsedEntries.push(
      buildNormalizedNetwork({
        bssid: current.bssid,
        syntheticSeed: `${current.ssid || '<hidden>'}::${channel || '?'}::${security}::${sequence}`,
        ssid: current.ssid,
        rssi: current.rssi,
        channel,
        security,
      }),
    );

    current = null;
  }

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed) {
      continue;
    }

    const bssMatch = trimmed.match(/^BSS\s+([0-9a-fA-F:]{17})\b/iu);
    if (bssMatch) {
      flushCurrent();
      current = {
        bssid: bssMatch[1].toLowerCase(),
        ssid: '<hidden>',
        rssi: null,
        channel: '',
        frequency: null,
        security: '',
        privacyEnabled: false,
      };
      continue;
    }

    if (!current) {
      continue;
    }

    const signalMatch = trimmed.match(/^signal:\s*(-?\d+(?:\.\d+)?)\s*dBm/iu);
    if (signalMatch) {
      current.rssi = Math.round(Number.parseFloat(signalMatch[1]));
      continue;
    }

    const frequencyMatch = trimmed.match(/^freq:\s*(\d+)/iu);
    if (frequencyMatch) {
      current.frequency = Number.parseInt(frequencyMatch[1], 10);
      continue;
    }

    const dsChannelMatch = trimmed.match(/^DS Parameter set:\s*channel\s*(\d+)/iu);
    if (dsChannelMatch) {
      current.channel = dsChannelMatch[1].trim();
      continue;
    }

    const primaryChannelMatch = trimmed.match(/^primary channel:\s*(\d+)/iu);
    if (primaryChannelMatch) {
      current.channel = primaryChannelMatch[1].trim();
      continue;
    }

    const ssidMatch = trimmed.match(/^SSID:\s*(.*)$/iu);
    if (ssidMatch) {
      current.ssid = ssidMatch[1].trim() || '<hidden>';
      continue;
    }

    if (/^(RSN|WPA)\s*:/iu.test(trimmed)) {
      current.security = 'WPA/WPA2';
      continue;
    }

    if (/^capability:.*privacy/iu.test(trimmed)) {
      current.privacyEnabled = true;
    }
  }

  flushCurrent();
  return dedupeByStrongestRssi(parsedEntries);
}

function parseLine(line, columnStarts) {
  const fromRegex = parseWithRegex(line);
  if (fromRegex) {
    return fromRegex;
  }
  return parseWithColumns(line, columnStarts);
}

function parseWithColumns(line, columnStarts) {
  if (!columnStarts || columnStarts.BSSID === undefined || columnStarts.RSSI === undefined) {
    return null;
  }

  const bssidStart = columnStarts.BSSID;
  const rssiStart = columnStarts.RSSI;

  if (line.length < rssiStart) {
    return null;
  }

  const channelStart = columnStarts.CHANNEL ?? findNextStart(columnStarts, rssiStart);
  const securityStart = columnStarts.SECURITY;

  const ssid = line.slice(0, bssidStart).trim();
  const bssidSliceEnd = rssiStart;
  const bssid = line.slice(bssidStart, bssidSliceEnd).trim().split(/\s+/u)[0];

  if (!BSSID_PATTERN.test(bssid)) {
    return null;
  }

  const rssiToken = line
    .slice(rssiStart, channelStart ?? line.length)
    .trim()
    .split(/\s+/u)[0];
  const rssi = Number.parseInt(rssiToken, 10);
  if (!Number.isFinite(rssi)) {
    return null;
  }

  let channel = '';
  if (channelStart !== undefined) {
    const channelEnd = findNextStart(columnStarts, channelStart);
    channel = line
      .slice(channelStart, channelEnd ?? line.length)
      .trim()
      .split(/\s+/u)[0] ?? '';
  }

  const rest = securityStart !== undefined ? line.slice(securityStart).trim() : '';

  return normalizeNetwork({
    ssid,
    bssid,
    rssi,
    channel,
    security: inferSecurity(rest),
  });
}

function parseWithRegex(line) {
  const match = line.match(LINE_PATTERN);
  if (!match || !match.groups) {
    return null;
  }

  const rssi = Number.parseInt(match.groups.rssi, 10);
  if (!Number.isFinite(rssi)) {
    return null;
  }

  return normalizeNetwork({
    bssid: match.groups.bssid,
    ssid: match.groups.ssid,
    rssi,
    channel: match.groups.channel,
    security: inferSecurity(match.groups.rest),
  });
}

function normalizeNetwork({ bssid, ssid, rssi, channel, security }) {
  const normalizedBssid = String(bssid).toLowerCase();
  if (!BSSID_PATTERN.test(normalizedBssid)) {
    return null;
  }

  const normalizedSsid = String(ssid || '').trim() || '<hidden>';
  const normalizedChannel = String(channel || '').trim();

  return {
    bssid: normalizedBssid,
    ssid: normalizedSsid,
    rssi,
    channel: normalizedChannel,
    band: inferBand(normalizedChannel),
    security: security || 'UNKNOWN',
  };
}

function parseSystemProfilerNetwork(network, seenByKey) {
  if (!network || typeof network !== 'object') {
    return null;
  }

  const ssid = String(network._name || '').trim() || '<hidden>';
  const channelText = String(network.spairport_network_channel || '').trim();
  const channel = parseChannel(channelText);
  const security = normalizeSystemProfilerSecurity(network.spairport_security_mode);

  const key = `${ssid}::${channel || '?'}::${security}`;
  const nextIndex = (seenByKey.get(key) ?? 0) + 1;
  seenByKey.set(key, nextIndex);

  return {
    bssid: syntheticBssid(`${key}::${nextIndex}`),
    ssid,
    rssi: parseSignalNoise(network.spairport_signal_noise),
    channel,
    band: inferBand(channelText || channel),
    security,
    scanSource: 'system_profiler',
    rssiEstimated: !network.spairport_signal_noise,
  };
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

function inferBandFromTextOrChannel(bandText, channelText) {
  const lowered = String(bandText || '').toLowerCase();
  if (lowered.includes('6')) {
    return '6ghz';
  }
  if (lowered.includes('5')) {
    return '5ghz';
  }
  if (lowered.includes('2.4') || lowered.includes('2')) {
    return '2.4ghz';
  }
  return inferBand(channelText);
}

function inferSecurity(securityText) {
  const cleaned = String(securityText || '').trim();
  if (!cleaned) {
    return 'UNKNOWN';
  }

  const tokens = cleaned.split(/\s+/u);
  if (tokens.length >= 3) {
    return tokens.slice(2).join(' ') || 'UNKNOWN';
  }

  if (/wpa|wep|none|open|802\.1x|psk|sae/i.test(cleaned)) {
    return cleaned;
  }

  return 'UNKNOWN';
}

function parseChannel(channelText) {
  const match = String(channelText || '').match(/\d+/u);
  return match ? match[0] : '';
}

function parseSignalNoise(signalNoiseText) {
  const match = String(signalNoiseText || '').match(/(-?\d+)\s*dBm/i);
  if (!match) {
    return null;
  }

  const value = Number.parseInt(match[1], 10);
  return Number.isFinite(value) ? value : null;
}

function signalPercentToRssi(signalPercent) {
  const numeric = Number(signalPercent);
  if (!Number.isFinite(numeric)) {
    return null;
  }

  const clamped = Math.max(0, Math.min(100, numeric));
  return Math.round(clamped / 2 - 100);
}

function splitEscapedFields(text, delimiter = ':') {
  const values = [];
  let current = '';
  let escaped = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }

    if (ch === '\\') {
      escaped = true;
      continue;
    }

    if (ch === delimiter) {
      values.push(current);
      current = '';
      continue;
    }

    current += ch;
  }

  if (escaped) {
    current += '\\';
  }

  values.push(current);
  return values;
}

function frequencyToChannel(frequency) {
  const freq = Number(frequency);
  if (!Number.isFinite(freq) || freq <= 0) {
    return '';
  }

  if (freq === 2484) {
    return '14';
  }
  if (freq >= 2412 && freq <= 2472) {
    return String(Math.round((freq - 2407) / 5));
  }
  if (freq >= 5000 && freq <= 5895) {
    return String(Math.round((freq - 5000) / 5));
  }
  if (freq >= 5955 && freq <= 7115) {
    return String(Math.round((freq - 5950) / 5));
  }

  return '';
}

function formatNetshSecurity(authentication, encryption) {
  const auth = String(authentication || '').trim();
  const enc = String(encryption || '').trim();

  if (auth && enc) {
    return `${auth}/${enc}`.toUpperCase();
  }
  if (auth) {
    return auth.toUpperCase();
  }
  if (enc) {
    return enc.toUpperCase();
  }
  return 'UNKNOWN';
}

function buildNormalizedNetwork({
  bssid,
  syntheticSeed,
  ssid,
  rssi,
  channel,
  bandText,
  security,
}) {
  const bssidRaw = String(bssid || '').trim().toLowerCase();
  const normalizedBssid = EXACT_BSSID_PATTERN.test(bssidRaw)
    ? bssidRaw
    : syntheticBssid(syntheticSeed || `${ssid || '<hidden>'}::${channel || '?'}::${security || 'UNKNOWN'}`);

  const normalized = normalizeNetwork({
    bssid: normalizedBssid,
    ssid,
    rssi,
    channel,
    security,
  });

  if (!normalized) {
    return null;
  }

  if (bandText) {
    normalized.band = inferBandFromTextOrChannel(bandText, normalized.channel);
  }
  normalized.bssidSynthetic = !EXACT_BSSID_PATTERN.test(bssidRaw);
  return normalized;
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

function normalizeSystemProfilerSecurity(mode) {
  const cleaned = String(mode || '')
    .trim()
    .replace(/^spairport_security_mode_/u, '')
    .replace(/^pairport_security_mode_/u, '')
    .replace(/_/gu, ' ')
    .trim();

  return cleaned ? cleaned.toUpperCase() : 'UNKNOWN';
}

function syntheticBssid(seed) {
  const hashA = hashCode(seed);
  const hashB = hashCode(`${seed}::wifi-space`);

  const bytes = [
    hashA & 0xff,
    (hashA >>> 8) & 0xff,
    (hashA >>> 16) & 0xff,
    (hashA >>> 24) & 0xff,
    hashB & 0xff,
    (hashB >>> 8) & 0xff,
  ];

  // Mark as locally administered unicast address.
  bytes[0] = (bytes[0] | 0x02) & 0xfe;

  return bytes.map((value) => value.toString(16).padStart(2, '0')).join(':');
}

function hashCode(value) {
  let hash = 2166136261;
  for (let i = 0; i < value.length; i += 1) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function inferColumnStarts(headerLine) {
  const columns = ['SSID', 'BSSID', 'RSSI', 'CHANNEL', 'HT', 'CC', 'SECURITY'];
  const starts = {};

  for (const column of columns) {
    const index = headerLine.indexOf(column);
    if (index >= 0) {
      starts[column] = index;
    }
  }

  return starts;
}

function findNextStart(columnStarts, currentStart) {
  const nextValues = Object.values(columnStarts).filter((value) => value > currentStart);
  if (!nextValues.length) {
    return undefined;
  }
  return Math.min(...nextValues);
}

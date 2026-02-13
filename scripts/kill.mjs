import { execSync } from 'node:child_process';

const TARGET_PORTS = [8787, 5173];

function getPidsForPort(port) {
  try {
    const output = execSync(`lsof -ti tcp:${port}`, {
      stdio: ['ignore', 'pipe', 'ignore'],
      encoding: 'utf8',
    });

    return output
      .split(/\s+/u)
      .map((value) => Number.parseInt(value, 10))
      .filter((value) => Number.isFinite(value));
  } catch {
    return [];
  }
}

function unique(values) {
  return [...new Set(values)];
}

function killPids(pids, signal) {
  for (const pid of pids) {
    try {
      process.kill(pid, signal);
      console.log(`[kill] sent ${signal} to pid ${pid}`);
    } catch {
      // Process may already be gone.
    }
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const firstPass = unique(TARGET_PORTS.flatMap((port) => getPidsForPort(port)));
  if (!firstPass.length) {
    console.log('[kill] no wifi-topology-viewer processes found on ports 8787/5173');
    return;
  }

  killPids(firstPass, 'SIGTERM');
  await sleep(600);

  const secondPass = unique(TARGET_PORTS.flatMap((port) => getPidsForPort(port)));
  if (secondPass.length) {
    killPids(secondPass, 'SIGKILL');
  }

  const remaining = unique(TARGET_PORTS.flatMap((port) => getPidsForPort(port)));
  if (remaining.length) {
    console.log(`[kill] warning: remaining pids ${remaining.join(', ')}`);
  } else {
    console.log('[kill] done');
  }
}

void main();

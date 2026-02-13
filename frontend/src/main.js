import './styles.css';

import {
  fetchConfig,
  fetchRecordStatus,
  fetchReplayStatus,
  startRecording,
  startReplay,
  stopRecording,
  stopReplay,
  updateConfig,
} from './api.js';
import { createHud } from './hud.js';
import { createWifiScene } from './scene.js';
import { connectSnapshotStream } from './ws.js';

const sceneRoot = document.getElementById('scene-root');
const hudRoot = document.getElementById('hud-root');

let hud;

const scene = createWifiScene(sceneRoot, {
  onSelect(bssid) {
    hud?.setSelectedBssid(bssid);
  },
});

hud = createHud(hudRoot, {
  applyConfig(payload) {
    return updateConfig(payload);
  },
  startRecording(path) {
    return startRecording(path || undefined);
  },
  stopRecording() {
    return stopRecording();
  },
  startReplay(payload) {
    if (!payload.path) {
      throw new Error('Replay path is required');
    }
    return startReplay(payload);
  },
  stopReplay() {
    return stopReplay();
  },
  onVisualSettingsChange(settings) {
    scene.applyVisualSettings(settings);
  },
});

const socket = connectSnapshotStream({
  onSnapshot(snapshot) {
    scene.update(snapshot);
    hud.update(snapshot);
  },
  onStatus(status) {
    hud.setConnection(status);
  },
});

void bootstrapControls();

async function bootstrapControls() {
  try {
    const [config, recordStatus, replayStatus] = await Promise.all([
      fetchConfig(),
      fetchRecordStatus(),
      fetchReplayStatus(),
    ]);

    hud.setConfig(config);
    hud.setRecording(recordStatus);
    hud.setReplay(replayStatus);
  } catch (error) {
    hud.setControlMessage(error.message || 'backend unavailable', true);
  }
}

window.addEventListener('beforeunload', () => {
  socket.close();
  scene.dispose();
});

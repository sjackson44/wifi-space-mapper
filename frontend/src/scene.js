import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js';
import {
  estimateDistanceMetersFromRssi,
  estimatePairDistanceRangeMeters,
  formatDistanceMeters,
  formatDistanceRangeMeters,
} from './distance.js';

const MAX_RENDER_NODES = 120;
const MAX_RENDER_EDGES = 160;

const BASE_EDGE_OPACITY = 0.2;
const OUTER_GRID_OPACITY_NEAR = 0.15;
const OUTER_GRID_OPACITY_FAR = 0.05;
const INNER_GRID_OPACITY_NEAR = 0.09;
const INNER_GRID_OPACITY_FAR = 0.04;
const GRID_FADE_NEAR_DISTANCE = 60;
const GRID_FADE_FAR_DISTANCE = 220;

const MOTION_AMPLITUDE = 0.34;
const MINIMAL_CAMERA_DISTANCE_FACTOR = 0.78;

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function lerp(a, b, alpha) {
  return a + (b - a) * alpha;
}

function hashCode(value) {
  const text = String(value ?? '');
  let hash = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function truncateLabel(text, maxLength = 18) {
  const source = String(text || '');
  if (source.length <= maxLength) {
    return source;
  }
  return `${source.slice(0, maxLength - 1)}…`;
}

function createGlowTexture() {
  const size = 128;
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;

  const ctx = canvas.getContext('2d');
  const center = size / 2;
  const gradient = ctx.createRadialGradient(center, center, 0, center, center, center);
  gradient.addColorStop(0, 'rgba(180, 255, 210, 1)');
  gradient.addColorStop(0.25, 'rgba(80, 255, 150, 0.75)');
  gradient.addColorStop(0.55, 'rgba(20, 160, 90, 0.25)');
  gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');

  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, size, size);

  const texture = new THREE.CanvasTexture(canvas);
  texture.needsUpdate = true;
  return texture;
}

function createClusterColorGetter() {
  const cache = new Map([[0, new THREE.Color(0x5bff9d)]]);
  return (clusterId) => {
    const normalized = Number.isFinite(clusterId) ? Math.max(0, clusterId) : 0;
    if (cache.has(normalized)) {
      return cache.get(normalized);
    }

    // Keep palette in green/cyan with subtle deterministic hue shifts.
    const offset = ((normalized * 12) % 34) - 17;
    const hue = (140 + offset) / 360;
    const color = new THREE.Color().setHSL(hue, 0.78, 0.64);
    cache.set(normalized, color);
    return color;
  };
}

function createSpritePool(scene, glowTexture) {
  const pool = [];

  for (let i = 0; i < MAX_RENDER_NODES; i += 1) {
    const material = new THREE.SpriteMaterial({
      map: glowTexture,
      color: new THREE.Color(0x5bff9d),
      transparent: true,
      opacity: 0,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
    });

    const sprite = new THREE.Sprite(material);
    sprite.visible = false;
    sprite.scale.setScalar(0.1);
    scene.add(sprite);

    const node = {
      id: null,
      sprite,
      material,
      lastSeenFrame: -1,
      ap: null,
      basePosition: new THREE.Vector3(),
      baseScale: 0.1,
      baseOpacity: 0,
      motionSeed: 0,
    };

    sprite.userData.node = node;
    pool.push(node);
  }

  return pool;
}

export function createWifiScene(container, handlers = {}) {
  const getClusterColor = createClusterColorGetter();

  const tooltipEl = document.createElement('div');
  tooltipEl.className = 'node-tooltip';
  const tooltipTitleEl = document.createElement('p');
  tooltipTitleEl.className = 'node-tooltip-title';
  const tooltipMetaEl = document.createElement('p');
  tooltipMetaEl.className = 'node-tooltip-meta';
  const tooltipPairEl = document.createElement('p');
  tooltipPairEl.className = 'node-tooltip-pair';
  tooltipPairEl.hidden = true;
  tooltipEl.appendChild(tooltipTitleEl);
  tooltipEl.appendChild(tooltipMetaEl);
  tooltipEl.appendChild(tooltipPairEl);
  container.appendChild(tooltipEl);

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(container.clientWidth, container.clientHeight);
  renderer.toneMapping = THREE.ReinhardToneMapping;
  renderer.toneMappingExposure = 1.15;
  container.appendChild(renderer.domElement);

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x010703);
  scene.fog = new THREE.FogExp2(0x03130b, 0.012);

  const camera = new THREE.PerspectiveCamera(
    58,
    container.clientWidth / container.clientHeight,
    0.1,
    600,
  );
  camera.position.set(0, 18, 130);
  const defaultCameraPosition = camera.position.clone();
  const minimalCameraPosition = defaultCameraPosition.clone().multiplyScalar(MINIMAL_CAMERA_DISTANCE_FACTOR);
  const cameraTargetPosition = defaultCameraPosition.clone();

  const controls = new OrbitControls(camera, renderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;
  controls.minDistance = 45;
  controls.maxDistance = 240;

  scene.add(new THREE.AmbientLight(0x4eff97, 0.35));
  const keyLight = new THREE.PointLight(0x52ff9f, 1.5, 460);
  keyLight.position.set(30, 52, 60);
  scene.add(keyLight);

  const worldSphereMaterial = new THREE.MeshBasicMaterial({
    color: new THREE.Color(0x2fff8f),
    wireframe: true,
    transparent: true,
    opacity: OUTER_GRID_OPACITY_NEAR,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });

  const worldSphere = new THREE.Mesh(
    new THREE.SphereGeometry(72, 48, 32),
    worldSphereMaterial,
  );

  const innerSphereMaterial = new THREE.MeshBasicMaterial({
    color: new THREE.Color(0x15a25c),
    wireframe: true,
    transparent: true,
    opacity: INNER_GRID_OPACITY_NEAR,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });

  const innerSphere = new THREE.Mesh(
    new THREE.SphereGeometry(46, 32, 22),
    innerSphereMaterial,
  );

  const backgroundGridGroup = new THREE.Group();
  backgroundGridGroup.add(worldSphere);
  backgroundGridGroup.add(innerSphere);
  scene.add(backgroundGridGroup);

  const edgePositions = new Float32Array(MAX_RENDER_EDGES * 2 * 3);
  const edgeColors = new Float32Array(MAX_RENDER_EDGES * 2 * 3);
  const edgeGeometry = new THREE.BufferGeometry();

  const edgePositionAttr = new THREE.BufferAttribute(edgePositions, 3);
  edgePositionAttr.setUsage(THREE.DynamicDrawUsage);
  const edgeColorAttr = new THREE.BufferAttribute(edgeColors, 3);
  edgeColorAttr.setUsage(THREE.DynamicDrawUsage);

  edgeGeometry.setAttribute('position', edgePositionAttr);
  edgeGeometry.setAttribute('color', edgeColorAttr);
  edgeGeometry.setDrawRange(0, 0);

  const edgeMaterial = new THREE.LineBasicMaterial({
    vertexColors: true,
    transparent: true,
    opacity: BASE_EDGE_OPACITY,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  });
  const edgeLines = new THREE.LineSegments(edgeGeometry, edgeMaterial);
  edgeLines.frustumCulled = false;
  scene.add(edgeLines);

  const coverageGeometry = new THREE.SphereGeometry(1, 22, 16);
  const coverageMaterial = new THREE.MeshBasicMaterial({
    wireframe: true,
    transparent: true,
    opacity: 0.2,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    depthTest: false,
    side: THREE.DoubleSide,
    vertexColors: true,
  });
  const coverageMesh = new THREE.InstancedMesh(coverageGeometry, coverageMaterial, MAX_RENDER_NODES);
  coverageMesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
  coverageMesh.count = 0;
  coverageMesh.frustumCulled = false;
  scene.add(coverageMesh);

  const selectionRingMaterial = new THREE.MeshBasicMaterial({
    color: new THREE.Color(0x9effcf),
    transparent: true,
    opacity: 0.55,
    depthWrite: false,
    depthTest: false,
    side: THREE.DoubleSide,
    blending: THREE.AdditiveBlending,
  });
  const selectionRing = new THREE.Mesh(
    new THREE.RingGeometry(0.72, 0.95, 56),
    selectionRingMaterial,
  );
  selectionRing.visible = false;
  scene.add(selectionRing);

  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  const bloomPass = new UnrealBloomPass(
    new THREE.Vector2(container.clientWidth, container.clientHeight),
    1,
    0.38,
    0.18,
  );
  composer.addPass(bloomPass);

  const glowTexture = createGlowTexture();
  const spritePool = createSpritePool(scene, glowTexture);
  const freePool = [...spritePool];
  const activePoolById = new Map();

  const tempPosition = new THREE.Vector3();
  const tempScale = new THREE.Vector3();
  const tempMatrix = new THREE.Matrix4();
  const identityQuaternion = new THREE.Quaternion();
  const tempColor = new THREE.Color();
  const whiteColor = new THREE.Color(0xffffff);
  const raycaster = new THREE.Raycaster();
  const pointerNdc = new THREE.Vector2(2, 2);

  const visualSettings = {
    minimalMode: false,
    subtleMotion: false,
  };

  let hoveredNode = null;
  let selectedBssid = null;

  let frameId = 0;

  function acquireNode(id) {
    if (activePoolById.has(id)) {
      return activePoolById.get(id);
    }

    const node = freePool.pop();
    if (!node) {
      return null;
    }

    node.id = id;
    node.ap = null;
    node.motionSeed = (hashCode(id) % 720) / 80;
    node.sprite.visible = true;
    node.material.opacity = 0.9;
    activePoolById.set(id, node);
    return node;
  }

  function releaseNode(id) {
    const node = activePoolById.get(id);
    if (!node) {
      return;
    }

    activePoolById.delete(id);
    node.id = null;
    node.ap = null;
    node.lastSeenFrame = -1;
    node.baseScale = 0.1;
    node.baseOpacity = 0;
    node.basePosition.set(0, 0, 0);
    node.sprite.position.set(0, 0, 0);
    node.sprite.visible = false;
    node.sprite.scale.setScalar(0.1);
    node.material.opacity = 0;
    freePool.push(node);
  }

  function setSelectedBssid(nextBssid, emit = true) {
    const normalized = nextBssid || null;
    if (selectedBssid === normalized) {
      return;
    }

    selectedBssid = normalized;
    if (emit) {
      handlers.onSelect?.(selectedBssid);
    }
  }

  function applyVisualSettings(nextSettings = {}) {
    if (nextSettings.minimalMode !== undefined) {
      visualSettings.minimalMode = Boolean(nextSettings.minimalMode);
    }
    if (nextSettings.subtleMotion !== undefined) {
      visualSettings.subtleMotion = Boolean(nextSettings.subtleMotion);
    }

    const showDecor = !visualSettings.minimalMode;
    edgeLines.visible = showDecor;
    coverageMesh.visible = showDecor;
    backgroundGridGroup.visible = showDecor;

    edgeMaterial.opacity = showDecor ? BASE_EDGE_OPACITY : 0;

    if (visualSettings.minimalMode) {
      cameraTargetPosition.copy(minimalCameraPosition);
      controls.rotateSpeed = 0.78;
    } else {
      cameraTargetPosition.copy(defaultCameraPosition);
      controls.rotateSpeed = 1;
    }

    if (!showDecor) {
      edgeGeometry.setDrawRange(0, 0);
      edgePositionAttr.needsUpdate = true;
      edgeColorAttr.needsUpdate = true;
      coverageMesh.count = 0;
      coverageMesh.instanceMatrix.needsUpdate = true;
    }
  }

  function hideTooltip() {
    hoveredNode = null;
    tooltipEl.classList.remove('visible');
  }

  function showTooltip(ap, clientX, clientY) {
    if (!ap) {
      hideTooltip();
      return;
    }

    const ssid = ap.ssid || '<hidden>';
    const rssi = ap.rssiEstimated ? `~${ap.rssi}` : `${ap.rssi}`;
    const channel = ap.channel || '?';
    const band = ap.band || 'unknown';
    const distance = estimateDistanceMetersFromRssi(ap.rssi);

    tooltipTitleEl.textContent = ssid;
    tooltipMetaEl.textContent = `${rssi} dBm • ch ${channel} • ${band} • ${formatDistanceMeters(distance)}`;
    tooltipPairEl.hidden = true;

    if (selectedBssid && ap.bssid !== selectedBssid) {
      const selectedAp = activePoolById.get(selectedBssid)?.ap;
      const selectedDistance = estimateDistanceMetersFromRssi(selectedAp?.rssi);
      const pairRange = estimatePairDistanceRangeMeters(selectedDistance, distance);
      if (selectedAp && pairRange) {
        const selectedName = truncateLabel(selectedAp.ssid || '<hidden>');
        tooltipPairEl.textContent = `Pair estimate with ${selectedName}: ${formatDistanceRangeMeters(pairRange)}`;
        tooltipPairEl.hidden = false;
      }
    }

    tooltipEl.classList.add('visible');

    const rect = renderer.domElement.getBoundingClientRect();
    const localX = clientX - rect.left;
    const localY = clientY - rect.top;
    const tooltipWidth = tooltipEl.offsetWidth || 220;
    const tooltipHeight = tooltipEl.offsetHeight || 54;
    const maxLeft = Math.max(8, rect.width - tooltipWidth - 8);
    const maxTop = Math.max(8, rect.height - tooltipHeight - 8);
    const left = clamp(localX + 14, 8, maxLeft);
    const top = clamp(localY + 14, 8, maxTop);

    tooltipEl.style.left = `${left}px`;
    tooltipEl.style.top = `${top}px`;
  }

  function pickHoveredNode(clientX, clientY) {
    const rect = renderer.domElement.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) {
      return null;
    }

    pointerNdc.x = ((clientX - rect.left) / rect.width) * 2 - 1;
    pointerNdc.y = -((clientY - rect.top) / rect.height) * 2 + 1;
    raycaster.setFromCamera(pointerNdc, camera);

    const activeSprites = [];
    for (const node of activePoolById.values()) {
      if (node.sprite.visible) {
        activeSprites.push(node.sprite);
      }
    }

    if (!activeSprites.length) {
      return null;
    }

    const intersections = raycaster.intersectObjects(activeSprites, false);
    if (!intersections.length) {
      return null;
    }

    return intersections[0].object.userData.node || null;
  }

  function onPointerMove(event) {
    if (event.buttons > 0) {
      hideTooltip();
      return;
    }

    const node = pickHoveredNode(event.clientX, event.clientY);
    if (!node || !node.ap) {
      hideTooltip();
      return;
    }

    hoveredNode = node;
    showTooltip(node.ap, event.clientX, event.clientY);
  }

  function onPointerLeave() {
    hideTooltip();
  }

  function onClick(event) {
    const node = pickHoveredNode(event.clientX, event.clientY);
    if (!node || !node.ap) {
      setSelectedBssid(null);
      hideTooltip();
      return;
    }

    const nextSelected = selectedBssid === node.id ? null : node.id;
    setSelectedBssid(nextSelected);

    if (!nextSelected) {
      hideTooltip();
      return;
    }

    hoveredNode = node;
    showTooltip(node.ap, event.clientX, event.clientY);
  }

  renderer.domElement.addEventListener('pointermove', onPointerMove);
  renderer.domElement.addEventListener('pointerleave', onPointerLeave);
  renderer.domElement.addEventListener('click', onClick);
  applyVisualSettings();

  function update(snapshot) {
    frameId += 1;

    const positions = snapshot.positions ?? {};
    const aps = (snapshot.aps ?? []).slice(0, MAX_RENDER_NODES);
    const clusterById = new Map(aps.map((ap) => [ap.bssid, ap.clusterId || 0]));
    const edgeThreshold = Number.isFinite(snapshot.meta?.edgeThreshold)
      ? snapshot.meta.edgeThreshold
      : 0.6;

    for (const ap of aps) {
      const node = acquireNode(ap.bssid);
      if (!node) {
        continue;
      }

      node.lastSeenFrame = frameId;
      node.ap = ap;

      const target = positions[ap.bssid] ?? { x: 0, y: 0, z: 0 };
      node.basePosition.x += (target.x - node.basePosition.x) * 0.35;
      node.basePosition.y += (target.y - node.basePosition.y) * 0.35;
      node.basePosition.z += (target.z - node.basePosition.z) * 0.35;
      node.sprite.position.copy(node.basePosition);

      const strength = clamp((ap.rssi + 90) / 60, 0, 1);
      const isSelected = ap.bssid === selectedBssid;
      node.baseScale = (1.7 + strength * 4.3) * (isSelected ? 1.18 : 1);

      const clusterColor = getClusterColor(ap.clusterId || 0);
      if (isSelected) {
        tempColor.copy(clusterColor).lerp(whiteColor, 0.24);
        node.material.color.copy(tempColor);
      } else {
        node.material.color.copy(clusterColor);
      }
      node.baseOpacity = isSelected ? 1 : ap.rssiEstimated ? 0.64 : 0.92;
      node.material.opacity = node.baseOpacity;
    }

    for (const [id, node] of activePoolById.entries()) {
      if (node.lastSeenFrame !== frameId) {
        if (id === selectedBssid) {
          setSelectedBssid(null);
        }
        if (hoveredNode === node) {
          hideTooltip();
        }
        releaseNode(id);
      }
    }

    if (visualSettings.minimalMode) {
      coverageMesh.count = 0;
      coverageMesh.instanceMatrix.needsUpdate = true;
    } else {
      let coverageIndex = 0;
      for (const ap of aps) {
        const node = activePoolById.get(ap.bssid);
        if (!node || coverageIndex >= MAX_RENDER_NODES) {
          continue;
        }

        const strength = clamp((ap.rssi + 90) / 60, 0, 1);
        const sphereRadius = (5 + strength * 20) * (ap.bssid === selectedBssid ? 1.08 : 1);

        tempPosition.copy(node.basePosition);
        tempScale.setScalar(sphereRadius);
        tempMatrix.compose(tempPosition, identityQuaternion, tempScale);

        coverageMesh.setMatrixAt(coverageIndex, tempMatrix);
        coverageMesh.setColorAt(coverageIndex, getClusterColor(ap.clusterId || 0));
        coverageIndex += 1;
      }

      coverageMesh.count = coverageIndex;
      coverageMesh.instanceMatrix.needsUpdate = true;
      if (coverageMesh.instanceColor) {
        coverageMesh.instanceColor.needsUpdate = true;
      }
    }

    if (visualSettings.minimalMode) {
      edgeGeometry.setDrawRange(0, 0);
      edgePositionAttr.needsUpdate = true;
      edgeColorAttr.needsUpdate = true;
    } else {
      let edgeCount = 0;
      for (const edge of snapshot.edges ?? []) {
        if (edgeCount >= MAX_RENDER_EDGES) {
          break;
        }
        if (edge.corr < edgeThreshold) {
          continue;
        }

        const a = positions[edge.a];
        const b = positions[edge.b];
        if (!a || !b) {
          continue;
        }

        const base = edgeCount * 6;
        edgePositions[base] = a.x;
        edgePositions[base + 1] = a.y;
        edgePositions[base + 2] = a.z;
        edgePositions[base + 3] = b.x;
        edgePositions[base + 4] = b.y;
        edgePositions[base + 5] = b.z;

        const corrIntensity = clamp((edge.corr - edgeThreshold) / (1 - edgeThreshold), 0, 1);
        const colorA = getClusterColor(clusterById.get(edge.a) || 0);
        const colorB = getClusterColor(clusterById.get(edge.b) || 0);
        tempColor.copy(colorA).lerp(colorB, 0.5).multiplyScalar(0.28 + corrIntensity * 0.5);

        edgeColors[base] = tempColor.r;
        edgeColors[base + 1] = tempColor.g;
        edgeColors[base + 2] = tempColor.b;
        edgeColors[base + 3] = tempColor.r;
        edgeColors[base + 4] = tempColor.g;
        edgeColors[base + 5] = tempColor.b;

        edgeCount += 1;
      }

      edgeGeometry.setDrawRange(0, edgeCount * 2);
      edgePositionAttr.needsUpdate = true;
      edgeColorAttr.needsUpdate = true;
    }
  }

  const clock = new THREE.Clock();
  let animationFrameId = 0;

  function renderLoop() {
    animationFrameId = requestAnimationFrame(renderLoop);

    const t = clock.getElapsedTime();
    worldSphere.rotation.y += 0.0009;
    innerSphere.rotation.x -= 0.0006;
    innerSphere.rotation.z += 0.0004;

    keyLight.position.x = Math.sin(t * 0.35) * 56;
    keyLight.position.z = Math.cos(t * 0.28) * 56;

    controls.target.y = Math.sin(t * 0.45) * 2;
    camera.position.lerp(cameraTargetPosition, 0.08);
    controls.update();

    if (!visualSettings.minimalMode) {
      const cameraDistance = camera.position.distanceTo(controls.target);
      const fade = clamp(
        (cameraDistance - GRID_FADE_NEAR_DISTANCE) /
          (GRID_FADE_FAR_DISTANCE - GRID_FADE_NEAR_DISTANCE),
        0,
        1,
      );
      worldSphereMaterial.opacity = lerp(OUTER_GRID_OPACITY_NEAR, OUTER_GRID_OPACITY_FAR, fade);
      innerSphereMaterial.opacity = lerp(INNER_GRID_OPACITY_NEAR, INNER_GRID_OPACITY_FAR, fade);
    }

    const selectedNode = selectedBssid ? activePoolById.get(selectedBssid) : null;

    for (const node of activePoolById.values()) {
      const isSelected = selectedNode === node;
      const isHovered = hoveredNode === node;

      let posX = node.basePosition.x;
      let posY = node.basePosition.y;
      let posZ = node.basePosition.z;

      if (visualSettings.subtleMotion) {
        const wave = t * 0.85 + node.motionSeed;
        const amp = MOTION_AMPLITUDE;
        posX += Math.sin(wave * 1.1) * amp;
        posY += Math.sin(wave * 0.9 + 1.4) * amp * 0.75;
        posZ += Math.cos(wave * 1.04 + 0.6) * amp;
      }

      node.sprite.position.set(posX, posY, posZ);

      let scale = node.baseScale;
      if (isHovered && !isSelected) {
        scale *= 1.05;
      }
      if (isSelected) {
        scale *= 1 + Math.sin(t * 3.2) * 0.09;
      }
      node.sprite.scale.set(scale, scale, 1);

      if (isSelected) {
        node.material.opacity = 1;
      } else if (isHovered) {
        node.material.opacity = Math.min(1, node.baseOpacity + 0.12);
      } else {
        node.material.opacity = node.baseOpacity;
      }
    }

    if (selectedNode) {
      selectionRing.visible = true;
      selectionRing.position.copy(selectedNode.sprite.position);
      selectionRing.quaternion.copy(camera.quaternion);
      selectionRing.scale.setScalar(selectedNode.baseScale * (1.62 + Math.sin(t * 2.4) * 0.12));
      selectionRingMaterial.color.copy(getClusterColor(selectedNode.ap?.clusterId || 0));
      selectionRingMaterial.opacity = 0.6 + Math.sin(t * 2.4) * 0.1;
    } else {
      selectionRing.visible = false;
    }

    composer.render();
  }

  renderLoop();

  function onResize() {
    const { clientWidth, clientHeight } = container;
    camera.aspect = clientWidth / clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(clientWidth, clientHeight);
    composer.setSize(clientWidth, clientHeight);
  }

  window.addEventListener('resize', onResize);

  return {
    update,
    applyVisualSettings,
    setVisualMode: applyVisualSettings,
    dispose() {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', onResize);
      renderer.domElement.removeEventListener('pointermove', onPointerMove);
      renderer.domElement.removeEventListener('pointerleave', onPointerLeave);
      renderer.domElement.removeEventListener('click', onClick);

      for (const node of spritePool) {
        scene.remove(node.sprite);
        node.material.dispose();
      }

      edgeGeometry.dispose();
      edgeMaterial.dispose();
      coverageGeometry.dispose();
      coverageMaterial.dispose();
      selectionRing.geometry.dispose();
      selectionRingMaterial.dispose();
      worldSphere.geometry.dispose();
      worldSphereMaterial.dispose();
      innerSphere.geometry.dispose();
      innerSphereMaterial.dispose();
      glowTexture.dispose();
      controls.dispose();
      composer.dispose();
      renderer.dispose();
      tooltipEl.remove();
    },
  };
}

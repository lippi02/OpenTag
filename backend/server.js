'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const APP_VERSION = (() => { try { return require('./package.json').version; } catch (_) { return 'dev'; } })();
const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT || 3000);
const WS_PATH = process.env.WS_PATH || '/ws';
const TRACKER_TTL_MS = Number(process.env.TRACKER_TTL_MS || 15000);
const MAX_MESSAGE_BYTES = 32 * 1024;
const MAX_BODY_BYTES = 8 * 1024;
const MAX_TRACKERS_PER_USER = 100;
const PING_INTERVAL_MS = Number(process.env.PING_INTERVAL_MS || 25000);
const DATA_FILE = process.env.DATA_FILE || '';
const AUTH_FILE = process.env.AUTH_FILE || (DATA_FILE ? path.join(path.dirname(DATA_FILE), 'auth.json') : '');
const TRACKERS_FILE = process.env.TRACKERS_FILE || (DATA_FILE ? path.join(path.dirname(DATA_FILE), 'trackers.json') : '');
const REGISTRATION_ENABLED = String(process.env.REGISTRATION_ENABLED || 'true').toLowerCase() !== 'false';
const SESSION_COOKIE = 'opentag_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const USERNAME_RE = /^[a-zA-Z0-9._-]{3,32}$/;
const PASSWORD_MIN_LENGTH = Math.max(0, Number(process.env.PASSWORD_MIN_LENGTH ?? 10) || 0);
const PASSWORD_MAX_LENGTH = 128;
const SCRYPT_KEY_LENGTH = 64;
const scryptAsync = require('node:util').promisify(crypto.scrypt);
const TRUSTED_PROXY_HOPS = Math.max(0, Number(process.env.TRUSTED_PROXY_HOPS ?? 1) || 0);
const STATIC_DIR = process.env.STATIC_DIR ? path.resolve(process.env.STATIC_DIR) : '';
const MAX_WS_BACKLOG_BYTES = 1024 * 1024;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const MAX_DEVICE_ID_LENGTH = 100;
const STATIC_MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
};

const users = new Map();
const usersByName = new Map();
const sessions = new Map();
const trackerStates = new Map();
const lastKnown = new Map();
const ownedTrackers = new Map();
const clients = new Set();
const clientsByUser = new Map();
const authRateLimits = new Map();
let saveTimer = null;
let saving = false;
let dirty = false;
const DUMMY_SALT = crypto.randomBytes(16);

function now() { return Date.now(); }
function finiteNumber(value) {
  if (typeof value === 'string') { if (!value.trim()) return null; }
  else if (typeof value !== 'number') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}
function validLatitude(value) {
  const n = finiteNumber(value);
  return n !== null && n >= -90 && n <= 90;
}
function validLongitude(value) {
  const n = finiteNumber(value);
  return n !== null && n >= -180 && n <= 180;
}
function clampText(value, maxLength) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLength);
}
function jsonResponse(response, statusCode, data, extraHeaders = {}) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders,
  });
  response.end(JSON.stringify(data));
}
function safeUser(user) {
  return {
    id: user.id,
    username: user.username,
    createdAt: user.createdAt
  };
}
function hashSession(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
function parseCookies(header) {
  const out = Object.create(null);
  for (const part of String(header || '').split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    try {
      out[key] = decodeURIComponent(value);
    } catch (_) {
      out[key] = value;
    }
  }
  return out;
}
function isSecureRequest(request) {
  const forwarded = String(request.headers['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  return request.socket.encrypted === true || forwarded === 'https';
}
function cookieHeader(request, token, maxAgeSeconds) {
  const bits = [`${SESSION_COOKIE}=${encodeURIComponent(token)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSeconds}`];
  if (isSecureRequest(request)) bits.push('Secure');
  return bits.join('; ');
}
function setSessionCookie(request, response, token) {
  response.setHeader('Set-Cookie', cookieHeader(request, token, Math.floor(SESSION_TTL_MS / 1000)));
}
function clearSessionCookie(request, response) {
  response.setHeader('Set-Cookie', cookieHeader(request, '', 0));
}
function getSessionUser(request) {
  const cookies = parseCookies(request.headers.cookie);
  const token = cookies[SESSION_COOKIE];
  if (!token) return null;
  const key = hashSession(token);
  const session = sessions.get(key);
  if (!session) return null;
  if (session.expiresAt <= now()) {
    sessions.delete(key);
    return null;
  }
  const user = users.get(session.userId);
  if (!user) {
    sessions.delete(key);
    return null;
  }
  return user;
}
function createSession(user) {
  const token = crypto.randomBytes(32).toString('base64url');
  sessions.set(hashSession(token), {
    userId: user.id,
    expiresAt: now() + SESSION_TTL_MS
  });
  return token;
}
function getClientIp(request) {
  const parts = String(request.headers['x-forwarded-for'] || '').split(',').map(p => p.trim()).filter(Boolean);
  if (TRUSTED_PROXY_HOPS > 0 && parts.length) {
    return parts[Math.max(0, parts.length - TRUSTED_PROXY_HOPS)];
  }
  return request.socket.remoteAddress || 'unknown';
}
function rateLimitAuth(request, response, route) {
  const key = `${route}:${getClientIp(request)}`;
  const cutoff = now() - RATE_WINDOW_MS;
  const timestamps = (authRateLimits.get(key) || []).filter(time => time > cutoff);
  if (timestamps.length >= 12) {
    authRateLimits.set(key, timestamps);
    jsonResponse(response, 429, { error: 'Too many attempts. Please wait 15 minutes and try again.' }, { 'Retry-After': '900' });
    return false;
  }
  timestamps.push(now());
  authRateLimits.set(key, timestamps);
  return true;
}
async function readJsonBody(request) {
  const contentType = String(request.headers['content-type'] || '').toLowerCase();
  if (!contentType.startsWith('application/json')) {
    const error = new Error('Content-Type must be application/json');
    error.statusCode = 415;
    throw error;
  }
  const declaredLength = Number(request.headers['content-length'] || 0);
  if (declaredLength > MAX_BODY_BYTES) {
    const error = new Error('Request body is too large');
    error.statusCode = 413;
    throw error;
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) {
      const error = new Error('Request body is too large');
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Expected an object');
    return body;
  } catch (_) {
    const error = new Error('Invalid JSON body');
    error.statusCode = 400;
    throw error;
  }
}
function lastKnownJson() {
  return JSON.stringify([...lastKnown.values()].map(({ reporterId, ...rest }) => rest));
}
function scheduleSave() {
  if (!DATA_FILE) return;
  dirty = true;
  if (saveTimer || saving) return;
  saveTimer = setTimeout(persistLastKnown, 5000);
}
async function persistLastKnown() {
  saveTimer = null;
  if (!dirty || !DATA_FILE) return;
  dirty = false;
  saving = true;
  const tmp = `${DATA_FILE}.tmp`;
  try {
    await fs.promises.mkdir(path.dirname(DATA_FILE), { recursive: true });
    await fs.promises.writeFile(tmp, lastKnownJson(), { mode: 0o600 });
    await fs.promises.rename(tmp, DATA_FILE);
  } catch (error) {
    dirty = true;
    console.warn(`Could not save ${DATA_FILE}: ${error.message}`);
  } finally {
    saving = false;
    if (dirty && !saveTimer) saveTimer = setTimeout(persistLastKnown, 5000);
  }
}
function flushLastKnownSync() {
  if (!DATA_FILE || !dirty) return;
  const tmp = `${DATA_FILE}.tmp`;
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(tmp, lastKnownJson(), { mode: 0o600 });
    fs.renameSync(tmp, DATA_FILE);
    dirty = false;
  } catch (error) {
    console.warn(`Could not save ${DATA_FILE}: ${error.message}`);
  }
}
function saveLastKnownNow() {
  dirty = true;
  flushLastKnownSync();
}
function saveUsers() {
  if (!AUTH_FILE) {
    console.warn('AUTH_FILE is not configured; registered users will not survive a restart. Configure a persistent /data directory.');
    return;
  }
  const tmp = `${AUTH_FILE}.tmp`;
  try {
    fs.mkdirSync(path.dirname(AUTH_FILE), {
      recursive: true
    });
    fs.writeFileSync(tmp, JSON.stringify({
      version: 1,
      users: [...users.values()]
    }), {
      mode: 0o600
    });
    fs.renameSync(tmp, AUTH_FILE);
  } catch (error) {
    console.error(`Could not save authentication database ${AUTH_FILE}: ${error.message}`);
    throw new Error('Could not save account data. Check that the persistent data directory is writable.');
  }
}
function loadUsers() {
  if (!AUTH_FILE) {
    console.warn('AUTH_FILE is not configured; account database will be memory-only.');
    return;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
    for (const item of Array.isArray(parsed.users) ? parsed.users : []) {
      if (!item || typeof item.id !== 'string' || typeof item.username !== 'string' ||
          typeof item.passwordSalt !== 'string' || typeof item.passwordHash !== 'string') continue;
      if (usersByName.has(item.username)) continue;
      users.set(item.id, item);
      usersByName.set(item.username, item);
    }
    console.log(`Loaded ${users.size} account(s) from ${AUTH_FILE}`);
  } catch (error) {
    if (error.code !== 'ENOENT') console.error(`Could not load account database: ${error.message}`);
  }
}
function saveTrackers() {
  if (!TRACKERS_FILE) {
    console.warn('TRACKERS_FILE is not configured; tracker registry will be memory-only.');
    return;
  }
  const tmp = `${TRACKERS_FILE}.tmp`;
  try {
    fs.mkdirSync(path.dirname(TRACKERS_FILE), {
      recursive: true
    });
    fs.writeFileSync(tmp, JSON.stringify({
      version: 2,
      trackers: [...ownedTrackers.values()]
    }), {
      mode: 0o600
    });
    fs.renameSync(tmp, TRACKERS_FILE);
  } catch (error) {
    console.error(`Could not save tracker registry ${TRACKERS_FILE}: ${error.message}`);
    throw new Error('Could not save tracker registry. Check that the persistent data directory is writable.');
  }
}
function loadTrackers() {
  if (!TRACKERS_FILE) {
    console.warn('TRACKERS_FILE is not configured; tracker registry will be memory-only.');
    return;
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(TRACKERS_FILE, 'utf8'));
    for (const item of Array.isArray(parsed.trackers) ? parsed.trackers : []) {
      if (!item || typeof item.trackerId !== 'string' || typeof item.userId !== 'string' ||
        typeof item.deviceId !== 'string' || typeof item.name !== 'string') continue;
      ownedTrackers.set(item.trackerId, item);
    }
    console.log(`Loaded ${ownedTrackers.size} registered tracker(s) from ${TRACKERS_FILE}`);
  } catch (error) {
    if (error.code !== 'ENOENT') console.error(`Could not load tracker registry: ${error.message}`);
  }
}
function publicTracker(record) {
  const { userId, ...safe } = record;
  return safe;
}
function trackersForUser(userId) {
  return [...ownedTrackers.values()]
    .filter(item => item.userId === userId)
    .sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0))
    .map(publicTracker);
}
function findTrackerForUser(userId, deviceIdOrName) {
  const value = clampText(deviceIdOrName, MAX_DEVICE_ID_LENGTH);
  if (!value) return null;
  const exact = ownedTrackers.get(scopedTrackerId(userId, value));
  if (exact) return exact;
  for (const item of ownedTrackers.values()) if (item.userId === userId && item.name === value) return item;
  return null;
}
function ensureLegacyTrackerRecords() {
  let registryChanged = false;
  let positionsChanged = false;
  for (const [oldKey, state] of [...lastKnown.entries()]) {
    if (!state.userId || ownedTrackers.has(oldKey)) continue;
    if (state.deviceId) {
      lastKnown.delete(oldKey);
      positionsChanged = true;
      continue;
    }
    const prefix = `${state.userId}:`;
    const legacyName = oldKey.startsWith(prefix) ? oldKey.slice(prefix.length) : (state.trackerName || oldKey);
    const deviceId = `legacy-${legacyName.replace(/[^a-zA-Z0-9._-]/g, '-').slice(0, 80)}`;
    const newKey = scopedTrackerId(state.userId, deviceId);
    const record = {
      trackerId: newKey,
      deviceId,
      userId: state.userId,
      name: clampText(state.trackerName || legacyName, 48) || 'OpenTag tracker',
      createdAt: state.updatedAt || now(),
      updatedAt: now(),
      legacy: true,
    };
    ownedTrackers.set(newKey, record);
    lastKnown.delete(oldKey);
    lastKnown.set(newKey, { ...state, trackerId: newKey, deviceId, trackerName: record.name, userId: state.userId, live: false });
    registryChanged = positionsChanged = true;
  }
  if (registryChanged) {
    saveTrackers();
    console.log('Migrated previously saved tracker positions into the v2 tracker registry.');
  }
  if (positionsChanged) saveLastKnownNow();
}
function migrateLegacyNamedTracker(userId, name, deviceId) {
  const normalizedName = name.toLowerCase();
  let legacy = null;
  for (const item of ownedTrackers.values()) {
    if (item.userId !== userId || !item.legacy) continue;
    const legacyName = item.name.toLowerCase();
    if (legacyName === normalizedName || normalizedName.startsWith(`${legacyName}-`)) { legacy = item; break; }
  }
  if (!legacy) return null;
  const oldKey = legacy.trackerId;
  const newKey = scopedTrackerId(userId, deviceId);
  const updated = { ...legacy, trackerId: newKey, deviceId, legacy: false, updatedAt: now() };
  ownedTrackers.delete(oldKey);
  ownedTrackers.set(newKey, updated);
  try { saveTrackers(); }
  catch (error) { ownedTrackers.delete(newKey); ownedTrackers.set(oldKey, legacy); throw error; }
  const previous = lastKnown.get(oldKey);
  if (previous) {
    lastKnown.delete(oldKey);
    lastKnown.set(newKey, { ...previous, trackerId: newKey, deviceId, trackerName: updated.name });
  }
  const live = trackerStates.get(oldKey);
  if (live) {
    trackerStates.delete(oldKey);
    trackerStates.set(newKey, { ...live, trackerId: newKey, deviceId, trackerName: updated.name });
  }
  if (previous) saveLastKnownNow();
  return updated;
}
function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}
function registerTracker(user, body) {
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId.trim() : '';
  const name = clampText(body.name || 'OpenTag tracker', 48);
  if (!new RegExp(`^[a-zA-Z0-9._:-]{6,${MAX_DEVICE_ID_LENGTH}}$`).test(deviceId)) {
    throw httpError(400, 'Invalid tracker hardware ID. Update the tracker firmware and try again.');
  }
  if (!name) throw httpError(400, 'Tracker name is required.');
  for (const item of ownedTrackers.values()) {
    if (item.deviceId === deviceId && item.userId !== user.id) {
      throw httpError(409, 'This tracker is already registered to another account.');
    }
  }
  const key = scopedTrackerId(user.id, deviceId);
  const existing = ownedTrackers.get(key);
  if (existing) return publicTracker(existing);
  const migrated = migrateLegacyNamedTracker(user.id, name, deviceId);
  if (migrated) return publicTracker(migrated);
  let count = 0;
  for (const item of ownedTrackers.values()) if (item.userId === user.id) count++;
  if (count >= MAX_TRACKERS_PER_USER) throw httpError(409, `This account can register up to ${MAX_TRACKERS_PER_USER} trackers.`);
  const record = { trackerId: key, deviceId, userId: user.id, name, createdAt: now(), updatedAt: now(), legacy: false };
  ownedTrackers.set(key, record);
  try { saveTrackers(); }
  catch (error) { ownedTrackers.delete(key); throw error; }
  return publicTracker(record);
}
function renameTracker(user, body) {
  const trackerId = clampText(body.trackerId, 160);
  const name = clampText(body.name, 48);
  const record = ownedTrackers.get(trackerId);
  if (!record || record.userId !== user.id) throw httpError(404, 'Tracker not found in this account.');
  if (!name) throw httpError(400, 'Tracker name is required.');
  const previousName = record.name;
  const previousUpdatedAt = record.updatedAt;
  record.name = name;
  record.updatedAt = now();
  try { saveTrackers(); }
  catch (error) { record.name = previousName; record.updatedAt = previousUpdatedAt; throw error; }
  for (const stateMap of [trackerStates, lastKnown]) {
    const state = stateMap.get(trackerId);
    if (state) state.trackerName = name;
  }
  scheduleSave();
  broadcastToUser(user.id, { type: 'trackerRenamed', trackerId, name });
  return publicTracker(record);
}
function deleteTracker(user, body) {
  const trackerId = clampText(body.trackerId, 160);
  const record = ownedTrackers.get(trackerId);
  if (!record || record.userId !== user.id) throw httpError(404, 'Tracker not found in this account.');
  ownedTrackers.delete(trackerId);
  try { saveTrackers(); }
  catch (error) { ownedTrackers.set(trackerId, record); throw error; }
  trackerStates.delete(trackerId);
  lastKnown.delete(trackerId);
  saveLastKnownNow();
  broadcastToUser(user.id, { type: 'trackerDeleted', trackerId });
  return true;
}

function sanitizeLocation(location) {
  if (!location || !validLatitude(location.lat) || !validLongitude(location.lng)) return null;
  const accuracy = finiteNumber(location.accuracy);
  return {
    lat: Number(location.lat),
    lng: Number(location.lng),
    accuracy: accuracy !== null && accuracy >= 0 && accuracy <= 100000 ? accuracy : null,
  };
}
function scopedTrackerId(userId, rawTrackerId) {
  const clean = clampText(rawTrackerId, 100);
  return clean ? `${userId}:${clean}` : '';
}
function loadLastKnown() {
  if (!DATA_FILE) return;
  try {
    const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    for (const item of Array.isArray(data) ? data : []) {
      const location = sanitizeLocation(item && item.location);
      const trackerId = clampText(item && item.trackerId, 140);
      if (!trackerId || !location) continue;
      const savedState = {
        ...item
      };
      const legacyMode = savedState.mode;
      savedState.trackerMode = ['normal', 'lost'].includes(savedState.trackerMode)
        ? savedState.trackerMode
        : (['normal', 'lost'].includes(legacyMode) ? legacyMode : null);
      delete savedState.mode;
      delete savedState.reporterId;
      lastKnown.set(trackerId, {
        ...savedState,
        trackerId,
        location,
        live: false
      });
    }
    console.log(`Loaded ${lastKnown.size} last known position(s) from ${DATA_FILE}`);
  } catch (error) {
    if (error.code !== 'ENOENT') console.warn(`Could not load ${DATA_FILE}: ${error.message}`);
  }
}
function migrateLegacyPositionsToFirstUser(userId) {
  let changed = false;
  for (const [oldId, item] of [...lastKnown.entries()]) {
    if (item.userId) continue;
    const rawId = clampText(item.trackerName || item.trackerId || oldId, 100);
    const deviceId = `legacy-${rawId.replace(/[^a-zA-Z0-9._-]/g, '-').slice(0, 80)}`;
    const newId = scopedTrackerId(userId, deviceId);
    lastKnown.delete(oldId);
    lastKnown.set(newId, {
      ...item,
      trackerId: newId,
      deviceId,
      trackerName: item.trackerName || rawId,
      userId,
      live: false
    });
    ownedTrackers.set(newId, {
      trackerId: newId,
      deviceId,
      userId,
      name: clampText(item.trackerName || rawId, 48),
      createdAt: item.updatedAt || now(),
      updatedAt: now(),
      legacy: true
    });
    changed = true;
  }
  if (changed) {
    console.log(`Migrated legacy unowned position(s) to the first account (${userId}).`);
    saveTrackers();
    saveLastKnownNow();
  }
}
function lastKnownSnapshot(userId) {
  return [...lastKnown.values()]
    .filter(state => state.userId === userId)
    .map(publicState);
}
function publicState(state) {
  const { userId, reporterId, ...safe } = state;
  return safe;
}
function removeStaleTrackers() {
  const cutoff = now() - TRACKER_TTL_MS;
  for (const [trackerId, state] of trackerStates) {
    if (state.updatedAt >= cutoff) continue;
    trackerStates.delete(trackerId);
    broadcastTrackerRemoved(state.userId, trackerId, 'stale');
  }
}
function stateSnapshot(userId) {
  removeStaleTrackers();
  const states = [];
  for (const state of trackerStates.values()) {
    if (state.userId === userId) states.push(publicState(state));
  }
  return states;
}
function broadcastTrackerRemoved(userId, trackerId, reason) {
  const known = lastKnown.get(trackerId);
  broadcastToUser(userId, {
    type: 'trackerRemoved', trackerId,
    lastKnown: known ? publicState(known) : null,
    reason, at: now(),
  });
}
function sanitizeReport(message, client) {
  const rawDeviceId = clampText(message.deviceId || message.trackerId, MAX_DEVICE_ID_LENGTH);
  if (!rawDeviceId) throw new Error('deviceId is required');
  const record = findTrackerForUser(client.userId, rawDeviceId);
  if (!record) throw new Error('This tracker is not registered to your account. Add it from the tracker menu first.');
  const rssi = finiteNumber(message.rssi);
  const txPower = finiteNumber(message.txPower);
  const distanceM = finiteNumber(message.distanceM);
  const location = sanitizeLocation(message.location);
  const trackerMode = ['normal', 'lost'].includes(message.trackerMode) ? message.trackerMode : null;
  const blePacketAt = finiteNumber(message.lastBlePacketAt);
  return {
    trackerId: record.trackerId,
    deviceId: record.deviceId,
    trackerName: record.name,
    location,
    rssi: rssi !== null && rssi >= -150 && rssi <= 0 ? rssi : null,
    txPower: txPower !== null && txPower >= -100 && txPower <= 30 ? txPower : null,
    distanceM: distanceM !== null && distanceM >= 0 && distanceM <= 100000 ? distanceM : null,
    trackerMode,
    live: true,
    userId: client.userId,
    reporterId: client.clientId,
    updatedAt: now(),
    lastBlePacketAt: blePacketAt !== null && blePacketAt > 0 && blePacketAt <= now() ? blePacketAt : now(),
  };
}
function sendFrame(socket, opcode, payloadBuffer = Buffer.alloc(0)) {
  if (socket.destroyed) return;
  const payload = Buffer.isBuffer(payloadBuffer) ? payloadBuffer : Buffer.from(payloadBuffer);
  let header;
  if (payload.length < 126) {
    header = Buffer.from([0x80 | opcode, payload.length]);
  } else if (payload.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  if (socket.writableLength > MAX_WS_BACKLOG_BYTES) { socket.destroy(); return; }
  socket.write(Buffer.concat([header, payload]));
}
function sendJson(client, message) {
  sendFrame(client.socket, 0x1, Buffer.from(JSON.stringify(message)));
}
function broadcastToUser(userId, message) {
  const set = clientsByUser.get(userId);
  if (!set) return;
  const frame = Buffer.from(JSON.stringify(message));
  for (const client of [...set]) {
    try { sendFrame(client.socket, 0x1, frame); } catch (_) { destroyClient(client); }
  }
}
function removeTrackerForClient(client, rawTrackerId) {
  const record = findTrackerForUser(client.userId, rawTrackerId);
  if (!record) return false;
  const trackerId = record.trackerId;
  const state = trackerStates.get(trackerId);
  if (!state || state.userId !== client.userId || state.reporterId !== client.clientId) return false;
  trackerStates.delete(trackerId);
  client.trackerIds.delete(trackerId);
  broadcastTrackerRemoved(client.userId, trackerId, 'reporter_disconnected');
  return true;
}
function handleMessage(client, message) {
  if (!message || typeof message !== 'object') return;
  if (message.type === 'hello') {
    sendJson(client, { type: 'helloAck', clientId: client.clientId, appVersion: APP_VERSION, serverTime: now() });
    sendJson(client, {
      type: 'snapshot',
      trackers: stateSnapshot(client.userId),
      lastKnown: lastKnownSnapshot(client.userId),
      ownedTrackers: trackersForUser(client.userId),
      serverTime: now(),
    });
    return;
  }
  if (message.type === 'trackerReport') {
    try {
      const state = sanitizeReport(message, client);
      const previous = trackerStates.get(state.trackerId) || lastKnown.get(state.trackerId);
      if (!state.trackerMode && previous && previous.trackerMode) state.trackerMode = previous.trackerMode;
      trackerStates.set(state.trackerId, state);
      client.trackerIds.add(state.trackerId);
      if (state.location) {
        lastKnown.set(state.trackerId, { ...state, live: false });
        scheduleSave();
      }
      broadcastToUser(client.userId, { type: 'trackerState', state: publicState(state) });
    } catch (error) {
      sendJson(client, { type: 'error', message: error.message });
    }
    return;
  }
  if (message.type === 'trackerStop') {
    const rawTrackerId = clampText(message.deviceId || message.trackerId, MAX_DEVICE_ID_LENGTH);
    if (rawTrackerId) removeTrackerForClient(client, rawTrackerId);
    return;
  }
  sendJson(client, { type: 'error', message: `Unknown message type: ${String(message.type || 'undefined')}` });
}
function closeClient(client, code) {
  if (client.closing) return;
  client.closing = true;
  client.buffer = Buffer.alloc(0);
  sendFrame(client.socket, 0x8, Buffer.from([code >> 8, code & 0xff]));
  client.socket.end();
}
function dispatchTextFrame(client, payload) {
  let message;
  try { message = JSON.parse(payload.toString('utf8')); }
  catch (_) { sendJson(client, { type: 'error', message: 'Invalid JSON message' }); return; }
  try { handleMessage(client, message); }
  catch (error) {
    console.error(`Message handler failed: ${error.stack || error.message}`);
    sendJson(client, { type: 'error', message: 'Internal error while handling the message' });
  }
}
function processWebSocketBuffer(client) {
  while (!client.closing && client.buffer.length >= 2) {
    const first = client.buffer[0];
    const second = client.buffer[1];
    const fin = Boolean(first & 0x80);
    const opcode = first & 0x0f;
    const masked = Boolean(second & 0x80);
    let payloadLength = second & 0x7f;
    let offset = 2;
    if (!masked) return closeClient(client, 1002);
    if (opcode >= 0x8 && (!fin || payloadLength > 125)) return closeClient(client, 1002);
    if (payloadLength === 126) {
      if (client.buffer.length < offset + 2) return;
      payloadLength = client.buffer.readUInt16BE(offset);
      offset += 2;
    } else if (payloadLength === 127) {
      if (client.buffer.length < offset + 8) return;
      const length64 = client.buffer.readBigUInt64BE(offset);
      if (length64 > BigInt(MAX_MESSAGE_BYTES)) return closeClient(client, 1009);
      payloadLength = Number(length64);
      offset += 8;
    }
    if (payloadLength > MAX_MESSAGE_BYTES) return closeClient(client, 1009);
    const frameLength = offset + 4 + payloadLength;
    if (client.buffer.length < frameLength) return;
    const mask = client.buffer.subarray(offset, offset + 4);
    offset += 4;
    const payload = Buffer.from(client.buffer.subarray(offset, offset + payloadLength));
    client.buffer = client.buffer.subarray(frameLength);
    client.alive = true;
    for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    if (!fin && opcode < 8) return closeClient(client, 1003);
    if (opcode === 0x1) {
      dispatchTextFrame(client, payload);
    } else if (opcode === 0x8) {
      client.closing = true;
      client.buffer = Buffer.alloc(0);
      sendFrame(client.socket, 0x8, payload);
      client.socket.end();
      return;
    } else if (opcode === 0x9) {
      sendFrame(client.socket, 0xA, payload);
    } else if (opcode !== 0xA) {
      return closeClient(client, 1003);
    }
  }
}
function destroyClient(client) {
  if (client.destroyed) return;
  client.destroyed = true;
  clients.delete(client);
  const set = clientsByUser.get(client.userId);
  if (set) { set.delete(client); if (!set.size) clientsByUser.delete(client.userId); }
  for (const trackerId of client.trackerIds) {
    const state = trackerStates.get(trackerId);
    if (state && state.reporterId === client.clientId && state.userId === client.userId) {
      trackerStates.delete(trackerId);
      broadcastTrackerRemoved(client.userId, trackerId, 'reporter_disconnected');
    }
  }
  client.trackerIds.clear();
  try { client.socket.destroy(); } catch (_) {}
}
function rejectUpgrade(socket, statusLine) {
  try { socket.write(`HTTP/1.1 ${statusLine}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n`); } catch (_) {}
  socket.destroy();
}
function handleUpgrade(request, socket, head) {
  socket.on('error', () => {});
  let pathname;
  try { pathname = new URL(request.url, 'http://localhost').pathname; }
  catch (_) { return rejectUpgrade(socket, '400 Bad Request'); }
  const expectedWsPath = (WS_PATH || '/ws').replace(/\/+$/, '') || '/ws';
  if (request.method !== 'GET' || (pathname !== expectedWsPath && pathname !== `${expectedWsPath}/`)) {
    return rejectUpgrade(socket, '404 Not Found');
  }
  const user = getSessionUser(request);
  if (!user) return rejectUpgrade(socket, '401 Unauthorized');
  const upgrade = String(request.headers.upgrade || '').toLowerCase();
  const connection = String(request.headers.connection || '').toLowerCase();
  const key = request.headers['sec-websocket-key'];
  const version = String(request.headers['sec-websocket-version'] || '');
  if (upgrade !== 'websocket' || !connection.includes('upgrade') || !key || version !== '13') {
    return rejectUpgrade(socket, '400 Bad Request');
  }
  const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' + `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);
  socket.setNoDelay(true);
  const cookies = parseCookies(request.headers.cookie);
  const client = {
    socket,
    clientId: crypto.randomUUID(),
    sessionKey: hashSession(cookies[SESSION_COOKIE]),
    userId: user.id,
    buffer: Buffer.alloc(0),
    trackerIds: new Set(),
    destroyed: false,
    closing: false,
    alive: true,
  };
  clients.add(client);
  if (!clientsByUser.has(user.id)) clientsByUser.set(user.id, new Set());
  clientsByUser.get(user.id).add(client);
  socket.on('data', chunk => {
    if (client.destroyed || client.closing) return;
    client.buffer = client.buffer.length ? Buffer.concat([client.buffer, chunk]) : chunk;
    processWebSocketBuffer(client);
  });
  socket.on('close', () => destroyClient(client));
  socket.on('end', () => destroyClient(client));
  socket.on('error', () => destroyClient(client));
  if (head && head.length) { client.buffer = Buffer.from(head); processWebSocketBuffer(client); }
}
function readCredentials(body) {
  const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';
  return { username, password };
}
async function registerAccount(request, response) {
  if (!REGISTRATION_ENABLED) return jsonResponse(response, 403, { error: 'Registration is currently disabled.' });
  if (!rateLimitAuth(request, response, 'register')) return;
  const body = await readJsonBody(request);
  const { username, password } = readCredentials(body);
  if (!USERNAME_RE.test(username)) {
    return jsonResponse(response, 400, { error: 'Username must be 3–32 characters and contain only letters, numbers, dot, underscore, or hyphen.' });
  }
  if (password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
    return jsonResponse(response, 400, { error: `Password must be between ${PASSWORD_MIN_LENGTH} and ${PASSWORD_MAX_LENGTH} characters.` });
  }
  if (usersByName.has(username)) return jsonResponse(response, 409, { error: 'That username is already taken.' });
  const salt = crypto.randomBytes(16);
  const hash = await scryptAsync(password, salt, SCRYPT_KEY_LENGTH);
  if (usersByName.has(username)) return jsonResponse(response, 409, { error: 'That username is already taken.' });
  const isFirstUser = users.size === 0;
  const user = {
    id: crypto.randomUUID(),
    username,
    passwordSalt: salt.toString('base64url'),
    passwordHash: Buffer.from(hash).toString('base64url'),
    createdAt: now(),
  };
  users.set(user.id, user);
  usersByName.set(username, user);
  try {
    saveUsers();
  } catch (error) {
    users.delete(user.id);
    usersByName.delete(username);
    throw error;
  }
  if (isFirstUser) migrateLegacyPositionsToFirstUser(user.id);
  const token = createSession(user);
  setSessionCookie(request, response, token);
  jsonResponse(response, 201, { ok: true, user: safeUser(user) });
}
async function loginAccount(request, response) {
  if (!rateLimitAuth(request, response, 'login')) return;
  const body = await readJsonBody(request);
  const { username, password } = readCredentials(body);
  const user = usersByName.get(username);
  let valid = false;
  if (password.length <= PASSWORD_MAX_LENGTH) {
    try {
      const salt = user ? Buffer.from(user.passwordSalt, 'base64url') : DUMMY_SALT;
      const candidate = Buffer.from(await scryptAsync(password, salt, SCRYPT_KEY_LENGTH));
      if (user) {
        const saved = Buffer.from(user.passwordHash, 'base64url');
        valid = candidate.length === saved.length && crypto.timingSafeEqual(candidate, saved);
      }
    } catch (_) { valid = false; }
  }
  if (!valid) return jsonResponse(response, 401, { error: 'Incorrect username or password.' });
  const token = createSession(user);
  setSessionCookie(request, response, token);
  jsonResponse(response, 200, { ok: true, user: safeUser(user) });
}
function logoutAccount(request, response) {
  const cookies = parseCookies(request.headers.cookie);
  const token = cookies[SESSION_COOKIE];
  const sessionKey = token ? hashSession(token) : '';
  if (sessionKey) sessions.delete(sessionKey);
  if (sessionKey) {
    for (const client of [...clients]) {
      if (client.sessionKey === sessionKey) destroyClient(client);
    }
  }
  clearSessionCookie(request, response);
  jsonResponse(response, 200, {
    ok: true
  });
}

async function serveStatic(request, response, pathname) {
  if (!STATIC_DIR || (request.method !== 'GET' && request.method !== 'HEAD')) return false;
  let relative;
  try { relative = decodeURIComponent(pathname); } catch (_) { return false; }
  if (relative.includes('\0')) return false;
  if (relative.endsWith('/')) relative += 'index.html';
  const file = path.resolve(STATIC_DIR, `.${relative}`);
  if (file !== STATIC_DIR && !file.startsWith(STATIC_DIR + path.sep)) return false;
  const type = STATIC_MIME[path.extname(file).toLowerCase()];
  if (!type) return false;
  try {
    const data = await fs.promises.readFile(file);
    response.writeHead(200, { 'Content-Type': type, 'Content-Length': data.length, 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff' });
    response.end(request.method === 'HEAD' ? undefined : data);
    return true;
  } catch (_) { return false; }
}

const server = http.createServer(async (request, response) => {
  let pathname;
  try { pathname = new URL(request.url, 'http://localhost').pathname; }
  catch (_) { return jsonResponse(response, 400, { error: 'Bad request.' }); }
  try {
    if (request.method === 'GET' && pathname === '/api/health') {
      return jsonResponse(response, 200, { ok: true, service: 'opentag-backend', version: APP_VERSION, time: now() });
    }
    if (request.method === 'GET' && pathname === '/api/auth/me') {
      const user = getSessionUser(request);
      return jsonResponse(response, 200, user ? { authenticated: true, user: safeUser(user) } : { authenticated: false });
    }
    if (request.method === 'POST' && pathname === '/api/auth/register') return await registerAccount(request, response);
    if (request.method === 'POST' && pathname === '/api/auth/login') return await loginAccount(request, response);
    if (request.method === 'POST' && pathname === '/api/auth/logout') return logoutAccount(request, response);

    if (pathname.startsWith('/api/trackers')) {
      const user = getSessionUser(request);
      if (!user) return jsonResponse(response, 401, { error: 'Authentication required.' });
      if (request.method === 'GET' && pathname === '/api/trackers') {
        return jsonResponse(response, 200, { trackers: trackersForUser(user.id), serverTime: now() });
      }
      if (request.method === 'POST' && pathname === '/api/trackers/add') {
        return jsonResponse(response, 201, { ok: true, tracker: registerTracker(user, await readJsonBody(request)) });
      }
      if (request.method === 'POST' && pathname === '/api/trackers/rename') {
        return jsonResponse(response, 200, { ok: true, tracker: renameTracker(user, await readJsonBody(request)) });
      }
      if (request.method === 'POST' && pathname === '/api/trackers/remove') {
        deleteTracker(user, await readJsonBody(request));
        return jsonResponse(response, 200, { ok: true });
      }
      return jsonResponse(response, 404, { error: 'Not found' });
    }

    if (request.method === 'GET' && pathname === '/api/state') {
      const user = getSessionUser(request);
      if (!user) return jsonResponse(response, 401, { error: 'Authentication required.' });
      const body = {
        trackers: stateSnapshot(user.id),
        lastKnown: lastKnownSnapshot(user.id),
        ownedTrackers: trackersForUser(user.id),
        serverTime: now(),
      };
      return jsonResponse(response, 200, body, { 'Cache-Control': 'no-store, no-cache, must-revalidate', Pragma: 'no-cache', Expires: '0' });
    }
    if (!pathname.startsWith('/api/') && await serveStatic(request, response, pathname)) return;
    return jsonResponse(response, 404, { error: 'Not found' });
  } catch (error) {
    const statusCode = Number.isInteger(error.statusCode) ? error.statusCode : 500;
    if (statusCode >= 500) console.error(`Request failed (${request.method} ${pathname}): ${error.message}`);
    if (response.headersSent) return response.destroy();
    return jsonResponse(response, statusCode, { error: statusCode >= 500 ? 'Internal server error.' : error.message });
  }
});
server.on('upgrade', handleUpgrade);

setInterval(removeStaleTrackers, 5000).unref();

setInterval(() => {
  const t = now();
  for (const [key, session] of sessions) if (session.expiresAt <= t) sessions.delete(key);
  for (const [key, timestamps] of authRateLimits) {
    const recent = timestamps.filter(time => time > t - RATE_WINDOW_MS);
    if (recent.length) authRateLimits.set(key, recent); else authRateLimits.delete(key);
  }
  for (const client of [...clients]) {
    if (!sessions.has(client.sessionKey) || !client.alive) { destroyClient(client); continue; }
    client.alive = false;
    try { sendFrame(client.socket, 0x9); } catch (_) { destroyClient(client); }
  }
}, PING_INTERVAL_MS).unref();

let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`${signal} received, saving data and shutting down.`);
  flushLastKnownSync();
  for (const client of [...clients]) { try { closeClient(client, 1001); } catch (_) {} }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => console.error('Unhandled rejection:', reason));

loadUsers();
loadTrackers();
loadLastKnown();
ensureLegacyTrackerRecords();

server.listen(PORT, HOST, () => {
  console.log(`OpenTag v${APP_VERSION} multi-tracker backend listening on http://${HOST}:${PORT}`);
  console.log(`WebSocket endpoint: ${WS_PATH}`);
  console.log(`Tracker state TTL: ${TRACKER_TTL_MS} ms`);
  console.log(`Account registration: ${REGISTRATION_ENABLED ? 'enabled' : 'disabled'}`);
  console.log(`Minimum password length: ${PASSWORD_MIN_LENGTH}`);
  if (STATIC_DIR) console.log(`Serving web app from ${STATIC_DIR}`);
  console.log(`Authentication database: ${AUTH_FILE || 'none (memory only)'}`);
  console.log(`Last known positions file: ${DATA_FILE || 'none (memory only)'}`);
  console.log(`Tracker registry file: ${TRACKERS_FILE || 'none (memory only)'}`);
});
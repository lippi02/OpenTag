'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);
const env = process.env;
const now = Date.now;

function intSetting(name, fallback, min, max) {
    const raw = env[name];
    if (raw === undefined || raw === '') return fallback;
    const value = Number(raw);
    if (Number.isSafeInteger(value) && value >= min && value <= max) return value;
    console.warn(`Invalid ${name} value; using ${fallback}.`);
    return fallback;
}

function wsPathSetting(value = '/ws') {
    const candidate = String(value).trim().replace(/\/{2,}/g, '/').replace(/\/+$/, '');
    if (candidate.startsWith('/') && !/[?#\\\0]/.test(candidate) && !candidate.split('/').some(part => part === '.' || part === '..')) return candidate;
    console.warn('Invalid WS_PATH value; using /ws.');
    return '/ws';
}

const DAY_MS = 24 * 60 * 60 * 1000;
const HOST = String(env.HOST || '').trim() || '0.0.0.0';
const PORT = intSetting('PORT', 3000, 0, 65535);
const WS_PATH = wsPathSetting(env.WS_PATH);
const TRACKER_TTL_MS = intSetting('TRACKER_TTL_MS', 15000, 1000, DAY_MS);
const DEVICE_TTL_MS = intSetting('DEVICE_TTL_MS', 90000, 1000, DAY_MS);
const PING_INTERVAL_MS = intSetting('PING_INTERVAL_MS', 25000, 1000, 600000);
const PASSWORD_MIN_LENGTH = intSetting('PASSWORD_MIN_LENGTH', 10, 0, 128);
const TRUSTED_PROXY_HOPS = intSetting('TRUSTED_PROXY_HOPS', 0, 0, 10);
const TRUSTED_PROXIES = trustedProxySetting(env.TRUSTED_PROXY_IPS);
const REGISTRATION_ENABLED = String(env.REGISTRATION_ENABLED || 'true').toLowerCase() !== 'false';
const STATIC_DIR = env.STATIC_DIR ? path.resolve(env.STATIC_DIR) : '';
const DATA_DIR = env.DATA_DIR || [env.AUTH_FILE, env.TRACKERS_FILE, env.DEVICES_FILE, env.DATA_FILE].filter(Boolean).map(file => path.dirname(file))[0] || '';
const dataFile = (name, file) => env[name] || (DATA_DIR ? path.join(DATA_DIR, file) : '');

const PASSWORD_MAX_LENGTH = 128;
const USERNAME_RE = /^[a-zA-Z0-9._-]{3,32}$/;
const HARDWARE_ID_RE = /^[a-zA-Z0-9._:-]{6,100}$/;
const TEMPORARY_ID_RE = /^(browser|legacy)-/;
const SESSION_COOKIE = 'opentag_session';
const SESSION_TTL_MS = 7 * DAY_MS;
const SUGGESTION_TTL_MS = 7 * DAY_MS;
const RATE_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT = 12;
const SAVE_DELAY_MS = 5000;
const SWEEP_INTERVAL_MS = 5000;
const SCRYPT_KEY_LENGTH = 64;
const NAME_MAX_LENGTH = 48;
const MAX_BODY_BYTES = 8 * 1024;
const MAX_MESSAGE_BYTES = 32 * 1024;
const MAX_WS_BUFFER_BYTES = MAX_MESSAGE_BYTES * 4 + 64;
const MAX_WS_BACKLOG_BYTES = 1024 * 1024;
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const WS_CLOSE_CODES = new Set([1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014]);
const DEVICE_TYPES = new Set(['phone', 'tablet', 'laptop', 'computer', 'other']);
const TRACKER_MODES = new Set(['normal', 'lost']);
const SIGNAL_RANGES = { rssi: [-150, 0], txPower: [-100, 30], distanceM: [0, 100000] };
const SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
};
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data: blob: https://tile.openstreetmap.org; connect-src 'self' ws: wss:; font-src 'self' data: https://unpkg.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
const STATIC_MIME = {
    '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
};
const DUMMY_SALT = crypto.randomBytes(16);
const utf8 = new TextDecoder('utf-8', { fatal: true });

const users = new Map();
const usersByName = new Map();
const sessions = new Map();
const clients = new Set();
const clientsByUser = new Map();
const authAttempts = new Map();
let shuttingDown = false;

function httpError(statusCode, message, headers) {
    return Object.assign(new Error(message), { statusCode, expose: true, headers });
}

function num(value) {
    if (typeof value === 'string' ? !value.trim() : typeof value !== 'number') return null;
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
}

function inRange(value, min, max) {
    const n = num(value);
    return n !== null && n >= min && n <= max ? n : null;
}

function timestamp(value) {
    const n = num(value);
    return n !== null && n > 0 ? n : null;
}

function text(value, maxLength) {
    return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function validUserId(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= 128;
}

function normalizeName(value) {
    return text(value, NAME_MAX_LENGTH).normalize('NFKC').replace(/\s+/g, ' ').toLowerCase();
}

function readName(value, fallback = '') {
    const name = (text(value, NAME_MAX_LENGTH) || fallback).replace(/\s+/g, ' ');
    if (!name) throw httpError(400, 'Name is required.');
    return name;
}

function sanitizeLocation(location) {
    const lat = inRange(location?.lat, -90, 90);
    const lng = inRange(location?.lng, -180, 180);
    return lat === null || lng === null ? null : { lat, lng, accuracy: inRange(location.accuracy, 0, 100000) };
}

function trackerFields(source, previous = {}) {
    const fields = {
        trackerMode: TRACKER_MODES.has(source.trackerMode) ? source.trackerMode : previous.trackerMode ?? null,
        lastBlePacketAt: timestamp(source.lastBlePacketAt),
    };
    for (const [name, [min, max]] of Object.entries(SIGNAL_RANGES)) fields[name] = inRange(source[name], min, max);
    fields.txPower ??= previous.txPower ?? null;
    return fields;
}

function deviceFields(source) {
    return { type: DEVICE_TYPES.has(source.type) ? source.type : 'other', platform: text(source.platform, 16) };
}

function platformFromUserAgent(userAgent) {
    const ua = String(userAgent || '');
    if (/iPhone|iPad|iPod/i.test(ua)) return 'iOS';
    if (/Android/i.test(ua)) return 'Android';
    if (/CrOS/i.test(ua)) return 'ChromeOS';
    if (/Windows/i.test(ua)) return 'Windows';
    if (/Macintosh|Mac OS X/i.test(ua)) return 'macOS';
    if (/Linux/i.test(ua)) return 'Linux';
    return '';
}

function forwardedValues(header) {
    return String(header || '').split(',').map(part => part.trim()).filter(Boolean);
}

function normalizedIp(value) {
    const ip = String(value || '').trim().toLowerCase();
    return ip.startsWith('::ffff:') && net.isIPv4(ip.slice(7)) ? ip.slice(7) : ip;
}

// TRUSTED_PROXY_IPS: comma-separated IP addresses and/or CIDR ranges, e.g. "172.16.0.0/12,192.168.1.101".
function trustedProxySetting(raw) {
    const list = new net.BlockList();
    let count = 0;
    for (const entry of String(raw || '').split(',').map(value => value.trim()).filter(Boolean)) {
        const match = /^([^/]+)(?:\/(\d{1,3}))?$/.exec(entry);
        const ip = match ? normalizedIp(match[1]) : '';
        const family = net.isIP(ip);
        const prefix = match && match[2] !== undefined ? Number(match[2]) : null;
        if (!family || (prefix !== null && prefix > (family === 4 ? 32 : 128))) {
            console.warn(`Ignoring invalid TRUSTED_PROXY_IPS entry: ${entry}`);
            continue;
        }
        const type = family === 4 ? 'ipv4' : 'ipv6';
        if (prefix === null) list.addAddress(ip, type);
        else list.addSubnet(ip, prefix, type);
        count += 1;
    }
    return { list, count };
}

const untrustedProxyWarnings = new Set();

function isTrustedProxy(request) {
    if (TRUSTED_PROXY_HOPS < 1 || !TRUSTED_PROXIES.count) return false;
    const remote = normalizedIp(request.socket.remoteAddress);
    const family = net.isIP(remote);
    return Boolean(family) && TRUSTED_PROXIES.list.check(remote, family === 4 ? 'ipv4' : 'ipv6');
}

function warnUntrustedProxy(request) {
    if (TRUSTED_PROXY_HOPS < 1 || !request.headers['x-forwarded-for']) return;
    const remote = normalizedIp(request.socket.remoteAddress);
    if (untrustedProxyWarnings.has(remote) || untrustedProxyWarnings.size >= 20) return;
    untrustedProxyWarnings.add(remote);
    console.warn(`Ignoring X-Forwarded-* headers from untrusted address ${remote}. If this is your reverse proxy, add it to TRUSTED_PROXY_IPS.`);
}

function clientIp(request) {
    const remote = normalizedIp(request.socket.remoteAddress) || 'unknown';
    if (!isTrustedProxy(request)) {
        warnUntrustedProxy(request);
        return remote;
    }
    const hops = forwardedValues(request.headers['x-forwarded-for']);
    const candidate = hops.length >= TRUSTED_PROXY_HOPS ? normalizedIp(hops[hops.length - TRUSTED_PROXY_HOPS]) : '';
    return net.isIP(candidate) ? candidate : remote;
}

function requestInfo(request) {
    return { ip: clientIp(request), platform: platformFromUserAgent(request.headers['user-agent']) };
}

class JsonStore {
    constructor(file, label, version, key, serialize) {
        Object.assign(this, { file, label, version, key, serialize, dirty: false, timer: null });
    }

    load(addItem) {
        if (!this.file) {
            console.warn(`No file configured for the ${this.label} registry; it will be memory-only.`);
            return;
        }
        let parsed;
        try {
            parsed = JSON.parse(fs.readFileSync(this.file, 'utf8'));
        } catch (error) {
            if (error.code === 'ENOENT') return;
            throw new Error(`Could not load ${this.file}; startup stopped to protect existing data: ${error.message}`);
        }
        const items = parsed?.[this.key];
        if (!Array.isArray(items)) throw new Error(`Invalid format in ${this.file}; startup stopped to protect existing data.`);
        items.forEach((item, index) => {
            if (!item || typeof item !== 'object' || !addItem(item)) {
                throw new Error(`Invalid or duplicate ${this.label} record ${index + 1} in ${this.file}; startup stopped to protect existing data.`);
            }
        });
        console.log(`Loaded ${items.length} ${this.label} record(s) from ${this.file}`);
    }

    save() {
        if (!this.file) return;
        const tmp = `${this.file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
        try {
            fs.mkdirSync(path.dirname(this.file), { recursive: true });
            fs.writeFileSync(tmp, JSON.stringify({ version: this.version, [this.key]: this.serialize() }), { mode: 0o600, flag: 'wx' });
            fs.renameSync(tmp, this.file);
            this.cancel();
            this.dirty = false;
        } catch (error) {
            try { fs.rmSync(tmp, { force: true }); } catch (_) { }
            console.error(`Could not save ${this.file}: ${error.message}`);
            throw httpError(503, `Could not save ${this.label} data. Check that the persistent data directory is writable.`);
        }
    }

    commit(undo) {
        try {
            this.save();
        } catch (error) {
            undo();
            throw error;
        }
    }

    schedule() {
        if (!this.file) return;
        this.dirty = true;
        if (this.timer || shuttingDown) return;
        this.timer = setTimeout(() => {
            this.timer = null;
            if (!this.dirty || shuttingDown) return;
            try { this.save(); } catch (_) { this.schedule(); }
        }, SAVE_DELAY_MS);
        this.timer.unref();
    }

    cancel() {
        clearTimeout(this.timer);
        this.timer = null;
    }

    flush() {
        this.cancel();
        if (!this.file || !this.dirty) return true;
        try {
            this.save();
            return true;
        } catch (_) {
            return false;
        }
    }
}

class Registry {
    constructor(kind, { title, file, version, max, ttlMs, uniqueNames = false, fields, onReport }) {
        Object.assign(this, { kind, title, max, ttlMs, uniqueNames, fields, onReport });
        this.records = new Map();
        this.presence = new Map();
        this.seen = new Map();
        this.store = new JsonStore(file, kind, version, `${kind}s`, () => [...this.records.values()].map(({ id, ...rest }) => ({ deviceId: id, ...rest })));
    }

    key(userId, id) {
        return `${userId}:${id}`;
    }

    keyOf(record) {
        return this.key(record.userId, record.id);
    }

    get(userId, id) {
        return typeof id === 'string' && id ? this.records.get(this.key(userId, id)) || null : null;
    }

    require(user, id) {
        const record = this.get(user.id, id);
        if (!record) throw httpError(404, `${this.title} not found in this account.`);
        return record;
    }

    forUser(userId) {
        return [...this.records.values()].filter(record => record.userId === userId);
    }

    owner(id) {
        for (const record of this.records.values()) if (record.id === id) return record.userId;
        return null;
    }

    add(record) {
        this.records.set(this.keyOf(record), record);
    }

    delete(record) {
        this.records.delete(this.keyOf(record));
    }

    load() {
        this.store.load(item => {
            const id = text(item.deviceId, 100) || (this.uniqueNames ? normalizeName(item.name) : '');
            if (!id || !validUserId(item.userId) || this.get(item.userId, id)) return false;
            const created = timestamp(item.createdAt) || now();
            this.add({
                id,
                userId: item.userId,
                name: text(item.name, NAME_MAX_LENGTH) || this.title,
                createdAt: created,
                updatedAt: timestamp(item.updatedAt) || created,
                lastSeenAt: timestamp(item.lastSeenAt),
                lastLocation: sanitizeLocation(item.lastLocation),
                ...this.fields(item),
            });
            return true;
        });
    }

    isOnline(record) {
        const reporters = this.presence.get(this.keyOf(record));
        if (!reporters) return false;
        const cutoff = now() - this.ttlMs;
        for (const at of reporters.values()) if (at >= cutoff) return true;
        return false;
    }

    view(record) {
        const { userId, lastLocation, ...rest } = record;
        return { kind: this.kind, ...rest, location: lastLocation, online: this.isOnline(record) };
    }

    views(userId) {
        return this.forUser(userId).sort((a, b) => a.createdAt - b.createdAt).map(record => this.view(record));
    }

    publish(record) {
        broadcast(record.userId, { type: 'upsert', item: this.view(record) });
    }

    assertNameFree(userId, name, except = null) {
        if (!this.uniqueNames) return;
        const wanted = normalizeName(name);
        if (this.forUser(userId).some(record => record !== except && normalizeName(record.name) === wanted)) {
            throw httpError(409, `Another ${this.kind} in this account already uses that name. If this is that ${this.kind}, choose it from the list instead.`);
        }
    }

    create(user, id, fields) {
        if (this.forUser(user.id).length >= this.max) throw httpError(409, `This account can register up to ${this.max} ${this.kind}s.`);
        this.assertNameFree(user.id, fields.name);
        const created = now();
        const record = { id, userId: user.id, createdAt: created, updatedAt: created, lastSeenAt: null, lastLocation: null, ...fields };
        this.add(record);
        this.store.commit(() => this.delete(record));
        this.publish(record);
        return this.view(record);
    }

    rename(user, body) {
        const record = this.require(user, body.id);
        const name = readName(body.name);
        this.assertNameFree(user.id, name, record);
        const previous = { name: record.name, updatedAt: record.updatedAt };
        Object.assign(record, { name, updatedAt: now() });
        this.store.commit(() => Object.assign(record, previous));
        this.publish(record);
        return this.view(record);
    }

    remove(user, body) {
        const record = this.require(user, body.id);
        this.delete(record);
        this.store.commit(() => this.add(record));
        this.forget(record);
    }

    forget(record) {
        const key = this.keyOf(record);
        this.presence.delete(key);
        this.seen.delete(key);
        for (const client of clientsByUser.get(record.userId) || []) if (client.reporting[this.kind] === key) client.reporting[this.kind] = null;
        broadcast(record.userId, { type: 'remove', kind: this.kind, id: record.id });
    }

    markSeen(record, info) {
        this.seen.set(this.keyOf(record), { ...info, at: now() });
    }

    report(client, message) {
        const record = this.get(client.userId, message.id);
        if (!record) throw new Error(`This ${this.kind} is not registered to your account. Add it from the menu first.`);
        const key = this.keyOf(record);
        const previous = client.reporting[this.kind];
        if (previous && previous !== key) this.release(previous, client.clientId);
        client.reporting[this.kind] = key;
        const location = sanitizeLocation(message.location);
        if (location) record.lastLocation = location;
        record.lastSeenAt = now();
        this.onReport(record, message, client);
        let reporters = this.presence.get(key);
        if (!reporters) this.presence.set(key, reporters = new Map());
        reporters.set(client.clientId, record.lastSeenAt);
        this.store.schedule();
        this.publish(record);
    }

    stop(client, id = '') {
        const key = id ? this.key(client.userId, id) : client.reporting[this.kind];
        if (!key) return;
        if (client.reporting[this.kind] === key) client.reporting[this.kind] = null;
        this.release(key, client.clientId);
    }

    release(key, clientId) {
        const reporters = this.presence.get(key);
        if (!reporters?.delete(clientId)) return;
        if (!reporters.size) this.presence.delete(key);
        const record = this.records.get(key);
        if (record && !this.isOnline(record)) this.publish(record);
    }

    sweep() {
        const cutoff = now() - this.ttlMs;
        for (const [key, reporters] of this.presence) {
            for (const [clientId, at] of reporters) if (at < cutoff) reporters.delete(clientId);
            if (reporters.size) continue;
            this.presence.delete(key);
            const record = this.records.get(key);
            if (record) this.publish(record);
        }
        for (const [key, seen] of this.seen) if (now() - seen.at > SUGGESTION_TTL_MS) this.seen.delete(key);
    }
}

const authStore = new JsonStore(dataFile('AUTH_FILE', 'auth.json'), 'account', 1, 'users', () => [...users.values()]);

const trackers = new Registry('tracker', {
    title: 'Tracker',
    file: dataFile('TRACKERS_FILE', 'trackers.json'),
    version: 4,
    max: 100,
    ttlMs: TRACKER_TTL_MS,
    fields: item => trackerFields(item),
    onReport(record, message) {
        Object.assign(record, trackerFields(message, record));
        if (!record.lastBlePacketAt || record.lastBlePacketAt > record.lastSeenAt) record.lastBlePacketAt = record.lastSeenAt;
    },
});

const devices = new Registry('device', {
    title: 'Device',
    file: dataFile('DEVICES_FILE', 'devices.json'),
    version: 3,
    max: 30,
    ttlMs: DEVICE_TTL_MS,
    uniqueNames: true,
    fields: deviceFields,
    onReport(record, message, client) {
        if (client.platform) record.platform = client.platform;
        this.markSeen(record, { ip: client.ip, platform: client.platform });
    },
});

const registries = new Map([[trackers.kind, trackers], [devices.kind, devices]]);

function runtimeConfig() {
    return { trackerTtlMs: TRACKER_TTL_MS, deviceTtlMs: DEVICE_TTL_MS, wsPath: WS_PATH };
}

function snapshot(userId) {
    return { items: [...trackers.views(userId), ...devices.views(userId)], ...runtimeConfig(), serverTime: now() };
}

function trackerId(value) {
    const id = typeof value === 'string' ? value.trim() : '';
    if (!HARDWARE_ID_RE.test(id)) throw httpError(400, 'Invalid tracker hardware ID. Update the tracker firmware and try again.');
    return id;
}

function assertTrackerAvailable(user, id) {
    const owner = trackers.owner(id);
    if (owner && owner !== user.id) throw httpError(409, 'This tracker is already registered to another account.');
}

function addTracker(user, body) {
    const id = trackerId(body.id);
    assertTrackerAvailable(user, id);
    const existing = trackers.get(user.id, id);
    if (existing) return trackers.view(existing);
    return trackers.create(user, id, { name: readName(body.name, 'OpenTag tracker'), ...trackerFields({}) });
}

function rebindTracker(user, body) {
    const record = trackers.require(user, body.id);
    const newId = trackerId(body.newId);
    if (TEMPORARY_ID_RE.test(newId)) throw httpError(400, 'A permanent tracker hardware ID is required. Update the tracker firmware and try again.');
    if (newId === record.id) return trackers.view(record);
    if (!TEMPORARY_ID_RE.test(record.id)) throw httpError(409, 'This tracker already has a permanent hardware ID and cannot be rebound automatically.');
    assertTrackerAvailable(user, newId);
    const existing = trackers.get(user.id, newId);
    const merged = existing ? { ...existing } : { ...record, id: newId, updatedAt: now() };
    if (existing && (record.lastSeenAt || 0) > (existing.lastSeenAt || 0)) {
        Object.assign(merged, { lastLocation: record.lastLocation, lastSeenAt: record.lastSeenAt });
    }
    trackers.delete(record);
    trackers.add(merged);
    trackers.store.commit(() => {
        trackers.delete(merged);
        trackers.add(record);
        if (existing) trackers.add(existing);
    });
    trackers.forget(record);
    trackers.publish(merged);
    return trackers.view(merged);
}

function registerDevice(user, body, request) {
    let id;
    do id = `dev-${crypto.randomBytes(9).toString('base64url')}`; while (devices.get(user.id, id));
    const info = requestInfo(request);
    const view = devices.create(user, id, { name: readName(body.name), type: deviceFields(body).type, platform: info.platform });
    devices.markSeen(devices.get(user.id, id), info);
    return view;
}

function linkDevice(user, body, request) {
    const record = devices.require(user, body.id);
    devices.markSeen(record, requestInfo(request));
    return devices.view(record);
}

function suggestDevices(user, request) {
    const { ip, platform } = requestInfo(request);
    const ids = devices.forUser(user.id)
        .map(record => ({ record, seen: devices.seen.get(devices.keyOf(record)) }))
        .filter(({ record, seen }) => platform && seen && seen.ip === ip && (seen.platform || record.platform) === platform)
        .sort((a, b) => b.seen.at - a.seen.at)
        .map(({ record }) => record.id);
    return { platform, ids };
}

function publicUser(user) {
    return { id: user.id, username: user.username, createdAt: user.createdAt };
}

function addUser(user) {
    users.set(user.id, user);
    usersByName.set(user.username, user);
}

function loadUsers() {
    authStore.load(item => {
        const username = typeof item.username === 'string' ? item.username.trim().toLowerCase() : '';
        const salt = typeof item.passwordSalt === 'string' ? Buffer.from(item.passwordSalt, 'base64url') : Buffer.alloc(0);
        const hash = typeof item.passwordHash === 'string' ? Buffer.from(item.passwordHash, 'base64url') : Buffer.alloc(0);
        if (!validUserId(item.id) || !USERNAME_RE.test(username) || salt.length !== 16 || hash.length !== SCRYPT_KEY_LENGTH) return false;
        if (users.has(item.id) || usersByName.has(username)) return false;
        addUser({ ...item, username, createdAt: timestamp(item.createdAt) || now() });
        return true;
    });
}

function hashToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function readCookie(header, name) {
    for (const part of String(header || '').split(';')) {
        const index = part.indexOf('=');
        if (index < 1 || part.slice(0, index).trim() !== name) continue;
        const value = part.slice(index + 1).trim();
        try { return decodeURIComponent(value); } catch (_) { return value; }
    }
    return '';
}

function getSession(request) {
    const token = readCookie(request.headers.cookie, SESSION_COOKIE);
    if (!token) return null;
    const key = hashToken(token);
    const session = sessions.get(key);
    const user = session && session.expiresAt > now() ? users.get(session.userId) : null;
    if (!user) {
        sessions.delete(key);
        return null;
    }
    return { key, user };
}

function isSecureRequest(request) {
    if (request.socket.encrypted) return true;
    if (!isTrustedProxy(request)) return false;
    const protocols = forwardedValues(request.headers['x-forwarded-proto']);
    // Proxies such as Nginx Proxy Manager overwrite X-Forwarded-Proto with a single value; use the value set by the nearest trusted proxy.
    return (protocols[protocols.length - 1] || '').toLowerCase() === 'https';
}

function setSessionCookie(request, response, token, maxAgeSeconds) {
    const parts = [`${SESSION_COOKIE}=${encodeURIComponent(token)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAgeSeconds}`];
    if (isSecureRequest(request)) parts.push('Secure');
    response.setHeader('Set-Cookie', parts.join('; '));
}

function startSession(request, response, user) {
    const token = crypto.randomBytes(32).toString('base64url');
    sessions.set(hashToken(token), { userId: user.id, expiresAt: now() + SESSION_TTL_MS });
    setSessionCookie(request, response, token, SESSION_TTL_MS / 1000);
    return { ok: true, user: publicUser(user) };
}

function rateLimit(request, route) {
    const key = `${route}:${clientIp(request)}`;
    const cutoff = now() - RATE_WINDOW_MS;
    const attempts = (authAttempts.get(key) || []).filter(at => at > cutoff);
    authAttempts.set(key, attempts);
    if (attempts.length >= RATE_LIMIT) {
        throw httpError(429, 'Too many attempts. Please wait 15 minutes and try again.', { 'Retry-After': String(RATE_WINDOW_MS / 1000) });
    }
    attempts.push(now());
}

function credentials(body) {
    return {
        username: typeof body.username === 'string' ? body.username.trim().toLowerCase() : '',
        password: typeof body.password === 'string' ? body.password : '',
    };
}

async function readJsonBody(request) {
    const contentType = String(request.headers['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
    if (contentType !== 'application/json') throw httpError(415, 'Content-Type must be application/json');
    if (Number(request.headers['content-length'] || 0) > MAX_BODY_BYTES) throw httpError(413, 'Request body is too large');
    const chunks = [];
    let total = 0;
    for await (const chunk of request) {
        total += chunk.length;
        if (total > MAX_BODY_BYTES) throw httpError(413, 'Request body is too large');
        chunks.push(chunk);
    }
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (_) { }
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw httpError(400, 'Invalid JSON body');
    return body;
}

function sendJson(response, statusCode, data, headers = {}) {
    response.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...SECURITY_HEADERS, ...headers });
    response.end(JSON.stringify(data));
}

const routes = new Map();
function route(method, pathname, handler, requiresAuth = true) {
    routes.set(`${method} ${pathname}`, { handler, requiresAuth });
}

route('GET', '/api/health', () => [200, { ok: true, service: 'opentag-backend', ...runtimeConfig(), time: now() }], false);

route('GET', '/api/auth/me', ({ session }) => [200, session ? { authenticated: true, user: publicUser(session.user) } : { authenticated: false }], false);

route('POST', '/api/auth/register', async ({ request, response, json }) => {
    if (!REGISTRATION_ENABLED) throw httpError(403, 'Registration is currently disabled.');
    rateLimit(request, 'register');
    const { username, password } = credentials(await json());
    if (!USERNAME_RE.test(username)) throw httpError(400, 'Username must be 3–32 characters and contain only letters, numbers, dot, underscore, or hyphen.');
    if (password.length < PASSWORD_MIN_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
        throw httpError(400, `Password must be between ${PASSWORD_MIN_LENGTH} and ${PASSWORD_MAX_LENGTH} characters.`);
    }
    if (usersByName.has(username)) throw httpError(409, 'That username is already taken.');
    const salt = crypto.randomBytes(16);
    const hash = await scrypt(password, salt, SCRYPT_KEY_LENGTH);
    if (usersByName.has(username)) throw httpError(409, 'That username is already taken.');
    const user = { id: crypto.randomUUID(), username, passwordSalt: salt.toString('base64url'), passwordHash: hash.toString('base64url'), createdAt: now() };
    addUser(user);
    authStore.commit(() => {
        users.delete(user.id);
        usersByName.delete(username);
    });
    return [201, startSession(request, response, user)];
}, false);

route('POST', '/api/auth/login', async ({ request, response, json }) => {
    rateLimit(request, 'login');
    const { username, password } = credentials(await json());
    const user = usersByName.get(username);
    let valid = false;
    if (password.length <= PASSWORD_MAX_LENGTH) {
        const candidate = await scrypt(password, user ? Buffer.from(user.passwordSalt, 'base64url') : DUMMY_SALT, SCRYPT_KEY_LENGTH);
        valid = Boolean(user) && crypto.timingSafeEqual(candidate, Buffer.from(user.passwordHash, 'base64url'));
    }
    if (!valid) throw httpError(401, 'Incorrect username or password.');
    return [200, startSession(request, response, user)];
}, false);

route('POST', '/api/auth/logout', ({ request, response, session }) => {
    if (session) {
        sessions.delete(session.key);
        for (const client of [...clients]) if (client.sessionKey === session.key) destroyClient(client);
    }
    setSessionCookie(request, response, '', 0);
    return [200, { ok: true }];
}, false);

route('GET', '/api/state', ({ user }) => [200, snapshot(user.id)]);
route('POST', '/api/trackers/add', async ({ user, json }) => [201, { ok: true, item: addTracker(user, await json()) }]);
route('POST', '/api/trackers/rebind', async ({ user, json }) => [200, { ok: true, item: rebindTracker(user, await json()) }]);
route('POST', '/api/devices/register', async ({ user, json, request }) => [201, { ok: true, item: registerDevice(user, await json(), request) }]);
route('POST', '/api/devices/link', async ({ user, json, request }) => [200, { ok: true, item: linkDevice(user, await json(), request) }]);
route('GET', '/api/devices/suggest', ({ user, request }) => [200, suggestDevices(user, request)]);
for (const registry of registries.values()) {
    route('POST', `/api/${registry.kind}s/rename`, async ({ user, json }) => [200, { ok: true, item: registry.rename(user, await json()) }]);
    route('POST', `/api/${registry.kind}s/remove`, async ({ user, json }) => {
        registry.remove(user, await json());
        return [200, { ok: true }];
    });
}

async function serveStatic(request, response, pathname) {
    if (!STATIC_DIR || (request.method !== 'GET' && request.method !== 'HEAD')) return false;
    let relative;
    try { relative = decodeURIComponent(pathname); } catch (_) { return false; }
    if (relative.includes('\0')) return false;
    if (relative.endsWith('/')) relative += 'index.html';
    const file = path.resolve(STATIC_DIR, `.${relative}`);
    if (!file.startsWith(STATIC_DIR + path.sep)) return false;
    const type = STATIC_MIME[path.extname(file).toLowerCase()];
    if (!type) return false;
    let data;
    try { data = await fs.promises.readFile(file); } catch (_) { return false; }
    response.writeHead(200, { 'Content-Type': type, 'Content-Length': data.length, 'Cache-Control': 'no-cache', 'Content-Security-Policy': CSP, ...SECURITY_HEADERS });
    response.end(request.method === 'HEAD' ? undefined : data);
    return true;
}

const server = http.createServer(async (request, response) => {
    let pathname;
    try { pathname = new URL(request.url, 'http://localhost').pathname; } catch (_) { return sendJson(response, 400, { error: 'Bad request.' }); }
    try {
        const entry = routes.get(`${request.method} ${pathname}`);
        if (entry) {
            const session = getSession(request);
            if (entry.requiresAuth && !session) throw httpError(401, 'Authentication required.');
            const [statusCode, data] = await entry.handler({ request, response, session, user: session?.user, json: () => readJsonBody(request) });
            return sendJson(response, statusCode, data);
        }
        if (!pathname.startsWith('/api/') && await serveStatic(request, response, pathname)) return;
        throw httpError(404, 'Not found');
    } catch (error) {
        const statusCode = Number.isInteger(error.statusCode) ? error.statusCode : 500;
        if (statusCode >= 500) console.error(`Request failed (${request.method} ${pathname}): ${error.stack || error.message}`);
        if (response.headersSent) return response.destroy();
        sendJson(response, statusCode, { error: error.expose ? error.message : 'Internal server error.' }, error.headers);
    }
});
server.requestTimeout = 30000;
server.headersTimeout = 10000;
server.keepAliveTimeout = 5000;
server.maxRequestsPerSocket = 1000;

function broadcast(userId, message) {
    const set = clientsByUser.get(userId);
    if (!set?.size) return;
    const payload = Buffer.from(JSON.stringify(message));
    for (const client of [...set]) sendFrame(client, 0x1, payload);
}

function send(client, message) {
    sendFrame(client, 0x1, Buffer.from(JSON.stringify(message)));
}

function sendFrame(client, opcode, payload = Buffer.alloc(0)) {
    const { socket } = client;
    if (socket.destroyed) return;
    if (socket.writableLength > MAX_WS_BACKLOG_BYTES) return destroyClient(client);
    const length = payload.length;
    const header = Buffer.alloc(length < 126 ? 2 : length < 65536 ? 4 : 10);
    header[0] = 0x80 | opcode;
    if (length < 126) header[1] = length;
    else if (length < 65536) {
        header[1] = 126;
        header.writeUInt16BE(length, 2);
    } else {
        header[1] = 127;
        header.writeBigUInt64BE(BigInt(length), 2);
    }
    socket.write(Buffer.concat([header, payload]));
}

function closeClient(client, code) {
    if (client.closing) return;
    client.closing = true;
    client.buffer = Buffer.alloc(0);
    sendFrame(client, 0x8, Buffer.from([code >> 8, code & 0xff]));
    client.socket.end();
}

function destroyClient(client) {
    if (client.destroyed) return;
    client.destroyed = true;
    clients.delete(client);
    const set = clientsByUser.get(client.userId);
    if (set) {
        set.delete(client);
        if (!set.size) clientsByUser.delete(client.userId);
    }
    for (const registry of registries.values()) registry.stop(client);
    client.socket.destroy();
}

function handleMessage(client, message) {
    const registry = registries.get(message?.kind);
    if (message?.type === 'hello') return send(client, { type: 'snapshot', ...snapshot(client.userId) });
    if (registry && message.type === 'report') {
        try { registry.report(client, message); } catch (error) { send(client, { type: 'error', message: error.message }); }
        return;
    }
    if (registry && message.type === 'stop') return registry.stop(client, typeof message.id === 'string' ? message.id : '');
    send(client, { type: 'error', message: `Unsupported message: ${String(message?.type)}` });
}

function handleText(client, payload) {
    let message;
    try { message = JSON.parse(utf8.decode(payload)); } catch (error) {
        if (error instanceof TypeError) return closeClient(client, 1007);
        return send(client, { type: 'error', message: 'Invalid JSON message' });
    }
    try {
        handleMessage(client, message);
    } catch (error) {
        console.error(`Message handler failed: ${error.stack || error.message}`);
        send(client, { type: 'error', message: 'Internal error while handling the message' });
    }
}

function processFrames(client) {
    while (!client.closing && client.buffer.length >= 2) {
        const buffer = client.buffer;
        const fin = (buffer[0] & 0x80) !== 0;
        const opcode = buffer[0] & 0x0f;
        let length = buffer[1] & 0x7f;
        let offset = 2;
        if (buffer[0] & 0x70 || !(buffer[1] & 0x80) || ![0x1, 0x2, 0x8, 0x9, 0xa].includes(opcode)) return closeClient(client, 1002);
        if (opcode >= 0x8 && (!fin || length > 125)) return closeClient(client, 1002);
        if (!fin) return closeClient(client, 1003);
        if (length === 126) {
            if (buffer.length < 4) return;
            length = buffer.readUInt16BE(2);
            if (length < 126) return closeClient(client, 1002);
            offset = 4;
        } else if (length === 127) {
            if (buffer.length < 10) return;
            const length64 = buffer.readBigUInt64BE(2);
            if (length64 < 65536n) return closeClient(client, 1002);
            if (length64 > BigInt(MAX_MESSAGE_BYTES)) return closeClient(client, 1009);
            length = Number(length64);
            offset = 10;
        }
        if (length > MAX_MESSAGE_BYTES) return closeClient(client, 1009);
        const end = offset + 4 + length;
        if (buffer.length < end) return;
        const mask = buffer.subarray(offset, offset + 4);
        const payload = Buffer.from(buffer.subarray(offset + 4, end));
        for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
        client.buffer = buffer.subarray(end);
        client.alive = true;
        if (opcode === 0x1) handleText(client, payload);
        else if (opcode === 0x2) return closeClient(client, 1003);
        else if (opcode === 0x9) sendFrame(client, 0xa, payload);
        else if (opcode === 0x8) {
            if (payload.length === 1) return closeClient(client, 1002);
            if (payload.length >= 2) {
                const code = payload.readUInt16BE(0);
                if (!WS_CLOSE_CODES.has(code) && (code < 3000 || code > 4999)) return closeClient(client, 1002);
                try { utf8.decode(payload.subarray(2)); } catch (_) { return closeClient(client, 1007); }
            }
            client.closing = true;
            client.buffer = Buffer.alloc(0);
            sendFrame(client, 0x8, payload);
            return client.socket.end();
        }
    }
}

function rejectUpgrade(socket, status) {
    try { socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n`); } catch (_) { }
    socket.destroy();
}

function originAllowed(request) {
    const origin = request.headers.origin;
    if (!origin) return true;
    try {
        const parsed = new URL(origin);
        return ['http:', 'https:'].includes(parsed.protocol) && parsed.host.toLowerCase() === String(request.headers.host || '').toLowerCase();
    } catch (_) {
        return false;
    }
}

server.on('upgrade', (request, socket, head) => {
    socket.on('error', () => { });
    let pathname;
    try { pathname = new URL(request.url, 'http://localhost').pathname.replace(/\/+$/, ''); } catch (_) { return rejectUpgrade(socket, '400 Bad Request'); }
    if (request.method !== 'GET' || pathname !== WS_PATH) return rejectUpgrade(socket, '404 Not Found');
    const session = getSession(request);
    if (!session) return rejectUpgrade(socket, '401 Unauthorized');
    if (!originAllowed(request)) return rejectUpgrade(socket, '403 Forbidden');
    const key = String(request.headers['sec-websocket-key'] || '').trim();
    const decodedKey = Buffer.from(key, 'base64');
    const connection = String(request.headers.connection || '').toLowerCase().split(',').map(value => value.trim());
    if (String(request.headers.upgrade || '').toLowerCase() !== 'websocket' || !connection.includes('upgrade') ||
        decodedKey.length !== 16 || decodedKey.toString('base64') !== key || request.headers['sec-websocket-version'] !== '13') {
        return rejectUpgrade(socket, '400 Bad Request');
    }
    const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.setNoDelay(true);
    const client = {
        socket,
        clientId: crypto.randomUUID(),
        sessionKey: session.key,
        userId: session.user.id,
        buffer: Buffer.alloc(0),
        reporting: { tracker: null, device: null },
        ...requestInfo(request),
        destroyed: false,
        closing: false,
        alive: true,
    };
    clients.add(client);
    if (!clientsByUser.has(client.userId)) clientsByUser.set(client.userId, new Set());
    clientsByUser.get(client.userId).add(client);
    socket.on('data', chunk => {
        if (client.destroyed || client.closing) return;
        if (client.buffer.length + chunk.length > MAX_WS_BUFFER_BYTES) return closeClient(client, 1009);
        client.buffer = client.buffer.length ? Buffer.concat([client.buffer, chunk]) : chunk;
        processFrames(client);
    });
    for (const event of ['close', 'end', 'error']) socket.on(event, () => destroyClient(client));
    if (head?.length) {
        client.buffer = Buffer.from(head);
        processFrames(client);
    }
});

setInterval(() => {
    for (const registry of registries.values()) registry.sweep();
}, SWEEP_INTERVAL_MS).unref();

setInterval(() => {
    const time = now();
    for (const [key, session] of sessions) if (session.expiresAt <= time) sessions.delete(key);
    for (const [key, attempts] of authAttempts) {
        const recent = attempts.filter(at => at > time - RATE_WINDOW_MS);
        if (recent.length) authAttempts.set(key, recent);
        else authAttempts.delete(key);
    }
    for (const client of [...clients]) {
        if (!sessions.has(client.sessionKey) || !client.alive) {
            destroyClient(client);
            continue;
        }
        client.alive = false;
        sendFrame(client, 0x9);
    }
}, PING_INTERVAL_MS).unref();

function shutdown(signal) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`${signal} received, saving data and shutting down.`);
    for (const client of [...clients]) closeClient(client, 1001);
    const saved = [authStore, trackers.store, devices.store].map(store => store.flush()).every(Boolean);
    if (!saved) console.error('One or more persistent data files could not be saved.');
    else console.log('Persistent data flush completed.');
    const exit = () => process.exit(saved ? 0 : 1);
    server.close(exit);
    setTimeout(exit, 3000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', reason => {
    console.error('Unhandled rejection:', reason);
    shutdown('UNHANDLED_REJECTION');
});

loadUsers();
for (const registry of registries.values()) registry.load();

server.listen(PORT, HOST, () => {
    console.log(`OpenTag backend listening on http://${HOST}:${PORT}`);
    console.log(`WebSocket endpoint: ${WS_PATH}`);
    console.log(`Account registration: ${REGISTRATION_ENABLED ? 'enabled' : 'disabled'}`);
    console.log(`Data directory: ${DATA_DIR || 'none (memory only)'}`);
    if (TRUSTED_PROXY_HOPS < 1) console.log('Reverse proxy: none (X-Forwarded-* headers ignored)');
    else if (!TRUSTED_PROXIES.count) console.warn('TRUSTED_PROXY_HOPS is set but TRUSTED_PROXY_IPS is empty; X-Forwarded-* headers are ignored. Set TRUSTED_PROXY_IPS to your reverse proxy address or range.');
    else console.log(`Reverse proxy: ${TRUSTED_PROXY_HOPS} hop(s), ${TRUSTED_PROXIES.count} trusted address/range entr${TRUSTED_PROXIES.count === 1 ? 'y' : 'ies'}`);
    if (STATIC_DIR) console.log(`Serving web app from ${STATIC_DIR}`);
});
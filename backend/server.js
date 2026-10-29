'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');

const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT || 3000);
const WS_PATH = process.env.WS_PATH || '/ws';
const TRACKER_TTL_MS = Number(process.env.TRACKER_TTL_MS || 15000);
const MAX_MESSAGE_BYTES = 32 * 1024;
const MAX_TRACKERS = 200;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN || '';
const PING_INTERVAL_MS = Number(process.env.PING_INTERVAL_MS || 25000);
const DATA_FILE = process.env.DATA_FILE || '';

const trackerStates = new Map();
const lastKnown = new Map();
const clients = new Set();

function now() {
  return Date.now();
}

function finiteNumber(value) {
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

function tokenOk(provided) {
  if (!ACCESS_TOKEN) return true;
  const a = crypto.createHash('sha256').update(String(provided || '')).digest();
  const b = crypto.createHash('sha256').update(ACCESS_TOKEN).digest();
  return crypto.timingSafeEqual(a, b);
}

let saveTimer = null;

function scheduleSave() {
  if (!DATA_FILE || saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    const tmp = `${DATA_FILE}.tmp`;
    try {
      fs.writeFileSync(tmp, JSON.stringify([...lastKnown.values()]));
      fs.renameSync(tmp, DATA_FILE);
    } catch (error) {
      console.warn(`Could not save ${DATA_FILE}: ${error.message}`);
    }
  }, 5000);
}

function loadLastKnown() {
  if (!DATA_FILE) return;
  try {
    const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    for (const item of Array.isArray(data) ? data : []) {
      const location = sanitizeLocation(item && item.location);
      const trackerId = clampText(item && item.trackerId, 100);
      if (!trackerId || !location) continue;
      lastKnown.set(trackerId, { ...item, trackerId, location, live: false });
    }
    console.log(`Loaded ${lastKnown.size} last known position(s) from ${DATA_FILE}`);
  } catch (error) {
    if (error.code !== 'ENOENT') console.warn(`Could not load ${DATA_FILE}: ${error.message}`);
  }
}

function lastKnownSnapshot() {
  return [...lastKnown.values()];
}

function sanitizeLocation(location) {
  if (!location || !validLatitude(location.lat) || !validLongitude(location.lng)) {
    return null;
  }

  const accuracy = finiteNumber(location.accuracy);
  return {
    lat: Number(location.lat),
    lng: Number(location.lng),
    accuracy: accuracy !== null && accuracy >= 0 && accuracy <= 100000
      ? accuracy
      : null,
  };
}

function sanitizeReport(message, clientId) {
  const trackerId = clampText(message.trackerId, 100);
  const trackerName = clampText(message.trackerName || trackerId, 100);

  if (!trackerId) {
    throw new Error('trackerId is required');
  }

  const rssi = finiteNumber(message.rssi);
  const txPower = finiteNumber(message.txPower);
  const distanceM = finiteNumber(message.distanceM);
  const location = sanitizeLocation(message.location);
  const mode = message.mode === 'lost' ? 'lost' : 'normal';

  return {
    trackerId,
    trackerName,
    location,
    rssi: rssi !== null && rssi >= -150 && rssi <= 0 ? rssi : null,
    txPower: txPower !== null && txPower >= -100 && txPower <= 30 ? txPower : null,
    distanceM: distanceM !== null && distanceM >= 0 && distanceM <= 100000
      ? distanceM
      : null,
    mode,
    live: true,
    reporterId: clientId,
    updatedAt: now(),
    lastBlePacketAt: Number.isFinite(Number(message.lastBlePacketAt))
      ? Number(message.lastBlePacketAt)
      : now(),
  };
}

function stateSnapshot() {
  const cutoff = now() - TRACKER_TTL_MS;
  const states = [];
  for (const [trackerId, state] of trackerStates) {
    if (state.updatedAt < cutoff) {
      trackerStates.delete(trackerId);
      continue;
    }
    states.push(state);
  }
  return states;
}

function sendFrame(socket, opcode, payloadBuffer = Buffer.alloc(0)) {
  if (socket.destroyed) return;

  const payload = Buffer.isBuffer(payloadBuffer)
    ? payloadBuffer
    : Buffer.from(payloadBuffer);

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

  socket.write(Buffer.concat([header, payload]));
}

function sendJson(client, message) {
  sendFrame(client.socket, 0x1, Buffer.from(JSON.stringify(message)));
}

function broadcast(message) {
  for (const client of clients) {
    try {
      sendJson(client, message);
    } catch (_) {
      destroyClient(client);
    }
  }
}

function removeTrackerForClient(clientId, trackerId) {
  const state = trackerStates.get(trackerId);
  if (!state || state.reporterId !== clientId) return false;

  trackerStates.delete(trackerId);
  broadcast({
    type: 'trackerRemoved',
    trackerId,
    lastKnown: lastKnown.get(trackerId) || null,
    reason: 'reporter_disconnected',
    at: now(),
  });
  return true;
}

function handleMessage(client, message) {
  if (!message || typeof message !== 'object') return;

  if (message.type === 'hello') {
    sendJson(client, {
      type: 'helloAck',
      clientId: client.clientId,
      serverTime: now(),
    });

    sendJson(client, {
      type: 'snapshot',
      trackers: stateSnapshot(),
      lastKnown: lastKnownSnapshot(),
      serverTime: now(),
    });
    return;
  }

  if (message.type === 'trackerReport') {
    try {
      const state = sanitizeReport(message, client.clientId);
      const known = trackerStates.has(state.trackerId) || lastKnown.has(state.trackerId);
      if (!known && Math.max(trackerStates.size, lastKnown.size) >= MAX_TRACKERS) {
        throw new Error('Too many trackers');
      }
      trackerStates.set(state.trackerId, state);
      if (state.location) {
        lastKnown.set(state.trackerId, { ...state, live: false });
        scheduleSave();
      }

      broadcast({
        type: 'trackerState',
        state,
      });
    } catch (error) {
      sendJson(client, {
        type: 'error',
        message: error.message,
      });
    }
    return;
  }

  if (message.type === 'trackerStop') {
    const trackerId = clampText(message.trackerId, 100);
    if (trackerId) removeTrackerForClient(client.clientId, trackerId);
    return;
  }

  sendJson(client, {
    type: 'error',
    message: `Unknown message type: ${String(message.type || 'undefined')}`,
  });
}

function processWebSocketBuffer(client) {
  while (client.buffer.length >= 2) {
    const first = client.buffer[0];
    const second = client.buffer[1];
    const fin = Boolean(first & 0x80);
    const opcode = first & 0x0f;
    const masked = Boolean(second & 0x80);
    let payloadLength = second & 0x7f;
    let offset = 2;

    if (!masked) {
      sendFrame(client.socket, 0x8, Buffer.from([0x03, 0xea]));
      client.socket.end();
      return;
    }

    if (payloadLength === 126) {
      if (client.buffer.length < offset + 2) return;
      payloadLength = client.buffer.readUInt16BE(offset);
      offset += 2;
    } else if (payloadLength === 127) {
      if (client.buffer.length < offset + 8) return;
      const length64 = client.buffer.readBigUInt64BE(offset);
      if (length64 > BigInt(MAX_MESSAGE_BYTES)) {
        sendFrame(client.socket, 0x8, Buffer.from([0x03, 0xf1]));
        client.socket.end();
        return;
      }
      payloadLength = Number(length64);
      offset += 8;
    }

    if (payloadLength > MAX_MESSAGE_BYTES) {
      sendFrame(client.socket, 0x8, Buffer.from([0x03, 0xf1]));
      client.socket.end();
      return;
    }

    const frameLength = offset + 4 + payloadLength;
    if (client.buffer.length < frameLength) return;

    const mask = client.buffer.subarray(offset, offset + 4);
    offset += 4;
    const payload = Buffer.from(client.buffer.subarray(offset, offset + payloadLength));
    client.buffer = client.buffer.subarray(frameLength);
    client.alive = true;

    for (let i = 0; i < payload.length; i++) {
      payload[i] ^= mask[i % 4];
    }

    if (!fin && opcode < 8) {
      sendFrame(client.socket, 0x8, Buffer.from([0x03, 0xeb]));
      client.socket.end();
      return;
    }

    if (opcode === 0x1) {
      try {
        const text = payload.toString('utf8');
        handleMessage(client, JSON.parse(text));
      } catch (error) {
        sendJson(client, {
          type: 'error',
          message: 'Invalid JSON message',
        });
      }
    } else if (opcode === 0x8) {
      sendFrame(client.socket, 0x8, payload);
      client.socket.end();
      return;
    } else if (opcode === 0x9) {
      sendFrame(client.socket, 0xA, payload);
    } else if (opcode === 0xA) {
    } else {
      sendFrame(client.socket, 0x8, Buffer.from([0x03, 0xeb]));
      client.socket.end();
      return;
    }
  }
}

function destroyClient(client) {
  if (client.destroyed) return;
  client.destroyed = true;
  clients.delete(client);

  for (const [trackerId, state] of trackerStates) {
    if (state.reporterId === client.clientId) {
      trackerStates.delete(trackerId);
      broadcast({
        type: 'trackerRemoved',
        trackerId,
        lastKnown: lastKnown.get(trackerId) || null,
        reason: 'reporter_disconnected',
        at: now(),
      });
    }
  }

  try { client.socket.destroy(); } catch (_) {}
}

function handleUpgrade(request, socket) {
  const url = new URL(request.url, 'http://localhost');
  const expectedWsPath = (WS_PATH || '/ws').replace(/\/+$/, '') || '/ws';
  if (request.method !== 'GET' || (url.pathname !== expectedWsPath && url.pathname !== `${expectedWsPath}/`)) {
    socket.destroy();
    return;
  }

  if (!tokenOk(url.searchParams.get('token'))) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }

  const upgrade = String(request.headers.upgrade || '').toLowerCase();
  const connection = String(request.headers.connection || '').toLowerCase();
  const key = request.headers['sec-websocket-key'];
  const version = String(request.headers['sec-websocket-version'] || '');

  if (upgrade !== 'websocket' || !connection.includes('upgrade') || !key || version !== '13') {
    socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }

  const accept = crypto
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');

  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n` +
    '\r\n'
  );

  const client = {
    socket,
    clientId: crypto.randomUUID(),
    buffer: Buffer.alloc(0),
    destroyed: false,
    alive: true,
  };

  clients.add(client);

  socket.on('data', (chunk) => {
    if (client.destroyed) return;
    client.buffer = Buffer.concat([client.buffer, chunk]);
    processWebSocketBuffer(client);
  });

  socket.on('close', () => destroyClient(client));
  socket.on('end', () => destroyClient(client));
  socket.on('error', () => destroyClient(client));

}

const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

  if (request.method === 'GET' && url.pathname === '/api/health') {
    const body = JSON.stringify({
      ok: true,
      service: 'opentag-backend',
      time: now(),
      clients: clients.size,
      trackers: stateSnapshot().length,
    });

    response.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    });
    response.end(body);
    return;
  }

  if (request.method === 'GET' && url.pathname === '/api/state') {
    const provided = url.searchParams.get('token') || request.headers['x-access-token'];
    if (!tokenOk(provided)) {
      response.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }
    const body = JSON.stringify({
      trackers: stateSnapshot(),
      lastKnown: lastKnownSnapshot(),
      serverTime: now(),
    });

    response.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0',
    });
    response.end(body);
    return;
  }

  response.writeHead(404, {
    'Content-Type': 'application/json; charset=utf-8',
  });
  response.end(JSON.stringify({ error: 'Not found' }));
});

server.on('upgrade', handleUpgrade);

setInterval(() => {
  const cutoff = now() - TRACKER_TTL_MS;
  for (const [trackerId, state] of trackerStates) {
    if (state.updatedAt < cutoff) {
      trackerStates.delete(trackerId);
      broadcast({
        type: 'trackerRemoved',
        trackerId,
        lastKnown: lastKnown.get(trackerId) || null,
        reason: 'stale',
        at: now(),
      });
    }
  }
}, 5000).unref();

setInterval(() => {
  for (const client of [...clients]) {
    if (!client.alive) {
      destroyClient(client);
      continue;
    }
    client.alive = false;
    try {
      sendFrame(client.socket, 0x9);
    } catch (_) {
      destroyClient(client);
    }
  }
}, PING_INTERVAL_MS).unref();

loadLastKnown();

server.listen(PORT, HOST, () => {
  console.log(`OpenTag backend listening on http://${HOST}:${PORT}`);
  console.log(`WebSocket endpoint: ${WS_PATH}`);
  console.log(`Tracker state TTL: ${TRACKER_TTL_MS} ms`);
  console.log(`Access code: ${ACCESS_TOKEN ? 'required' : 'NOT SET (open access)'}`);
  console.log(`Last known positions file: ${DATA_FILE || 'none (memory only)'}`);
});

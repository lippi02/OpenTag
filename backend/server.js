'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT || 3000);
const WS_PATH = process.env.WS_PATH || '/ws';
const TRACKER_TTL_MS = Number(process.env.TRACKER_TTL_MS || 15000);
const MAX_MESSAGE_BYTES = 32 * 1024;

// Phase 1 is intentionally simple: state lives in memory only.
// Later, authenticated users/trackers can be persisted in a database.
const trackerStates = new Map();
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
    // This prototype never intentionally sends payloads this large.
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
    reason: 'reporter_disconnected',
    at: now(),
  });
  return true;
}

function handleMessage(client, message) {
  if (!message || typeof message !== 'object') return;

  if (message.type === 'hello') {
    const requestedId = clampText(message.clientId, 120);
    if (requestedId) client.clientId = requestedId;

    sendJson(client, {
      type: 'helloAck',
      clientId: client.clientId,
      serverTime: now(),
    });

    sendJson(client, {
      type: 'snapshot',
      trackers: stateSnapshot(),
      serverTime: now(),
    });
    return;
  }

  if (message.type === 'trackerReport') {
    try {
      const state = sanitizeReport(message, client.clientId);
      trackerStates.set(state.trackerId, state);

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
      sendFrame(client.socket, 0x8, Buffer.from([0x03, 0xea])); // 1002
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
        sendFrame(client.socket, 0x8, Buffer.from([0x03, 0xf1])); // 1009
        client.socket.end();
        return;
      }
      payloadLength = Number(length64);
      offset += 8;
    }

    if (payloadLength > MAX_MESSAGE_BYTES) {
      sendFrame(client.socket, 0x8, Buffer.from([0x03, 0xf1])); // 1009
      client.socket.end();
      return;
    }

    const frameLength = offset + 4 + payloadLength;
    if (client.buffer.length < frameLength) return;

    const mask = client.buffer.subarray(offset, offset + 4);
    offset += 4;
    const payload = Buffer.from(client.buffer.subarray(offset, offset + payloadLength));
    client.buffer = client.buffer.subarray(frameLength);

    for (let i = 0; i < payload.length; i++) {
      payload[i] ^= mask[i % 4];
    }

    // Browsers send the JSON messages here as single, final text frames.
    if (!fin && opcode < 8) {
      sendFrame(client.socket, 0x8, Buffer.from([0x03, 0xeb])); // 1003
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
      sendFrame(client.socket, 0xA, payload); // pong
    } else if (opcode === 0xA) {
      // pong: nothing to do
    } else {
      sendFrame(client.socket, 0x8, Buffer.from([0x03, 0xeb])); // 1003
      client.socket.end();
      return;
    }
  }
}

function destroyClient(client) {
  if (client.destroyed) return;
  client.destroyed = true;
  clients.delete(client);

  // Only remove states that are still reported by this client.
  for (const [trackerId, state] of trackerStates) {
    if (state.reporterId === client.clientId) {
      trackerStates.delete(trackerId);
      broadcast({
        type: 'trackerRemoved',
        trackerId,
        reason: 'reporter_disconnected',
        at: now(),
      });
    }
  }

  try { client.socket.destroy(); } catch (_) {}
}

function handleUpgrade(request, socket) {
  const url = new URL(request.url, 'http://localhost');
  // Accept both forms because NPMplus custom locations are normally slash-terminated.
  const expectedWsPath = (WS_PATH || '/ws').replace(/\/+$/, '') || '/ws';
  if (request.method !== 'GET' || (url.pathname !== expectedWsPath && url.pathname !== `${expectedWsPath}/`)) {
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
    const body = JSON.stringify({
      trackers: stateSnapshot(),
      serverTime: now(),
    });

    response.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
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
        reason: 'stale',
        at: now(),
      });
    }
  }
}, 5000).unref();

server.listen(PORT, HOST, () => {
  console.log(`OpenTag backend listening on http://${HOST}:${PORT}`);
  console.log(`WebSocket endpoint: ${WS_PATH}`);
  console.log(`Tracker state TTL: ${TRACKER_TTL_MS} ms`);
});

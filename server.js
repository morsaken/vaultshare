const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Serve static files from the public directory.
// Use no-cache so browsers always revalidate against the ETag: unchanged files
// return a fast 304, but updated JS/CSS/HTML are picked up on a normal refresh
// (avoids stale cached client code after a deploy).
app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  setHeaders: (res) => {
    res.setHeader('Cache-Control', 'no-cache');
  }
}));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Track rooms: roomId -> array of ws connections
const rooms = new Map();

// Maximum peers allowed in a single room (1:1 transfer).
const MAX_PEERS = 2;

// --- Abuse / scanning protection ---------------------------------------------
// Room codes are short ("000-000", ~900k combinations), so the whole keyspace is
// small enough to enumerate. Without limits an attacker could script a client
// that cycles through every code to discover active rooms and grab the open peer
// slot — occupying it (denial-of-service) or attempting a MITM (the latter is
// still caught by the client's fingerprint verification, but we don't want to
// depend on users checking it). These limits make enumeration impractical while
// staying invisible to normal users, who join only a handful of times.

// X-Forwarded-For is client-controlled and trivially spoofed to dodge per-IP
// limits, so only trust it when explicitly running behind a known proxy.
const TRUST_PROXY = process.env.TRUST_PROXY === '1';

const MAX_CONNECTIONS_PER_IP = 10;   // concurrent sockets from one IP
const JOIN_WINDOW_MS = 60 * 1000;    // sliding window for join attempts
const MAX_JOINS_PER_WINDOW = 30;     // join attempts per IP per window
const MSG_WINDOW_MS = 10 * 1000;     // sliding window for all messages
const MAX_MSGS_PER_WINDOW = 120;     // messages per connection per window
const MAX_ROOM_ID_LENGTH = 64;       // reject absurdly long room IDs

const connectionsPerIp = new Map();  // ip -> live connection count
const joinAttempts = new Map();      // ip -> timestamps[] of recent joins

function getClientIp(req) {
  if (TRUST_PROXY) {
    const fwd = req.headers['x-forwarded-for'];

    if (fwd) return fwd.split(',')[0].trim();
  }

  return req.socket.remoteAddress || 'unknown';
}

// Record a hit against a sliding window and report whether it's still within
// the allowed rate. Shared by the per-IP join limiter.
function withinRate(map, key, windowMs, max) {
  const now = Date.now();
  const times = (map.get(key) || []).filter(t => now - t < windowMs);
 
  times.push(now);
  map.set(key, times);

  return times.length <= max;
}

// Periodically drop stale rate-limit records so the map can't grow unbounded
// from one-off scanner IPs. unref() keeps this timer from holding the process open.
setInterval(() => {
  const now = Date.now();
  
  for (const [ip, times] of joinAttempts) {
    const recent = times.filter(t => now - t < JOIN_WINDOW_MS);

    if (recent.length === 0) joinAttempts.delete(ip);
    else joinAttempts.set(ip, recent);
  }
}, JOIN_WINDOW_MS).unref();

// Remove any sockets that are no longer open, so a crashed/dropped peer doesn't
// keep occupying a slot and cause a false "Room is full" for a real peer.
function pruneDeadClients(clients) {
  for (let i = clients.length - 1; i >= 0; i--) {
    if (clients[i].readyState !== WebSocket.OPEN) {
      clients.splice(i, 1);
    }
  }
}

wss.on('connection', (ws, req) => {
  const ip = getClientIp(req);

  let currentRoomId = null;
  let msgTimes = []; // per-connection message timestamps (flood guard)

  // Track concurrent connections per IP. Registered before the cap check so the
  // close handler always decrements, even for a rejected connection.
  connectionsPerIp.set(ip, (connectionsPerIp.get(ip) || 0) + 1);

  ws.on('close', () => {
    leaveRoom(ws, currentRoomId);

    const remaining = (connectionsPerIp.get(ip) || 1) - 1;

    if (remaining <= 0) connectionsPerIp.delete(ip);
    else connectionsPerIp.set(ip, remaining);
  });

  ws.on('error', (err) => {
    console.error('WebSocket client error:', err);
    leaveRoom(ws, currentRoomId);
  });

  if (connectionsPerIp.get(ip) > MAX_CONNECTIONS_PER_IP) {
    ws.send(JSON.stringify({ type: 'error', message: 'Too many connections from this address' }));
    ws.close();
    return;
  }

  ws.on('message', messageStr => {
    // Per-connection flood guard: a single socket spamming joins/signals.
    const now = Date.now();

    msgTimes = msgTimes.filter(t => now - t < MSG_WINDOW_MS);
    msgTimes.push(now);

    if (msgTimes.length > MAX_MSGS_PER_WINDOW) {
      ws.send(JSON.stringify({ type: 'error', message: 'Rate limit exceeded' }));
      ws.close();

      return;
    }

    try {
      const message = JSON.parse(messageStr);

      switch (message.type) {
        case 'join': {
          const { roomId } = message;

          if (!roomId || typeof roomId !== 'string' || roomId.length > MAX_ROOM_ID_LENGTH) {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid room ID' }));
            return;
          }

          // Throttle join attempts per IP to stop room-code enumeration. A real
          // user joins a few times; a scanner needs thousands and gets cut off.
          if (!withinRate(joinAttempts, ip, JOIN_WINDOW_MS, MAX_JOINS_PER_WINDOW)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Too many join attempts. Please slow down and try again shortly.' }));
            return;
          }

          // Leave previous room if any
          leaveRoom(ws, currentRoomId);

          currentRoomId = roomId;

          if (!rooms.has(roomId)) {
            rooms.set(roomId, []);
          }

          const clients = rooms.get(roomId);

          // Drop dead sockets first so the cap reflects live peers only.
          pruneDeadClients(clients);

          if (clients.length >= MAX_PEERS) {
            ws.send(JSON.stringify({ type: 'error', message: 'Room is full' }));
            currentRoomId = null;
            return;
          }

          clients.push(ws);

          ws.send(JSON.stringify({ 
            type: 'joined', 
            roomId, 
            peerCount: clients.length 
          }));

          // Notify both peers that the room is now paired. The peer already
          // waiting in the room (clients[0]) drives the handshake as initiator;
          // the one that just joined answers. Assigning the role here (rather
          // than once at join time) keeps it correct across reconnects: whoever
          // is already present when someone (re)joins becomes the initiator, so
          // the handshake never deadlocks with two non-initiators.
          if (clients.length === MAX_PEERS) {
            const existingPeer = clients[0] === ws ? clients[1] : clients[0];
            existingPeer.send(JSON.stringify({ type: 'peer-joined', initiator: true }));
            ws.send(JSON.stringify({ type: 'peer-joined', initiator: false }));
          }

          break;
        }

        case 'signal': {
          if (!currentRoomId || !rooms.has(currentRoomId)) {
            ws.send(JSON.stringify({ type: 'error', message: 'Not in a room' }));
            return;
          }

          const clients = rooms.get(currentRoomId);
          const peer = clients.find(client => client !== ws);

          if (peer && (peer.readyState === WebSocket.OPEN)) {
            peer.send(JSON.stringify({ 
              type: 'signal', 
              payload: message.payload 
            }));
          }
          
          break;
        }

        case 'leave': {
          // Explicit leave from the client (peer dropped, or user disconnected).
          // Without this the socket stays registered in the room even after the
          // client resets, desyncing server and client: a reconnecting peer gets
          // paired with the stale slot, and the next join fires a phantom
          // "peer-left" at the other side.
          leaveRoom(ws, currentRoomId);
          currentRoomId = null;
          break;
        }

        default:
          ws.send(JSON.stringify({ type: 'error', message: 'Unknown message type' }));
      }
    } catch (err) {
      console.error('Error processing message:', err);
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
    }
  });
});

function leaveRoom(ws, roomId) {
  if (!roomId || !rooms.has(roomId)) return;

  const clients = rooms.get(roomId);
  const index = clients.indexOf(ws);

  if (index !== -1) {
    clients.splice(index, 1);
  }

  // Notify remaining peer
  if (clients.length > 0) {
    clients[0].send(JSON.stringify({ type: 'peer-left' }));
  } else {
    rooms.delete(roomId);
  }
}

server.listen(port, () => {
  console.log(`Signaling server listening on http://localhost:${port}`);
});

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const crypto = require('crypto');

// Load a local `.env` into process.env if present (Node >= 20.12). PM2 and a
// bare `node server.js` do NOT auto-load .env; ambient env vars still win.
try {
  process.loadEnvFile();
} catch (_) {
  /* no .env file — rely on the ambient environment */
}

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

// --- TURN credentials --------------------------------------------------------
// A browser can't safely hold a secret (client JS is fully readable), so it
// never talks to the ../turn credential service directly. Instead this server —
// which the browser already trusts as its origin — mints the time-based
// one-time code (TOTP, shared secret with ../turn) server-side, redeems it for
// short-lived coturn credentials, and serves the ICE list to the browser at
// GET /turn-credentials.
//
// The one-time code may only be redeemed once per ~30s window, and the coturn
// credentials are valid for hours, so we cache the payload and refresh well
// before expiry rather than minting a code per browser request (which would
// collide on the single-use check).

const TURN_AUTH_URL = process.env.TURN_AUTH_URL || 'http://localhost:8080';
const TURN_AUTH_TOTP_SECRET = process.env.TURN_AUTH_TOTP_SECRET || 'change-me-shared-totp-secret';
const TOTP_PERIOD = parseInt(process.env.TOTP_PERIOD || '30', 10);
const TOTP_DIGITS = parseInt(process.env.TOTP_DIGITS || '6', 10);

// STUN-only fallback so direct / same-network transfers still work if the TURN
// service is unreachable.
const STUN_FALLBACK = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun.cloudflare.com:3478' }
];

// Current TOTP code (RFC 6238) — same algorithm as ../turn's verifier and the
// mobile app: HMAC-SHA1 over the 8-byte big-endian time counter, truncated.
function turnAuthCode() {
  const counter = Math.floor(Date.now() / 1000 / TOTP_PERIOD);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac('sha1', Buffer.from(TURN_AUTH_TOTP_SECRET, 'utf8')).update(buf).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return String(bin % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

// Cached ICE list + in-flight de-dupe so concurrent browser requests trigger at
// most one code redemption. iceCache.iceServers is kept as the last-known-good
// even past the refresh time (the credential itself lives longer), so a failed
// refresh can still serve valid relay creds instead of dropping to STUN.
let iceCache = { iceServers: null, expiresAt: 0 };
let iceInFlight = null;

async function fetchIceServers() {
  const res = await fetch(`${TURN_AUTH_URL}/credentials`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: turnAuthCode() })
  });
  if (!res.ok) throw new Error(`TURN auth HTTP ${res.status}`);
  const data = await res.json();
  if (!Array.isArray(data.iceServers) || data.iceServers.length === 0) {
    throw new Error('TURN auth returned no iceServers');
  }
  // Refresh at half the credential lifetime so we never hand out a
  // nearly-expired credential; clamp for a missing/odd ttl.
  const ttlSec = Number(data.ttl) > 0 ? Number(data.ttl) : 3600;
  const refreshMs = Math.max(60, Math.floor(ttlSec / 2)) * 1000;
  iceCache = { iceServers: data.iceServers, expiresAt: Date.now() + refreshMs };
  return data.iceServers;
}

async function getIceServers() {
  if (iceCache.iceServers && Date.now() < iceCache.expiresAt) {
    return iceCache.iceServers;
  }
  if (!iceInFlight) {
    iceInFlight = fetchIceServers().finally(() => { iceInFlight = null; });
  }
  return iceInFlight;
}

// NOTE: credentials are intentionally NOT exposed over a plain HTTP endpoint.
// An open GET would let anyone harvest working relay credentials directly. They
// are instead handed out only over the signaling WebSocket, and only to a
// socket that has paired into a room (see the 'get-turn-credentials' handler
// below). So a credential is only ever issued to an actual in-progress session.

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

const MAX_CONNECTIONS_PER_IP = 100;   // concurrent sockets from one IP
const JOIN_WINDOW_MS = 60 * 1000;    // sliding window for join attempts
const MAX_JOINS_PER_WINDOW = 30;     // join attempts per IP per window
const MSG_WINDOW_MS = 10 * 1000;     // sliding window for all messages
const MAX_MSGS_PER_WINDOW = 120;     // messages per connection per window
const MAX_ROOM_ID_LENGTH = 64;       // reject absurdly long room IDs
const HEARTBEAT_INTERVAL_MS = 30 * 1000; // ping clients to detect dead sockets

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

// Heartbeat: ping every client each interval. A client that didn't answer the
// previous ping (isAlive still false) is treated as dead and terminated, which
// fires its 'close' handler — decrementing connectionsPerIp and freeing its room
// slot. Without this, silently-dropped sockets keep occupying the per-IP
// connection budget (false "Too many connections") and room slots (false "Room
// is full"), since an ungraceful drop never fires 'close' on its own.
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) {
      ws.terminate();
      continue;
    }

    ws.isAlive = false;
    ws.ping();
  }
}, HEARTBEAT_INTERVAL_MS).unref();

wss.on('close', () => clearInterval(heartbeat));

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

  // Liveness flag for the heartbeat below. A graceful close fires 'close', but an
  // ungraceful drop (browser killed, network loss, laptop sleep) sends no close
  // frame, so the socket lingers — still counted in connectionsPerIp and still
  // occupying a room slot — until the OS TCP timeout, which can be many minutes.
  // The ping/pong heartbeat detects these and terminate()s them, which fires the
  // 'close' handler and releases the per-IP count and room slot.
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

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

        case 'get-turn-credentials': {
          // Hand out TURN credentials ONLY to a socket that is actually paired
          // in a room (both peer slots filled). A lone scanner sitting in a room
          // — or anyone not in a room at all — can't farm relay credentials.
          if (!currentRoomId || !rooms.has(currentRoomId)) {
            ws.send(JSON.stringify({ type: 'turn-credentials', iceServers: STUN_FALLBACK }));
            return;
          }
          const clients = rooms.get(currentRoomId);
          pruneDeadClients(clients);
          if (!clients.includes(ws) || clients.length < MAX_PEERS) {
            ws.send(JSON.stringify({ type: 'turn-credentials', iceServers: STUN_FALLBACK }));
            return;
          }
          // Mint (cached) credentials from the ../turn service and relay them.
          getIceServers()
            .then(iceServers => {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'turn-credentials', iceServers }));
              }
            })
            .catch(() => {
              if (ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({ type: 'turn-credentials', iceServers: iceCache.iceServers || STUN_FALLBACK }));
              }
            });
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

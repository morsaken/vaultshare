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

// Remove any sockets that are no longer open, so a crashed/dropped peer doesn't
// keep occupying a slot and cause a false "Room is full" for a real peer.
function pruneDeadClients(clients) {
  for (let i = clients.length - 1; i >= 0; i--) {
    if (clients[i].readyState !== WebSocket.OPEN) {
      clients.splice(i, 1);
    }
  }
}

wss.on('connection', (ws) => {
  let currentRoomId = null;

  ws.on('message', (messageStr) => {
    try {
      const message = JSON.parse(messageStr);

      switch (message.type) {
        case 'join': {
          const { roomId } = message;

          if (!roomId || typeof roomId !== 'string') {
            ws.send(JSON.stringify({ type: 'error', message: 'Invalid room ID' }));
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

          // Notify the other peer that someone joined
          if (clients.length === MAX_PEERS) {
            const peer = clients[0] === ws ? clients[1] : clients[0];
            peer.send(JSON.stringify({ type: 'peer-joined' }));
            ws.send(JSON.stringify({ type: 'peer-joined' }));
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

          if (peer && peer.readyState === WebSocket.OPEN) {
            peer.send(JSON.stringify({ 
              type: 'signal', 
              payload: message.payload 
            }));
          }
          
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

  ws.on('close', () => {
    leaveRoom(ws, currentRoomId);
  });

  ws.on('error', (err) => {
    console.error('WebSocket client error:', err);
    leaveRoom(ws, currentRoomId);
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

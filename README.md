# VaultShare — Secure P2P File Sharing

End-to-end encrypted, peer-to-peer file transfer that runs entirely in the
browser. Files travel **directly between the two peers** over an encrypted
WebRTC data channel — they never touch the server. The Node.js server only acts
as a lightweight **signaling relay** to help the two browsers find each other.

## How it works

1. One peer **creates a room** (a 6-digit code, e.g. `529-194`); the other
   **joins** with that code.
2. The two browsers perform an **ECDH (P-256) key exchange** over the signaling
   WebSocket and derive a shared **AES-GCM-256** session key via HKDF.
3. A **security verification code** (fingerprint) is shown on both screens.
   Users confirm the codes match to rule out a man-in-the-middle. Transfers are
   **locked until both peers tick the "verified" box**.
4. A direct **WebRTC** connection is established (STUN for NAT traversal). The
   file is chunked, each chunk encrypted with AES-GCM, streamed peer-to-peer,
   and verified with a **SHA-256** checksum on arrival.

The signaling server only relays handshake messages and enforces a **2-peer
limit per room**. It never sees keys or file contents.

## Requirements

- **Node.js** >= 18
- **pnpm** (the project's package manager; pinned via `packageManager`)
- A **secure context** in the browser — the Web Crypto API only works over
  **HTTPS** or `http://localhost`. Plain `http://` on a LAN IP will not work.

## Local usage

```bash
# Install dependencies
pnpm install

# Start the server (defaults to port 3000)
pnpm start
```

Then open <http://localhost:3000> in two tabs (or two devices, see HTTPS note
below):

1. Tab A → **Generate Secret Room**, copy the room code.
2. Tab B → paste the code (with or without the dash) and **Join Room**
   (or press Enter).
3. Compare the **security verification codes** on both screens; if they match,
   tick *"I have verified the security code"* on **both** sides.
4. Drag & drop a file (or browse) and **Send Encrypted File**.

### Configuration

| Variable | Default | Description                |
| -------- | ------- | -------------------------- |
| `PORT`   | `3000`  | Port the server listens on |

```bash
PORT=8080 pnpm start
```

## Deploying on a server

The app is a single Node process serving static files **and** a WebSocket
endpoint on the same port. Put it behind a reverse proxy (nginx) that terminates
TLS — HTTPS is **required** for the Web Crypto API to function.

### 1. Get the code on the server and install

```bash
git clone <your-repo-url> /var/www/vaultshare
cd /var/www/vaultshare
pnpm install --prod
```

### 2. Run it as a service (systemd)

Create `/etc/systemd/system/vaultshare.service`:

```ini
[Unit]
Description=VaultShare signaling server
After=network.target

[Service]
Type=simple
WorkingDirectory=/var/www/vaultshare
Environment=PORT=3000
ExecStart=/usr/bin/node server.js
Restart=on-failure
User=www-data

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vaultshare
sudo systemctl status vaultshare
```

### 3. nginx reverse proxy (with WebSocket support)

The signaling uses WebSockets, so the proxy **must** forward the
`Upgrade`/`Connection` headers — otherwise the handshake fails and the
verification code never appears.

```nginx
server {
    listen 443 ssl;
    server_name share.example.com;

    ssl_certificate     /etc/letsencrypt/live/share.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/share.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;

        # --- required for WebSocket upgrade ---
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        # --------------------------------------

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout 86400;   # keep idle WS connections alive
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name share.example.com;
    return 301 https://$host$request_uri;
}
```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Get a TLS certificate with [Certbot](https://certbot.eff.org/):

```bash
sudo certbot --nginx -d share.example.com
```

### Verifying the deployment

```bash
# Should return: HTTP/1.1 101 Switching Protocols
curl -i --http1.1 \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==" \
  https://share.example.com/
```

If you get `200` + HTML instead of `101`, nginx is not proxying the WebSocket
upgrade — re-check the `proxy_http_version`/`Upgrade`/`Connection` lines above.

### Updating after a deploy

Static assets are served with `Cache-Control: no-cache`, so browsers revalidate
and pick up new client code on a normal refresh. After pulling changes:

```bash
git pull
pnpm install --prod
sudo systemctl restart vaultshare
```

## Project structure

```
server.js            # Express static server + WebSocket signaling relay
public/
  index.html         # UI
  index.js           # Client: crypto, signaling, WebRTC, file transfer
  index.css          # Styles
```

## Security notes

- All file data is end-to-end encrypted (AES-GCM-256); the server only relays
  signaling messages and cannot read keys or files.
- Always **compare the verification code** on both ends before sending — this is
  the defense against a man-in-the-middle on the signaling channel.
- Rooms are ephemeral and capped at 2 peers; nothing is persisted server-side.

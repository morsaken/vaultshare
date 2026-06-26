// --- DOM Element References ---
const connectionBadge = document.getElementById('connection-badge');
const btnCreateRoom = document.getElementById('btn-create-room');
const btnJoinRoom = document.getElementById('btn-join-room');
const inputRoomId = document.getElementById('input-room-id');
const sectionSetup = document.getElementById('section-setup');
const sectionConnection = document.getElementById('section-connection');
const displayRoomId = document.getElementById('display-room-id');
const textChannelStatus = document.getElementById('text-channel-status');
const btnLeaveRoom = document.getElementById('btn-leave-room');
const displayFingerprint = document.getElementById('display-fingerprint');
const chkVerified = document.getElementById('chk-verified');
const sectionTransfer = document.getElementById('section-transfer');
const dropzone = document.getElementById('dropzone');
const inputFile = document.getElementById('input-file');
const fileDetails = document.getElementById('file-details');
const fileList = document.getElementById('file-list');
const fileListSummary = document.getElementById('file-list-summary');
const btnClearFiles = document.getElementById('btn-clear-files');
const btnSendFile = document.getElementById('btn-send-file');
const progressContainer = document.getElementById('progress-container');
const progressStatus = document.getElementById('progress-status');
const progressPercent = document.getElementById('progress-percent');
const progressBarFill = document.getElementById('progress-bar-fill');
const progressSpeed = document.getElementById('progress-speed');
const progressEta = document.getElementById('progress-eta');
const btnClearLogs = document.getElementById('btn-clear-logs');
const logConsole = document.getElementById('log-console');

// --- State Variables ---
let ws = null;
let roomId = null;
let isInitiator = false;
let peerConnection = null;
let dataChannel = null;
let myKeyPair = null;
let peerPublicKey = null;
let aesKey = null;
let peerVerified = false;
let selectedFiles = [];

// Transfer state tracking
let startTime = 0;
let totalBytesTransferred = 0;
let expectedTotalChunks = 0;
let receivedChunks = [];
let fileMetadata = null;
let isTransferring = false;
// The file currently being streamed out (used for send-side progress/ETA).
let activeSendFile = null;
// Pending receiver reset; cleared when a back-to-back file starts arriving.
let receiverResetTimer = null;
// Serializes async processing of incoming P2P packets so handlers for
// consecutive messages don't interleave (see setupDataChannel).
let incomingQueue = Promise.resolve();

// ICE server configuration.
// STUN handles direct paths (same Wi-Fi/LAN, typical home routers). TURN (a
// relay) is needed when a peer is behind a restrictive/symmetric NAT — carrier
// CGNAT, corporate Wi-Fi, or an Android emulator's double NAT — where ICE
// otherwise stalls in "checking" and fails. TURN only relays the already
// end-to-end-encrypted packets, so it never sees keys or file contents.
// For production, run your own TURN (coturn) or use a provider, then uncomment
// and fill in below — keep this in sync with the mobile client's ICE_SERVERS.
const rtcConfig = {
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' }
    // ,{ urls: 'turn:turn.example.com:3478', username: 'YOUR_TURN_USERNAME', credential: 'YOUR_TURN_CREDENTIAL' }
  ]
};

// --- Logging Helper ---
function log(msg, type = 'system') {
  const entry = document.createElement('div');
  entry.className = `log-entry log-${type}`;
  const now = new Date().toLocaleTimeString();
  entry.innerText = `[${now}] [${type.toUpperCase()}] ${msg}`;
  logConsole.appendChild(entry);
  logConsole.scrollTop = logConsole.scrollHeight;
}

btnClearLogs.addEventListener('click', () => {
  logConsole.innerHTML = '<div class="log-entry log-system">[SYSTEM] Console cleared.</div>';
});

// --- Base64 / ArrayBuffer Helpers ---
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// --- Cryptography Manager ---
// The Web Crypto API (window.crypto.subtle) is only exposed in a "secure
// context": HTTPS pages, or http on localhost/127.0.0.1. Opening the app over
// plain http on a LAN IP (e.g. to test on a phone) leaves it undefined, which
// is the usual reason the fingerprint never appears.
function isCryptoAvailable() {
  return !!(window.crypto && window.crypto.subtle);
}

async function generateECDHKeyPair() {
  if (!isCryptoAvailable()) {
    throw new Error('Web Crypto unavailable — serve over HTTPS or via http://localhost');
  }
  log('Generating ECDH keypair (P-256 curve)...', 'crypto');
  myKeyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
  log('ECDH keypair generated successfully.', 'crypto');
}

async function deriveSessionKey(rawPeerPublicKeyBase64) {
  log('Importing peer\'s public key...', 'crypto');
  const peerPubKeyBuffer = base64ToArrayBuffer(rawPeerPublicKeyBase64);
  peerPublicKey = await window.crypto.subtle.importKey(
    'raw',
    peerPubKeyBuffer,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );

  log('Deriving shared secret from ECDH key exchange...', 'crypto');
  const sharedBits = await window.crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPublicKey },
    myKeyPair.privateKey,
    256
  );

  log('Importing shared bits into HKDF...', 'crypto');
  const hkdfKey = await window.crypto.subtle.importKey(
    'raw',
    sharedBits,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  log('Deriving 256-bit AES-GCM session key using HKDF (SHA-256)...', 'crypto');
  const salt = new Uint8Array(16); // Constant salt for single session context
  const info = new TextEncoder().encode('VaultShare Session Key');
  
  aesKey = await window.crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      salt: salt,
      info: info,
      hash: 'SHA-256'
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
  
  log('AES-GCM session key established. Encryption active!', 'crypto');
  
  // Calculate visual verification fingerprint code
  await computeFingerprint(rawPeerPublicKeyBase64);
}

async function computeFingerprint(rawPeerPublicKeyBase64) {
  const myPubRaw = await window.crypto.subtle.exportKey('raw', myKeyPair.publicKey);
  const myPubBase64 = arrayBufferToBase64(myPubRaw);
  
  // Alphabetically sort the base64 public keys to guarantee same ordering on both sides
  const sortedKeys = [myPubBase64, rawPeerPublicKeyBase64].sort().join('');
  const sortedBuffer = new TextEncoder().encode(sortedKeys);
  
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', sortedBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  
  // Group key fingerprint into readable chunks
  const groups = hashHex.match(/.{1,4}/g).slice(0, 8).join('-');
  displayFingerprint.innerText = groups;
  log(`Calculated line verification code: ${groups}`, 'crypto');
}

// Encrypt string with AES-GCM
async function encryptData(text, key) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return arrayBufferToBase64(combined);
}

// Decrypt string with AES-GCM
async function decryptData(combinedBase64, key) {
  const combined = base64ToArrayBuffer(combinedBase64);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  
  const decrypted = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  
  return new TextDecoder().decode(decrypted);
}

// --- Signaling Connection ---
function initSignaling() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}`;
  
  log(`Connecting to signaling server at ${wsUrl}...`, 'system');
  connectionBadge.className = 'badge badge-connecting';
  connectionBadge.innerText = 'Connecting...';
  
  ws = new WebSocket(wsUrl);
  
  ws.onopen = () => {
    log('Signaling server connected.', 'system');
    connectionBadge.className = 'badge badge-connected';
    connectionBadge.innerText = 'Online';
  };
  
  ws.onclose = () => {
    log('Signaling server disconnected. Reconnecting in 3s...', 'system');
    connectionBadge.className = 'badge badge-disconnected';
    connectionBadge.innerText = 'Offline';
    setTimeout(initSignaling, 3000);
  };
  
  ws.onerror = (err) => {
    log(`Signaling server error: ${err.message || 'unknown'}`, 'error');
  };
  
  ws.onmessage = async (event) => {
    try {
      const msg = JSON.parse(event.data);
      
      switch (msg.type) {
        case 'joined':
          log(`Joined room: ${msg.roomId} as peer #${msg.peerCount}`, 'p2p');
          roomId = msg.roomId;
          isInitiator = (msg.peerCount === 1);
          showConnectionUI(msg.roomId);
          break;
          
        case 'peer-joined':
          log('Peer connected to room. Initiating key exchange...', 'p2p');
          textChannelStatus.innerText = 'Performing key exchange...';
          
          // Generate key pair and send public key to peer
          await generateECDHKeyPair();
          const exportedPub = await window.crypto.subtle.exportKey('raw', myKeyPair.publicKey);
          sendSignal({ 
            type: 'ecdh-pub', 
            key: arrayBufferToBase64(exportedPub) 
          });
          break;
          
        case 'peer-left':
          log('Peer disconnected from room. Resetting connection.', 'error');
          resetConnection();
          break;
          
        case 'signal':
          await handleSignal(msg.payload);
          break;
          
        case 'error':
          log(`Server error: ${msg.message}`, 'error');
          alert(`Server error: ${msg.message}`);
          // Only tear down if we actually have an active session. Join-time
          // errors (e.g. "Room is full") happen before any connection exists,
          // so resetting would needlessly bounce the user around.
          if (roomId) {
            resetConnection();
          }
          break;
      }
    } catch (err) {
      log(`Error handling WebSocket message: ${err.message}`, 'error');
    }
  };
}

function sendWS(message) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(message));
  }
}

function sendSignal(payload) {
  sendWS({ type: 'signal', payload });
}

// Handle incoming WebRTC/ECDH signaling
async function handleSignal(payload) {
  if (payload.type === 'ecdh-pub') {
    // Key Exchange Phase
    log('Received peer\'s ECDH public key.', 'crypto');
    if (!myKeyPair) {
      // Receiver generates key pair if they haven't already
      await generateECDHKeyPair();
      const exportedPub = await window.crypto.subtle.exportKey('raw', myKeyPair.publicKey);
      sendSignal({ 
        type: 'ecdh-pub', 
        key: arrayBufferToBase64(exportedPub) 
      });
    }
    
    await deriveSessionKey(payload.key);
    textChannelStatus.innerText = 'Fingerprint code generated. Verify line security.';
    
    // Now that the line is secure, the initiator creates the WebRTC offer
    if (isInitiator) {
      log('Line secured. Initiating WebRTC peer connection...', 'p2p');
      setupWebRTC();
    }
  } else if (payload.type === 'verified' || payload.type === 'unverified') {
    // Peer announced their security-code verification state.
    peerVerified = (payload.type === 'verified');
    log(
      peerVerified
        ? 'Peer confirmed they verified the security code.'
        : 'Peer cleared their verification.',
      peerVerified ? 'success' : 'system'
    );
    refreshVerificationStatus();
    // Re-evaluate the send lock (peer state may have just unlocked/locked it).
    toggleInputStates(isTransferring);
  } else {
    // WebRTC Encrypted Handshake Phase
    if (!aesKey) {
      log('Warning: Received WebRTC signal before encryption key derived. Dropping.', 'error');
      return;
    }
    
    try {
      const decrypted = await decryptPayload(payload.data);
      
      if (decrypted.type === 'offer') {
        log('Received encrypted WebRTC offer. Configuring peer connection...', 'p2p');
        if (!peerConnection) setupWebRTC();
        
        await peerConnection.setRemoteDescription(new RTCSessionDescription(decrypted.sdp));
        log('Remote description set (offer). Creating WebRTC answer...', 'p2p');
        
        const answer = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(answer);
        
        const encryptedAnswer = await encryptPayload({ type: 'answer', sdp: answer });
        sendSignal({ type: 'webrtc-handshake', data: encryptedAnswer });
        log('Sent encrypted WebRTC answer.', 'p2p');
        
      } else if (decrypted.type === 'answer') {
        log('Received encrypted WebRTC answer. Finalizing peer connection...', 'p2p');
        await peerConnection.setRemoteDescription(new RTCSessionDescription(decrypted.sdp));
        log('Remote description set (answer). Handshake complete.', 'p2p');
        
      } else if (decrypted.type === 'candidate') {
        if (decrypted.candidate) {
          log('Received encrypted ICE candidate.', 'p2p');
          if (peerConnection) {
            await peerConnection.addIceCandidate(new RTCIceCandidate(decrypted.candidate));
          }
        }
      }
    } catch (err) {
      log(`Error processing encrypted WebRTC signal: ${err.message}`, 'error');
    }
  }
}

// Payload encryption helpers for signaling
async function encryptPayload(dataObj) {
  const jsonStr = JSON.stringify(dataObj);
  return await encryptData(jsonStr, aesKey);
}

async function decryptPayload(ciphertextBase64) {
  const jsonStr = await decryptData(ciphertextBase64, aesKey);
  return JSON.parse(jsonStr);
}

// --- WebRTC P2P Manager ---
function setupWebRTC() {
  log('Initializing RTCPeerConnection...', 'p2p');
  peerConnection = new RTCPeerConnection(rtcConfig);
  
  peerConnection.onicecandidate = async (e) => {
    if (e.candidate) {
      log('Local ICE candidate gathered. Encrypting & sending...', 'p2p');
      const encryptedCandidate = await encryptPayload({
        type: 'candidate',
        candidate: {
          candidate: e.candidate.candidate,
          sdpMid: e.candidate.sdpMid,
          sdpMLineIndex: e.candidate.sdpMLineIndex
        }
      });
      sendSignal({ type: 'webrtc-handshake', data: encryptedCandidate });
    }
  };
  
  peerConnection.oniceconnectionstatechange = () => {
    log(`ICE connection state changed: ${peerConnection.iceConnectionState}`, 'p2p');
    if (peerConnection.iceConnectionState === 'connected') {
      log('Direct WebRTC peer connection established!', 'p2p');
      textChannelStatus.innerText = 'P2P Tunnel active';
      sectionTransfer.classList.remove('hidden');
      // Start locked: the user must check the verification box before sending.
      toggleInputStates(false);
    } else if (peerConnection.iceConnectionState === 'failed' || peerConnection.iceConnectionState === 'disconnected') {
      log('WebRTC connection dropped.', 'error');
      resetConnection();
    }
  };
  
  if (isInitiator) {
    log('Creating data channel "file-transfer"...', 'p2p');
    dataChannel = peerConnection.createDataChannel('file-transfer', { ordered: true });
    setupDataChannel(dataChannel);
    
    // Create offer
    peerConnection.createOffer()
      .then(async (offer) => {
        await peerConnection.setLocalDescription(offer);
        const encryptedOffer = await encryptPayload({ type: 'offer', sdp: offer });
        sendSignal({ type: 'webrtc-handshake', data: encryptedOffer });
        log('Sent encrypted WebRTC offer.', 'p2p');
      })
      .catch((err) => {
        log(`Failed to create WebRTC offer: ${err.message}`, 'error');
      });
  } else {
    // Receiver waits for data channel event
    peerConnection.ondatachannel = (event) => {
      log('Remote data channel detected.', 'p2p');
      dataChannel = event.channel;
      setupDataChannel(dataChannel);
    };
  }
}

function setupDataChannel(channel) {
  channel.binaryType = 'arraybuffer';
  
  channel.onopen = () => {
    log('P2P Data Channel opened. Channel is ready for transmission.', 'p2p');
  };
  
  channel.onclose = () => {
    log('P2P Data Channel closed.', 'p2p');
  };
  
  // handleIncomingData is async (it awaits decrypt/hash). Without serializing,
  // the next message's handler would interleave with the current one — e.g. the
  // next file's metadata (0x01) resetting receivedChunks/fileMetadata while the
  // previous file's completion (0x04) is still hashing, causing a checksum
  // mismatch. Chain the calls so each packet is fully processed in arrival order.
  channel.onmessage = (event) => {
    // .catch keeps the queue alive if a handler ever rejects, so one bad packet
    // can't wedge processing of everything after it.
    incomingQueue = incomingQueue
      .then(() => handleIncomingData(event.data))
      .catch((err) => log(`Error processing incoming packet: ${err.message}`, 'error'));
  };
}

// --- File Encryption & Transmission Protocol ---
async function calculateSHA256(arrayBuffer) {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sendFile() {
  if (selectedFiles.length === 0 || !dataChannel || dataChannel.readyState !== 'open' || !aesKey) {
    log('Cannot send: connection not ready.', 'error');
    return;
  }

  if (!chkVerified.checked) {
    log('Send blocked: security code not verified.', 'error');
    alert('Please verify the security code with your peer before sending files.');
    return;
  }

  if (!peerVerified) {
    log('Send blocked: peer has not verified the security code.', 'error');
    alert('Your peer has not verified the security code yet. Wait until they confirm before sending.');
    return;
  }

  isTransferring = true;
  toggleInputStates(true);
  progressContainer.classList.remove('hidden');

  // Snapshot the queue so it can't change mid-transfer.
  const batch = selectedFiles.slice();
  log(`Starting transfer of ${batch.length} file(s):`, 'send');
  batch.forEach((file, i) => {
    log(`  ${i + 1}. ${file.name} (${formatFileSize(file.size)})`, 'send');
  });

  for (let f = 0; f < batch.length; f++) {
    if (!isTransferring) return; // Transfer was cancelled

    const ok = await sendSingleFile(batch[f], f, batch.length);
    if (!ok) return; // Cancelled/aborted mid-file; state already reset.
  }

  log(`All ${batch.length} file(s) transferred successfully!`, 'send');
  progressStatus.innerText = 'Transfer Complete!';

  setTimeout(() => {
    isTransferring = false;
    activeSendFile = null;
    toggleInputStates(false);
    progressContainer.classList.add('hidden');
    clearSelectedFiles();
  }, 2000);
}

// Stream a single file: metadata (0x01) -> chunks (0x02) -> complete (0x04).
// `fileIndex`/`fileCount` describe this file's place in the batch (for progress
// labels on both ends). Returns false if the transfer was cancelled/aborted.
async function sendSingleFile(file, fileIndex, fileCount) {
  activeSendFile = file;
  const batchLabel = fileCount > 1 ? `File ${fileIndex + 1}/${fileCount}: ` : '';
  // Tag every per-file log line so each file in a batch is clearly identifiable.
  const tag = `[${fileIndex + 1}/${fileCount}] ${file.name}:`;

  log(`${tag} Preparing to send (${formatFileSize(file.size)}).`, 'send');

  progressStatus.innerText = `${batchLabel}Calculating SHA-256 checksum...`;
  progressPercent.innerText = '0%';
  progressBarFill.style.width = '0%';

  const fileBytes = await file.arrayBuffer();

  log(`${tag} Generating SHA-256 checksum for integrity verification...`, 'crypto');
  const fileHash = await calculateSHA256(fileBytes);
  log(`${tag} Checksum derived: ${fileHash}`, 'crypto');

  // Header details
  const chunkSize = 60 * 1024; // 60 KB to fit within 64KB WebRTC MTU
  const totalChunks = Math.ceil(file.size / chunkSize);

  const metadata = {
    name: file.name,
    size: file.size,
    type: file.type || 'application/octet-stream',
    totalChunks,
    sha256: fileHash,
    fileIndex,
    fileCount
  };

  // Encrypt and send metadata header packet
  // Structure: [1-byte message type = 0x01] + [12-byte IV] + [ciphertext]
  log(`${tag} Sending metadata (${metadata.size} bytes) in ${totalChunks} chunks.`, 'p2p');
  progressStatus.innerText = `${batchLabel}Encrypting & sending metadata...`;

  const metadataStr = JSON.stringify(metadata);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedMeta = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(metadataStr)
  );

  const metaPacket = new Uint8Array(1 + 12 + encryptedMeta.byteLength);
  metaPacket[0] = 0x01; // type 0x01
  metaPacket.set(iv, 1);
  metaPacket.set(new Uint8Array(encryptedMeta), 13);

  dataChannel.send(metaPacket);

  // Send file chunks with backpressure
  log(`${tag} Starting chunk transmission stream...`, 'p2p');
  startTime = Date.now();
  totalBytesTransferred = 0;

  const BUFFER_THRESHOLD = 64 * 1024; // 64 KB threshold
  dataChannel.bufferedAmountLowThreshold = BUFFER_THRESHOLD;

  let offset = 0;
  for (let i = 0; i < totalChunks; i++) {
    // Backpressure check
    if (dataChannel.bufferedAmount > BUFFER_THRESHOLD) {
      await new Promise((resolve) => {
        dataChannel.onbufferedamountlow = () => {
          dataChannel.onbufferedamountlow = null;
          resolve();
        };
      });
    }

    if (!isTransferring) return false; // Transfer was cancelled

    const end = Math.min(offset + chunkSize, file.size);
    const chunkBytes = fileBytes.slice(offset, end);
    offset = end;

    // Chunk payload: [4-byte sequence index] + [data]
    const payload = new Uint8Array(4 + chunkBytes.byteLength);
    const view = new DataView(payload.buffer);
    view.setUint32(0, i);
    payload.set(new Uint8Array(chunkBytes), 4);

    // Encrypt chunk
    const chunkIv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedChunk = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: chunkIv },
      aesKey,
      payload
    );

    // Packet structure: [1-byte message type = 0x02] + [12-byte IV] + [ciphertext]
    const packet = new Uint8Array(1 + 12 + encryptedChunk.byteLength);
    packet[0] = 0x02; // type 0x02
    packet.set(chunkIv, 1);
    packet.set(new Uint8Array(encryptedChunk), 13);

    dataChannel.send(packet);
    totalBytesTransferred += chunkBytes.byteLength;

    updateProgress(i + 1, totalChunks, `${batchLabel}Uploading`);
  }

  // Complete message
  log(`${tag} Stream finished. Sending finalization trigger.`, 'p2p');
  const completeIv = window.crypto.getRandomValues(new Uint8Array(12));
  const encryptedComplete = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: completeIv },
    aesKey,
    new TextEncoder().encode('complete')
  );
  const completePacket = new Uint8Array(1 + 12 + encryptedComplete.byteLength);
  completePacket[0] = 0x04; // type 0x04
  completePacket.set(completeIv, 1);
  completePacket.set(new Uint8Array(encryptedComplete), 13);

  dataChannel.send(completePacket);

  log(`${tag} Transfer completed successfully!`, 'send');
  return true;
}

// Send a small encrypted control message over the data channel.
// Used for out-of-band signals like "I haven't verified the code yet".
async function sendDataChannelControl(typeByte, text) {
  if (!dataChannel || dataChannel.readyState !== 'open' || !aesKey) return;

  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    new TextEncoder().encode(text)
  );

  const packet = new Uint8Array(1 + 12 + encrypted.byteLength);
  packet[0] = typeByte;
  packet.set(iv, 1);
  packet.set(new Uint8Array(encrypted), 13);
  dataChannel.send(packet);
}

// Receive and decrypt data chunks
async function handleIncomingData(arrayBuffer) {
  const view = new Uint8Array(arrayBuffer);
  const type = view[0];
  const iv = view.slice(1, 13);
  const ciphertext = view.slice(13);
  
  if (!aesKey) {
    log('Security Error: Received P2P packet but line is not encrypted.', 'error');
    return;
  }

  if (!chkVerified.checked) {
    // Only act once (on the metadata packet) so chunks don't spam the log/peer.
    if (type === 0x01) {
      log('Incoming file blocked: verify the security code first to receive files.', 'error');
      alert('A peer is trying to send you a file. Verify the security code to receive it.');
      // Tell the sender to stop — we won't accept data over an unverified channel.
      sendDataChannelControl(0x05, 'unverified');
    }
    return;
  }

  try {
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      ciphertext
    );
    
    if (type === 0x01) {
      // File Metadata. A new file may begin before the previous file's 2s
      // cleanup timer fires, so cancel that pending reset to avoid it wiping
      // the incoming transfer's state.
      if (receiverResetTimer !== null) {
        clearTimeout(receiverResetTimer);
        receiverResetTimer = null;
      }

      const metaStr = new TextDecoder().decode(decrypted);
      fileMetadata = JSON.parse(metaStr);

      log(`${recvTag()} Receiving "${fileMetadata.name}" (${fileMetadata.size} bytes) in ${fileMetadata.totalChunks} chunks.`, 'p2p');
      log(`${recvTag()} Peer's file SHA-256 checksum: ${fileMetadata.sha256}`, 'crypto');

      expectedTotalChunks = fileMetadata.totalChunks;
      receivedChunks = new Array(expectedTotalChunks);
      totalBytesTransferred = 0;
      startTime = Date.now();
      isTransferring = true;
      toggleInputStates(true);

      progressContainer.classList.remove('hidden');
      updateProgress(0, expectedTotalChunks, receiveLabel());
      
    } else if (type === 0x02) {
      // File Chunk
      const payloadView = new Uint8Array(decrypted);
      const dataView = new DataView(decrypted);
      const chunkIndex = dataView.getUint32(0);
      const chunkData = payloadView.slice(4);
      
      receivedChunks[chunkIndex] = chunkData;
      totalBytesTransferred += chunkData.byteLength;
      
      const chunksLoaded = receivedChunks.filter(c => c !== undefined).length;
      updateProgress(chunksLoaded, expectedTotalChunks, receiveLabel());
      
    } else if (type === 0x04) {
      // File Transfer Complete
      const tag = recvTag();
      log(`${tag} Finalization received. Reassembling "${fileMetadata.name}"...`, 'p2p');
      progressStatus.innerText = 'Reassembling and verifying file...';

      // Ensure we have all chunks
      const missingChunks = [];
      for (let i = 0; i < expectedTotalChunks; i++) {
        if (!receivedChunks[i]) missingChunks.push(i);
      }

      if (missingChunks.length > 0) {
        log(`${tag} Security/Transfer Error: Missing ${missingChunks.length} chunks. Download aborted.`, 'error');
        resetTransferState();
        return;
      }

      const fileBlob = new Blob(receivedChunks, { type: fileMetadata.type });
      const assembledBuffer = await fileBlob.arrayBuffer();

      log(`${tag} Running integrity validation...`, 'crypto');
      const receivedHash = await calculateSHA256(assembledBuffer);
      log(`${tag} Derived checksum: ${receivedHash}`, 'crypto');

      if (receivedHash !== fileMetadata.sha256) {
        log(`${tag} Security Integrity Error: Checksum mismatch! File altered or corrupted.`, 'error');
        alert(`Security Integrity Error: Checksum mismatch on "${fileMetadata.name}"! Transfer aborted.`);
      } else {
        log(`${tag} Integrity verified! File hash matches peer hash perfectly.`, 'success');

        // Trigger save download
        const url = URL.createObjectURL(fileBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = fileMetadata.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        log(`${tag} Successfully downloaded and saved: ${fileMetadata.name}`, 'recv');
        progressStatus.innerText = 'Download Successful!';
      }

      // Delay cleanup so the user sees the result; if another file in the batch
      // arrives first, its 0x01 handler cancels this timer (see above).
      receiverResetTimer = setTimeout(() => {
        receiverResetTimer = null;
        resetTransferState();
      }, 2000);

    } else if (type === 0x05) {
      // Peer signalled they have not verified the security code. Abort our send.
      // resetTransferState() flips isTransferring off, which halts the send loop.
      log('Peer has not verified the security code. Transfer aborted.', 'error');
      alert('Your peer has not verified the security code yet. Transfer aborted — ask them to verify, then send again.');
      resetTransferState();
    }
  } catch (err) {
    log(`Crypto decryption error during transfer: ${err.message}`, 'error');
    resetTransferState();
  }
}

// Build the receive-side progress label, including batch position when the
// peer is sending more than one file.
function receiveLabel() {
  if (fileMetadata && fileMetadata.fileCount > 1) {
    return `File ${fileMetadata.fileIndex + 1}/${fileMetadata.fileCount}: Downloading`;
  }
  return 'Downloading';
}

// Per-file log prefix for the receive side, e.g. "[2/3] report.pdf:".
function recvTag() {
  if (!fileMetadata) return '';
  const pos = `${(fileMetadata.fileIndex ?? 0) + 1}/${fileMetadata.fileCount ?? 1}`;
  return `[${pos}] ${fileMetadata.name}:`;
}

// Progress metrics updater
function updateProgress(chunksLoaded, totalChunks, label = 'Transferring') {
  const percent = Math.round((chunksLoaded / totalChunks) * 100);
  progressPercent.innerText = `${percent}%`;
  progressBarFill.style.width = `${percent}%`;
  
  const elapsed = (Date.now() - startTime) / 1000;
  if (elapsed > 0) {
    const bytesPerSec = totalBytesTransferred / elapsed;
    let speedText = '';
    if (bytesPerSec > 1024 * 1024) {
      speedText = `${(bytesPerSec / (1024 * 1024)).toFixed(2)} MB/s`;
    } else {
      speedText = `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
    }
    progressSpeed.innerText = speedText;
    
    const fileTotalSize = fileMetadata ? fileMetadata.size : (activeSendFile ? activeSendFile.size : 0);
    const bytesRemaining = fileTotalSize - totalBytesTransferred;
    if (bytesPerSec > 0 && bytesRemaining > 0) {
      const eta = Math.round(bytesRemaining / bytesPerSec);
      progressEta.innerText = `Remaining: ${eta}s`;
    } else {
      progressEta.innerText = 'Remaining: 0s';
    }
  }
  
  progressStatus.innerText = `${label} (${chunksLoaded}/${totalChunks} blocks)...`;
}

function resetTransferState() {
  isTransferring = false;
  activeSendFile = null;
  if (receiverResetTimer !== null) {
    clearTimeout(receiverResetTimer);
    receiverResetTimer = null;
  }
  toggleInputStates(false);
  progressContainer.classList.add('hidden');
  receivedChunks = [];
  fileMetadata = null;
  expectedTotalChunks = 0;
  clearSelectedFiles();
}

// --- UI Event Listeners & State Controls ---
// Canonicalize a room ID so it matches regardless of how the user typed it.
// Generated codes look like "529-194"; a user may enter "529194", "529 194",
// etc. A 6-digit code is normalized to "XXX-XXX"; any other value is left as-is
// (just trimmed) so custom room names still work.
function normalizeRoomId(raw) {
  const trimmed = (raw || '').trim();
  const digits = trimmed.replace(/\D/g, '');
  if (/^\d{6}$/.test(digits)) {
    return `${digits.slice(0, 3)}-${digits.slice(3)}`;
  }
  return trimmed;
}

btnCreateRoom.addEventListener('click', () => {
  // Generate random room code
  const code = Math.floor(100000 + Math.random() * 900000);
  const formattedCode = `${String(code).slice(0, 3)}-${String(code).slice(3)}`;

  log(`Requesting connection to room: ${formattedCode}...`, 'system');
  sendWS({ type: 'join', roomId: formattedCode });
});

btnJoinRoom.addEventListener('click', () => {
  const val = normalizeRoomId(inputRoomId.value);
  if (!val) {
    alert('Please enter a valid Room ID.');
    return;
  }
  // Reflect the canonical form back to the user so it's clear what they joined.
  inputRoomId.value = val;
  sendWS({ type: 'join', roomId: val });
});

// Auto-mask the Room ID into the "000-000" format as the user types: keep only
// digits, cap at 6, and drop in the hyphen after the third one.
inputRoomId.addEventListener('input', () => {
  const digits = inputRoomId.value.replace(/\D/g, '').slice(0, 6);
  inputRoomId.value = digits.length > 3
    ? `${digits.slice(0, 3)}-${digits.slice(3)}`
    : digits;
});

// Pressing Enter in the Room ID field joins, same as clicking the button.
inputRoomId.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    btnJoinRoom.click();
  }
});

btnLeaveRoom.addEventListener('click', () => {
  if (confirm('Disconnect from current secure room?')) {
    resetConnection();
  }
});

chkVerified.addEventListener('change', () => {
  if (chkVerified.checked) {
    log('Security code verified. Notifying peer...', 'success');
  } else {
    log('Verification cleared. Notifying peer...', 'system');
  }
  // Announce our verification state to the peer over the signaling channel.
  sendSignal({ type: chkVerified.checked ? 'verified' : 'unverified' });
  refreshVerificationStatus();
  // Re-apply lock state (keep everything disabled if a transfer is in flight).
  toggleInputStates(isTransferring);
});

// Reflect the combined (local + peer) verification state in the channel status.
function refreshVerificationStatus() {
  if (!aesKey) return;
  if (chkVerified.checked && peerVerified) {
    textChannelStatus.innerText = 'Both peers verified — secure transfer ready.';
  } else if (chkVerified.checked && !peerVerified) {
    textChannelStatus.innerText = 'Waiting for peer to verify the security code...';
  } else if (!chkVerified.checked && peerVerified) {
    textChannelStatus.innerText = 'Peer verified. Confirm the code to enable transfers.';
  } else {
    textChannelStatus.innerText = 'Verify the security code on both clients to continue.';
  }
}

function showConnectionUI(room) {
  displayRoomId.innerText = room;
  sectionSetup.classList.add('hidden');
  sectionConnection.classList.remove('hidden');
  chkVerified.checked = false;
  peerVerified = false;
  // Key exchange (and the fingerprint) only starts once a second peer joins.
  textChannelStatus.innerText = 'Waiting for the other peer to join this room...';
}

function toggleInputStates(disable) {
  btnLeaveRoom.disabled = disable;
  chkVerified.disabled = disable;
  btnClearFiles.disabled = disable;

  // File sending is locked while transferring OR until BOTH peers have confirmed
  // the security code, to prevent transfers over an unverified channel.
  const lock = disable || !chkVerified.checked || !peerVerified;
  dropzone.style.pointerEvents = lock ? 'none' : 'auto';
  dropzone.style.opacity = lock ? '0.5' : '1';
  btnSendFile.disabled = lock;
}

function resetConnection() {
  log('Closing connection. Resetting cryptographic state...', 'system');

  // Tell the signaling server we're leaving so it removes us from the room.
  // Otherwise the server still considers us a member: a reconnecting peer would
  // be paired with our stale slot, and our next join would fire a spurious
  // "peer-left" at the other side (client/server desync). Harmless if we weren't
  // in a room — the server's leave handler is a no-op then.
  sendWS({ type: 'leave' });

  if (peerConnection) {
    peerConnection.close();
    peerConnection = null;
  }
  if (dataChannel) {
    dataChannel.close();
    dataChannel = null;
  }

  // Wipe all cryptographic material and session identity so nothing carries
  // over into the next room/peer.
  myKeyPair = null;
  peerPublicKey = null;
  aesKey = null;
  isInitiator = false;
  roomId = null;
  peerVerified = false;

  // Drop any in-flight packet processing chain.
  incomingQueue = Promise.resolve();

  // Wipe transfer/receiver state (received plaintext chunks, metadata,
  // pending timers, selected files, progress bar).
  resetTransferState();

  // Reset the UI back to a clean, unverified state.
  displayRoomId.innerText = '---';
  displayFingerprint.innerText = '---';
  textChannelStatus.innerText = 'Securing connection...';
  chkVerified.checked = false;

  sectionConnection.classList.add('hidden');
  sectionTransfer.classList.add('hidden');
  sectionSetup.classList.remove('hidden');
}

// Drag & Drop File Handling
dropzone.addEventListener('click', () => inputFile.click());

dropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropzone.classList.add('dragover');
});

dropzone.addEventListener('dragleave', () => {
  dropzone.classList.remove('dragover');
});

dropzone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropzone.classList.remove('dragover');
  if (e.dataTransfer.files.length > 0) {
    handleFilesSelect(e.dataTransfer.files);
  }
});

inputFile.addEventListener('change', () => {
  if (inputFile.files.length > 0) {
    handleFilesSelect(inputFile.files);
  }
  // Allow re-selecting the same file(s) after clearing.
  inputFile.value = '';
});

function formatFileSize(bytes) {
  if (bytes > 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
  return `${(bytes / 1024).toFixed(1)} KB`;
}

// Append the chosen files to the queue, skipping exact duplicates (same name +
// size) so re-dropping doesn't double them up.
function handleFilesSelect(fileList) {
  let added = 0;
  for (const file of fileList) {
    const dupe = selectedFiles.some(f => f.name === file.name && f.size === file.size);
    if (dupe) continue;
    selectedFiles.push(file);
    added++;
    log(`Selected local file for transfer: ${file.name} (${formatFileSize(file.size)})`, 'system');
  }
  if (added > 0) renderFileList();
}

function renderFileList() {
  fileList.innerHTML = '';

  if (selectedFiles.length === 0) {
    fileDetails.classList.add('hidden');
    return;
  }

  const totalBytes = selectedFiles.reduce((sum, f) => sum + f.size, 0);
  fileListSummary.innerText =
    `${selectedFiles.length} file${selectedFiles.length === 1 ? '' : 's'} selected · ${formatFileSize(totalBytes)}`;

  selectedFiles.forEach((file, index) => {
    const row = document.createElement('div');
    row.className = 'file-info-row';
    row.innerHTML = `
      <div class="file-info-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>
          <polyline points="13 2 13 9 20 9"/>
        </svg>
      </div>
      <div class="file-info-text">
        <div class="file-name"></div>
        <div class="file-size"></div>
      </div>
      <button class="btn-close" type="button" aria-label="Remove file">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="18"/>
        </svg>
      </button>`;
    row.querySelector('.file-name').innerText = file.name;
    row.querySelector('.file-size').innerText = formatFileSize(file.size);
    row.querySelector('.btn-close').addEventListener('click', () => removeFile(index));
    fileList.appendChild(row);
  });

  fileDetails.classList.remove('hidden');
}

function removeFile(index) {
  // Don't allow editing the queue mid-transfer.
  if (isTransferring) return;
  selectedFiles.splice(index, 1);
  renderFileList();
}

btnClearFiles.addEventListener('click', clearSelectedFiles);

function clearSelectedFiles() {
  selectedFiles = [];
  inputFile.value = '';
  fileList.innerHTML = '';
  fileDetails.classList.add('hidden');
}

btnSendFile.addEventListener('click', sendFile);

// Initialize Client
window.addEventListener('DOMContentLoaded', () => {
  if (!isCryptoAvailable()) {
    const msg = 'Encryption unavailable: this app must be opened over HTTPS or via http://localhost. '
      + 'If you are testing across devices on a LAN IP, the browser disables the Web Crypto API on insecure origins, '
      + 'so the security code cannot be generated.';
    log(msg, 'error');
    alert(msg);
    btnCreateRoom.disabled = true;
    btnJoinRoom.disabled = true;
    return;
  }
  initSignaling();
});

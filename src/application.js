

const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync, spawn, exec } = require('child_process');
const https = require('https');
const http = require('http');
const { config } = require('../lib/config');
const { ApplicationLogger } = require('../lib/logger');
const { TransferManager } = require('../lib/transfer-manager');
const { decodeBase64, normalizeFileName, sanitizeUsernameForPath } = require('../lib/validators');
const { createSamSession: createSamSessionProtocol, destinationToBase32 } = require('../lib/i2p-sam');
const { connectSocks5: connectSocks5Protocol } = require('../lib/socks5');

const PROJECT_ROOT = path.join(__dirname, '..');

// Per-start security token injected into the HTML.
let WEB_SESSION_TOKEN = null;

const UI_PORT = config.uiPort;
const PUBLIC_DIR = config.publicDir;
const RECEIVED_DIR = config.receivedDir;
const LOG_FILE = config.logFile;
const MAX_UPLOAD_BYTES = config.maxUploadBytes;
const AUTH_SERVER_URL = config.auth.url;
const AUTH_USE_HTTP = config.auth.useHttp;
const AUTH_HOST = config.auth.host;
const AUTH_PORT_UI = config.auth.port;
const AUTH_PATH = config.auth.path;
const AUTH_IS_HTTPS = config.auth.isHttps;
const LISTEN_PORT = config.i2p.listenPort;
const LOG_MAX = 500;

function getReceivedDirForUsername(username) {
  const safeUser = sanitizeUsernameForPath(username);
  if (!safeUser) return RECEIVED_DIR;
  return path.join(RECEIVED_DIR, safeUser);
}

function getCurrentUserReceivedDir() {
  return getReceivedDirForUsername(webState.username);
}

const I2P_CONFIG = {
  samHost: config.i2p.samHost,
  samPort: config.i2p.samPort,
  socksHost: config.i2p.socksHost,
  socksPort: config.i2p.socksPort
};

// Globale status voor I2P verbinding
const i2pState = {
  status: 'offline', // 'offline', 'starting', 'online', 'error'
  address: null,
  samSocket: null,
  sessionID: null,
  error: null
};

/**
 * Beslist of een verbinding met de central server rechtstreeks of via de SOCKS5 proxy (indien I2P host) verloopt.
 */
function connectToAuthServer(authHost, authPort, callback) {
  if (authHost.endsWith('.i2p')) {
    webLog(`[Verbinding] Routeren van auth server verzoek via SOCKS5 proxy...`);
    connectSocks5(I2P_CONFIG.socksHost, I2P_CONFIG.socksPort, authHost, 80, callback);
  } else {
    const errorHandler = err => {
      callback(err);
    };
    const socket = net.connect({ host: authHost, port: parseInt(authPort, 10) }, () => {
      socket.removeListener('error', errorHandler);
      callback(null, socket);
    });
    socket.on('error', errorHandler);
  }
}

/**
 * Verstuurt een auth-verzoek naar de centrale server via HTTP(S) of legacy TCP JSON-lijnprotocol.
 */
function sendAuthRequest(payload, callback, authHost = AUTH_HOST, authPort = AUTH_PORT_UI) {
  if (AUTH_USE_HTTP) {
    const transport = AUTH_IS_HTTPS ? https : http;
    const requestData = JSON.stringify(payload);
    const primaryHost = authHost || AUTH_HOST;
    const fallbackHost = primaryHost.startsWith('www.') ? primaryHost : `www.${primaryHost}`;

    let completed = false;
    let triedFallback = false;
    let attempts = 0;
    const maxAttempts = 3;

    const finish = (err, parsed) => {
      if (completed) return;
      completed = true;
      callback(err, parsed);
    };

    const makeRequest = (hostname) => {
      attempts++;
      const req = transport.request({
        hostname,
        port: authPort,
        path: AUTH_PATH,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(requestData),
          'Accept': 'application/json'
        },
        timeout: 8000 // 8 seconden timeout
      }, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk.toString());
        res.on('end', () => {
          const contentType = String(res.headers['content-type'] || '').toLowerCase();
          const trimmedBody = body.trim();

          // Sommige gratis hosts (o.a. InfinityFree) geven een JS anti-bot challenge
          // terug i.p.v. JSON voor server-to-server requests.
          if (contentType.includes('text/html') || trimmedBody.startsWith('<')) {
            if (trimmedBody.includes('__test=') || trimmedBody.includes('slowAES.decrypt') || trimmedBody.includes('enable Javascript')) {
              finish(new Error('Auth server wordt afgeschermd door anti-bot HTML challenge (geen JSON API-respons). Gebruik hosting zonder JS challenge voor API-verkeer.'));
              return;
            }
          }

          try {
            const parsed = JSON.parse(trimmedBody);
            finish(null, parsed);
          } catch {
            const preview = trimmedBody.slice(0, 140).replace(/\s+/g, ' ');
            finish(new Error(`Ongeldig JSON-antwoord van auth server (HTTP ${res.statusCode || 'n/a'}, content-type: ${contentType || 'onbekend'}, body: ${preview})`));
          }
        });
      });

      req.on('timeout', () => {
        req.destroy(new Error('ETIMEDOUT'));
      });

      req.on('error', (err) => {
        const isDnsErr = err && (
          err.code === 'ENOTFOUND' ||
          err.code === 'EAI_AGAIN' ||
          (err.errors && err.errors.some(e => e.code === 'ENOTFOUND' || e.code === 'EAI_AGAIN')) ||
          String(err.message || '').includes('ENOTFOUND') ||
          String(err.message || '').includes('EAI_AGAIN') ||
          String(err.name || '').includes('AggregateError')
        );

        if (!triedFallback && isDnsErr && hostname === primaryHost && fallbackHost !== primaryHost) {
          triedFallback = true;
          webLog(`[Auth] DNS lookup mislukt. Herproberen...`);
          makeRequest(fallbackHost);
          return;
        }

        if (attempts < maxAttempts) {
          const delay = 500 * attempts;
          webLog(`[Auth] Netwerkfout (${err.message || err.code || 'onbekend'}). Herproberen (${attempts}/${maxAttempts}) over ${delay}ms...`);
          setTimeout(() => {
            makeRequest(hostname);
          }, delay);
          return;
        }

        finish(err);
      });

      req.write(requestData);
      req.end();
    };

    makeRequest(primaryHost);
    return;
  }

  let tcpAttempts = 0;
  const maxTcpAttempts = 3;

  const tryTcpConnect = () => {
    tcpAttempts++;
    connectToAuthServer(authHost, authPort, (err, client) => {
      if (err) {
        if (tcpAttempts < maxTcpAttempts) {
          const delay = 500 * tcpAttempts;
          webLog(`[Auth] TCP verbinding mislukt. Herproberen (${tcpAttempts}/${maxTcpAttempts}) over ${delay}ms...`);
          setTimeout(tryTcpConnect, delay);
          return;
        }
        callback(err);
        return;
      }

      client.write(JSON.stringify(payload) + '\n');

      let buffer = Buffer.alloc(0);
      let answered = false;

      client.on('data', data => {
        if (answered) return;
        buffer = Buffer.concat([buffer, data]);
        const nl = buffer.indexOf(10);
        if (nl === -1) return;

        answered = true;
        const line = buffer.slice(0, nl).toString().trim();
        try {
          callback(null, JSON.parse(line));
        } catch {
          callback(new Error('Ongeldige JSON-reactie van server'));
        }
        client.destroy();
      });

      client.on('error', e => {
        if (answered) return;
        answered = true;
        callback(e);
      });
    });
  };

  tryTcpConnect();
}

/**
 * Koppel een I2P Base32-adres aan de actieve sessie op de central directory server.
 */
function updateAddressOnCentralServer(sessionToken, address, callback) {
  sendAuthRequest({
    action: 'update_address',
    session_token: sessionToken,
    address: address
  }, (err, res) => {
    if (err) {
      webLog(`[I2P Manager] Netwerkfout bij adres registratie: ${err.message}`);
      if (callback) callback(err);
      return;
    }

    if (res.status === 'success') {
      webLog(`[I2P Manager] Adres succesvol geregistreerd op directory server: ${address}`);
      if (callback) callback(null);
    } else {
      webLog(`[I2P Manager] Adres registratie mislukt: ${res.message}`);
      if (callback) callback(new Error(res.message || 'Onbekende auth server fout'));
    }
  });
}

/**
 * Bootst I2P op in de achtergrond en luistert naar inkomende verbindingen.
 */
function bootI2P() {
  i2pState.status = 'starting';
  webLog('[I2P Manager] Achtergrond-opstart van I2P gestart...');
  checkAndInstallI2P((i2pErr) => {
    if (i2pErr) {
      i2pState.status = 'error';
      i2pState.error = i2pErr.message;
      webLog(`[I2P Manager] I2P startfout: ${i2pErr.message}`);
      return;
    }
    
    webLog('[I2P Manager] SAM Bridge gedetecteerd. Initialiseren van SAM stream sessie...');
    createSamSession((err, sessionID, base64Destination, samSocket) => {
      if (err) {
        i2pState.status = 'error';
        i2pState.error = err.message;
        webLog(`[I2P Manager] Initialisatie SAM Bridge mislukt: ${err.message}`);
        return;
      }
      
      i2pState.status = 'online';
      i2pState.address = destinationToBase32(base64Destination);
      i2pState.sessionID = sessionID;
      i2pState.samSocket = samSocket;
      webLog(`[I2P Manager] I2P is ONLINE. Base32 adres: ${i2pState.address}`);
      
      // Start de ontvanger luister-tunnel direct
      startReceiver(
        null, null, LISTEN_PORT,
        AUTH_HOST, AUTH_PORT_UI,
        i2pState.address, i2pState.sessionID,
        false, onIncomingTransferUI
      );
      
      // Indien de gebruiker al is ingelogd, registreer direct het adres bij de auth server!
      if (webState.isOnline && webState.authToken) {
        webState.myBase32Address = i2pState.address;
        updateAddressOnCentralServer(webState.authToken, i2pState.address);
      }
    });
  });
}

// Start direct de Web UI bij opstarten
if (require.main === module) {
  startWebUI();
}


/**
 * Logt in bij de PHP server en registreert ons anonieme I2P adres of IP:poort.
 */
function login(username, password, address, authHost, authPort, callback) {
  sendAuthRequest({
    action: 'login',
    username: username,
    password: password,
    address: address
  }, (err, res) => {
    if (err) {
      return callback(new Error('Kan geen verbinding maken met authenticatieserver: ' + err.message));
    }

    if (res.status === 'success') {
      callback(null, res.session_token);
    } else {
      callback(new Error(res.message || 'Ongeldige auth server respons'));
    }
  }, authHost, authPort);
}

/**
 * Zoekt de I2P bestemming of IP-locatie van een online peer op.
 */
function lookup(sessionToken, targetUsername, authHost, authPort, callback) {
  sendAuthRequest({
    action: 'lookup',
    session_token: sessionToken,
    target: targetUsername
  }, (err, res) => {
    if (err) {
      return callback(err);
    }

    if (res.status === 'success') {
      callback(null, res.address);
    } else {
      callback(new Error(res.message || 'Lookup mislukt'));
    }
  }, authHost, authPort);
}

/**
 * Native SOCKS5 client om anoniem te verbinden via de I2P SOCKS5 proxy.
 */
function connectSocks5(socksHost, socksPort, targetHost, targetPort, callback) {
  connectSocks5Protocol({
    host: socksHost,
    port: socksPort,
    timeout: config.socketTimeout,
  }, {
    host: targetHost,
    port: targetPort,
  }, callback);
}

/**
 * Maakt een anonieme I2P SAM Bridge tunnel en geeft ons Base32 adres terug.
 */
function createSamSession(callback) {
  createSamSessionProtocol({
    host: I2P_CONFIG.samHost,
    port: I2P_CONFIG.samPort,
  }, (error, session) => {
    if (error) {
      callback(error);
      return;
    }
    callback(null, session.sessionId, session.destination, session.socket);
  });
}

/**
 * Start de ontvanger node. Kan direct luisteren op TCP of via de I2P SAM Bridge.
 */
function startReceiver(myUsername, sessionToken, myPort, authHost, authPort, base32Address, samSessionID, isMulti = false, onIncomingTransfer = null) {
  const activeReceiverSockets = new Set();
  const maxConcurrentReceives = 8;

  // Functie die inkomende P2P sockets afhandelt (ongeacht TCP of I2P)
  function behandelP2PVerbinding(socket) {
    if (activeReceiverSockets.size >= maxConcurrentReceives) {
      console.error('[P2P Ontvanger] Maximum aantal gelijktijdige verbindingen bereikt.');
      socket.destroy();
      return;
    }
    activeReceiverSockets.add(socket);
    socket.once('close', () => activeReceiverSockets.delete(socket));
    console.log('\n[P2P Ontvanger] Inkomende P2P-verbinding geaccepteerd.');
    
    let transferDone = false;

    // Direct foutafhandeling registreren om uncaught exception crashes te voorkomen
    socket.on('error', err => {
      if (transferDone && (err.code === 'ECONNRESET' || err.code === 'EPIPE')) {
        return; // Ignore normal socket teardown errors after completion
      }
      console.error('[P2P Ontvanger] Socketfout:', err.message);
    });

    socket.pause();

    // Beveiliging: Voorkom hangende connecties (Slowloris/inactiviteit)
    socket.setTimeout(config.socketTimeout);
    socket.on('timeout', () => {
      console.error('[P2P Ontvanger] Connectie gesloten wegens inactiviteit (timeout).');
      socket.destroy();
      cleanup();
    });

    let buffer = Buffer.alloc(0);
    let state = 'WAITING_HANDSHAKE';
    let sessionKey = null;
    let fileInfo = null;
    let expectedSha256 = null;
    let tempPath = null;
    let writeStream = null;
    let receivedBytes = 0;
    let privateKey = null;
    let publicKey = null;
    const hashSum = crypto.createHash('sha256');

    // Genereer lokaal een EPHEMERAL RSA-2048 sleutelpaar per verbinding asynchroon (Perfect Forward Secrecy)
    crypto.generateKeyPair('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    }, (err, pubK, privK) => {
      if (err) {
        console.error('[P2P Ontvanger] Fout bij genereren ephemeral sleutels:', err.message);
        socket.destroy();
        return;
      }
      publicKey = pubK;
      privateKey = privK;

      // Stuur direct de openbare RSA-sleutel naar de verzender
      socket.write(publicKey);
      socket.resume();

      socket.on('data', dataBlok => {
        // Beveiliging: Voorkom bufferuitputting / RAM-aanval
        if (state === 'WAITING_HANDSHAKE' && buffer.length + dataBlok.length > 4096) {
          console.error('[P2P Ontvanger] Handshake buffer limiet (4KB) overschreden. Connectie afgebroken.');
          socket.end('FOUT: Handshake buffer limiet overschreden\n');
          return;
        }

        // Beveiliging: Voorkom bufferuitputting / memory exhaustion tijdens streaming (max 256KB in queue)
        if (buffer.length + dataBlok.length > 256 * 1024) {
          console.error('[P2P Ontvanger] Streaming buffer limiet (256KB) overschreden. Connectie afgebroken.');
          socket.destroy();
          return;
        }

        buffer = Buffer.concat([buffer, dataBlok]);

        if (state === 'WAITING_HANDSHAKE') {
          // Handshake packet structuur:
          // [4 bytes env1Len] + [4 bytes metadataLen] + [env1] + [12 bytes nonce] + [16 bytes tag] + [encrypted metadata]
          if (buffer.length < 8) return;

          const env1Len = buffer.readUInt32BE(0);
          const metadataLen = buffer.readUInt32BE(4);

          // Beveiliging: Sanity check op de envelop- en metadatalengte om hackers direct te blokkeren
          if (env1Len !== 256 || metadataLen <= 0 || metadataLen > 1024) {
            console.error('[P2P Ontvanger] Ongeldige handshake header parameters gedetecteerd. Connectie direct verbroken.');
            socket.destroy();
            return;
          }

          const packetSize = 8 + env1Len + 12 + 16 + metadataLen;

          if (buffer.length < packetSize) return;

          const envelope1 = buffer.slice(8, 8 + env1Len);
          const nonce = buffer.slice(8 + env1Len, 8 + env1Len + 12);
          const tag = buffer.slice(8 + env1Len + 12, 8 + env1Len + 28);
          const ciphertext = buffer.slice(8 + env1Len + 28, packetSize);

          // Haal restant uit buffer
          buffer = buffer.slice(packetSize);

          // 1. Decrypt 1e envelop om ChaCha20-Poly1305 sleutel te herstellen
          try {
            sessionKey = crypto.privateDecrypt({
              key: privateKey,
              padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
              oaepHash: 'sha256'
            }, envelope1);

            if (sessionKey.length !== 32) throw new Error('Foutieve symmetrische sleutellengte');
          } catch (err) {
            console.error('[P2P Ontvanger] Decryptie van 1e envelop mislukt:', err.message);
            socket.end('FOUT: RSA decodering mislukt\n');
            return;
          }

          // 2. Decrypt de metadata handshake met ChaCha20-Poly1305
          try {
            const decipher = crypto.createDecipheriv('chacha20-poly1305', sessionKey, nonce, { authTagLength: 16 });
            decipher.setAuthTag(tag);
            const decryptedMetadata = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

            fileInfo = JSON.parse(decryptedMetadata.toString());
          } catch (err) {
            console.error('[P2P Ontvanger] Decryptie van metadata handshake mislukt:', err.message);
            socket.end('FOUT: Metadata handdruk corrupt\n');
            return;
          }

          if (!fileInfo.username || !fileInfo.filename || !fileInfo.file_size || !fileInfo.session_token) {
            socket.end('FOUT: Incomplete metadata\n');
            return;
          }

          // Beveiliging: file_size parameter validatie (positive integer)
          if (!Number.isInteger(fileInfo.file_size) || fileInfo.file_size <= 0 || fileInfo.file_size > MAX_UPLOAD_BYTES) {
            console.error(`[P2P Ontvanger] Ongeldige bestandsgrootte gedetecteerd: ${fileInfo.file_size}`);
            socket.end(`FOUT: Bestandsgrootte moet tussen 1 en ${MAX_UPLOAD_BYTES} bytes liggen\n`);
            return;
          }

          // Beveiliging: Strict bestandsnaam validatie (directory traversal & Alternate Data Streams)
          const veiligeNaam = path.basename(fileInfo.filename);
          if (veiligeNaam !== fileInfo.filename || veiligeNaam.includes('..') ||
            fileInfo.filename.includes('/') || fileInfo.filename.includes('\\') ||
            !/^[a-zA-Z0-9_\-\. ]+$/.test(veiligeNaam)) {
            console.error(`[P2P Ontvanger] Onveilige bestandsnaam gedetecteerd: ${fileInfo.filename}`);
            socket.end('FOUT: Onveilige bestandsnaam. Alleen letters, cijfers, underscores (_), streepjes (-), punten (.) en spaties zijn toegestaan.\n');
            return;
          }

          // Asynchroon de afzender verifiëren bij de centrale server (Pre-Approval Sender Verification)
          socket.pause();
          console.log(`[P2P Ontvanger] Afzender '${fileInfo.username}' aan het verifiëren via auth server...`);
          sendAuthRequest({
            action: 'verify_session',
            session_token: fileInfo.session_token,
            username: fileInfo.username
          }, (verifyErr, verifyRes) => {
            if (verifyErr) {
              console.error(`[P2P Ontvanger] Fout bij verbinden met auth server voor verificatie:`, verifyErr.message);
              socket.resume();
              socket.end('FOUT: Kan afzender niet verifiëren (verbindingsfout)\n');
              cleanup();
              return;
            }

            if (!verifyRes || verifyRes.status !== 'success') {
              console.error(`[P2P Ontvanger] Afzender verificatie mislukt voor '${fileInfo.username}':`, verifyRes ? verifyRes.message : 'Geen response');
              socket.resume();
              socket.end('FOUT: Afzender verificatie mislukt\n');
              cleanup();
              return;
            }

            console.log(`[P2P Ontvanger] Afzender '${fileInfo.username}' succesvol geverifieerd. Vraag toestemming via UI...`);

            // Beveiliging: Vraag toestemming via callback (UI) of via console
            const isAutoAccept = process.env.AUTO_ACCEPT === 'true';

            // Helper: schrijf het bestand en start ontvangst
            function doAccept() {
              console.log('[P2P Ontvanger] Overdracht geaccepteerd. Start download...');
              const ontvangMap = getCurrentUserReceivedDir();
              fs.mkdirSync(ontvangMap, { recursive: true });
              const finalPath = path.join(ontvangMap, veiligeNaam);
              if (fs.existsSync(finalPath)) {
                socket.resume();
                socket.end('FOUT: Er bestaat al een bestand met deze naam\n');
                cleanup();
                return;
              }
              tempPath = path.join(ontvangMap, `.${veiligeNaam}.${crypto.randomBytes(12).toString('hex')}.tmp`);

              try {
                writeStream = fs.createWriteStream(tempPath, { flags: 'wx', mode: 0o600 });
                writeStream.on('error', err => {
                  console.error('[P2P Ontvanger] Bestandsfout:', err.message);
                  socket.end('FOUT: Server schrijf error\n');
                  cleanup();
                });
              } catch (e) {
                console.error('[P2P Ontvanger] Fout bij aanmaken schrijfstroom:', e.message);
                socket.end('FOUT: Server schrijf error\n');
                cleanup();
                return;
              }

              state = 'WAITING_ENVELOPE_2';
              socket.resume();
              socket.write('ACCEPT\n');
            }

            function doDecline() {
              console.log('[P2P Ontvanger] Overdracht geweigerd.');
              socket.resume();
              socket.write('DECLINE: Geweigerd door ontvanger\n');
              socket.destroy();
              cleanup();
            }

            if (isAutoAccept) {
              console.log('[P2P Ontvanger] AUTO_ACCEPT actief. Overdracht automatisch geaccepteerd.');
              doAccept();
            } else if (typeof onIncomingTransfer === 'function') {
              // UI-modus: geef controle aan de Web UI callback. Socket blijft gepauzeerd tot doAccept/doDecline.
              console.log(`[P2P Ontvanger] Wachten op UI-beslissing voor '${veiligeNaam}'...`);
              onIncomingTransfer(
                { username: fileInfo.username, filename: veiligeNaam, file_size: fileInfo.file_size },
                doAccept,
                doDecline
              );
            } else {
              // Geen callback en geen AUTO_ACCEPT: automatisch weigeren
              console.log('[P2P Ontvanger] Geen UI callback beschikbaar. Transfer geweigerd.');
              doDecline();
            }
          }, authHost || AUTH_HOST, authPort || AUTH_PORT_UI);

        } else {
          processPayload();
        }
      });
    });

    function processPayload() {
      if (state === 'WAITING_ENVELOPE_2') {
        if (buffer.length < 4) return;
        const envLen = buffer.readUInt32BE(0);
        if (envLen < 28 || envLen > 4096) {
          socket.end('FOUT: Ongeldige 2e envelop grootte\n');
          cleanup();
          return;
        }
        if (buffer.length < 4 + envLen) return;

        const envelope2Bin = buffer.slice(4, 4 + envLen);
        buffer = buffer.slice(4 + envLen);

        // Decrypt 2e envelop met symmetrische sessionKey (om RSA sleutellimieten te omzeilen)
        try {
          const nonce = envelope2Bin.slice(0, 12);
          const tag = envelope2Bin.slice(12, 28);
          const ciphertext = envelope2Bin.slice(28);

          const decipher = crypto.createDecipheriv('chacha20-poly1305', sessionKey, nonce, { authTagLength: 16 });
          decipher.setAuthTag(tag);
          const decryptedEnv = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

          const envData = JSON.parse(decryptedEnv.toString());
          if (!/^[a-f0-9]{64}$/i.test(String(envData.sha256 || ''))) {
            throw new Error('Ongeldige SHA-256 hash in 2e envelop');
          }
          expectedSha256 = envData.sha256;
          console.log(`[P2P Ontvanger] 2e Envelop ontsleuteld. Verwachte hash: ${expectedSha256}`);

          state = 'STREAMING';
          processPayload(); // verwerk eventuele overige data in buffer
        } catch (err) {
          console.error('[P2P Ontvanger] Decryptie van 2e envelop mislukt:', err.message);
          socket.end('FOUT: 2e envelop corrupt\n');
          cleanup();
          return;
        }
      }

      if (state === 'STREAMING') {
        const CHUNK_SIZE = 65536;
        const remaining = fileInfo.file_size - receivedBytes;
        if (remaining <= 0) return;

        const currentChunk = Math.min(CHUNK_SIZE, remaining);
        const packetSize = 12 + currentChunk + 16; // nonce + ciphertext + tag

        while (buffer.length >= packetSize) {
          const packet = buffer.slice(0, packetSize);
          buffer = buffer.slice(packetSize);

          const nonce = packet.slice(0, 12);
          const ciphertext = packet.slice(12, 12 + currentChunk);
          const tag = packet.slice(12 + currentChunk, packetSize);

          try {
            const decipher = crypto.createDecipheriv('chacha20-poly1305', sessionKey, nonce, { authTagLength: 16 });
            decipher.setAuthTag(tag);
            const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

            writeStream.write(plaintext);
            hashSum.update(plaintext);
            receivedBytes += currentChunk;
          } catch (err) {
            console.error('[P2P Ontvanger] Poly1305 MAC verificatie mislukt! Data is corrupt.');
            socket.write('FOUT: Integriteitsfout tijdens streaming.\n');
            socket.destroy();
            cleanup();
            return;
          }

          const nextRemaining = fileInfo.file_size - receivedBytes;
          if (nextRemaining <= 0) {
            writeStream.end(() => {
              const finalPath = path.join(path.dirname(tempPath), fileInfo.filename);
              const calculatedSha256 = hashSum.digest('hex');

              if (calculatedSha256 !== expectedSha256) {
                console.error('[P2P Ontvanger] SHA-256 integriteitscontrole mislukt!');
                socket.end('FOUT: SHA-256 hash mismatch.\n');
                cleanup();
              } else {
                try {
                  fs.copyFileSync(tempPath, finalPath, fs.constants.COPYFILE_EXCL);
                  fs.unlinkSync(tempPath);
                } catch (err) {
                  console.error('[P2P Ontvanger] Bestand kon niet veilig worden opgeslagen:', err.message);
                  socket.end('FOUT: Bestand bestaat al of kan niet veilig worden opgeslagen.\n');
                  cleanup();
                  return;
                }
                console.log(`[P2P Ontvanger] Bestand succesvol opgeslagen: ${fileInfo.filename}`);
                webState.hasNewFiles = true;

                transferManager.completeReceiveByFile(fileInfo.username, fileInfo.filename, fileInfo.file_size);

                transferDone = true;
                socket.end(`OK geupload: ${fileInfo.filename}\n`);
                if (isMulti) {
                  process.stdout.write('\n> ');
                }
              }
            });
            break;
          }
        }
      }
    }

    function cleanup() {
      transferDone = true;
      activeReceiverSockets.delete(socket);
      if (writeStream) writeStream.destroy();
      if (tempPath && fs.existsSync(tempPath)) {
        try { fs.unlinkSync(tempPath); } catch (e) { }
      }
    }
  }

  // Luister via I2P SAM Bridge
  function startSamAcceptLoop() {
    const samAccept = net.connect({ host: I2P_CONFIG.samHost, port: I2P_CONFIG.samPort }, () => {
      samAccept.write('HELLO VERSION MIN=3.0 MAX=3.1\n');
    });

    let subState = 'HELLO';
    let subBuffer = Buffer.alloc(0);

    samAccept.on('error', err => {
      console.error('[P2P Ontvanger] I2P accept socket fout:', err.message);
    });

    samAccept.on('data', data => {
      subBuffer = Buffer.concat([subBuffer, data]);

      while (true) {
        const nl = subBuffer.indexOf(10);
        if (nl === -1) break;
        const line = subBuffer.slice(0, nl).toString().trim();
        subBuffer = subBuffer.slice(nl + 1);

        if (subState === 'HELLO') {
          if (line.includes('RESULT=OK')) {
            subState = 'STREAM_STATUS';
            samAccept.write(`STREAM ACCEPT ID=${samSessionID}\n`);
          } else {
            console.error('[P2P Ontvanger] I2P HELLO mislukt:', line);
            samAccept.destroy();
            break;
          }
        } else if (subState === 'STREAM_STATUS') {
          if (line.includes('RESULT=OK')) {
            subState = 'PEER_CONNECTION';
            // Tunnel luistert nu. We wachten tot de peer verbinding maakt.
          } else {
            console.error('[P2P Ontvanger] I2P Accept status mislukt:', line);
            samAccept.destroy();
            break;
          }
        } else if (subState === 'PEER_CONNECTION') {
          console.log('[P2P Ontvanger] I2P SAM tunnel peer verbonden. Handshake starten...');

          // Deze socket is nu verbonden met de client!
          samAccept.removeAllListeners('data');
          samAccept.removeAllListeners('error');
          if (subBuffer.length > 0) {
            samAccept.unshift(subBuffer);
          }
          behandelP2PVerbinding(samAccept);

          // Start direct de volgende accept socket om meer verbindingen op te vangen
          startSamAcceptLoop();
          break;
        }
      }
    });
  }

  startSamAcceptLoop();
  console.log(`P2P Node is online als '${myUsername}' op I2P.`);
  console.log(`I2P Destination: ${base32Address}`);
}

/**
 * Maakt verbinding met een peer en verzendt een bestand.
 */
function performSendFlow(file, targetUsername, myUsername, sessionToken, authHost, authPort, callback) {
  let finalized = false;
  const finalize = (err = null) => {
    if (finalized) return;
    finalized = true;
    if (callback) callback(err);
  };

  if (!fs.existsSync(file)) {
    console.error(`Fout: Bestand '${file}' bestaat niet.`);
    finalize(new Error('Bestand bestaat niet'));
    return;
  }
  const fileData = fs.readFileSync(file);
  const filename = path.basename(file);

  console.log(`[P2P Verzender] Vraag adres op van '${targetUsername}'...`);
  lookup(sessionToken, targetUsername, authHost, authPort, (err, targetAddress) => {
    if (err) {
      console.error(`[P2P Verzender] Lookup mislukt:`, err.message);
      finalize(err);
      return;
    }

    let verbindingKlaar = (peerSocket) => {
      console.log(`[P2P Verzender] Verbonden met peer '${targetUsername}'. Wachten op RSA sleutel...`);

      peerSocket.setTimeout(config.socketTimeout);
      peerSocket.on('timeout', () => {
        console.error('[P2P Verzender] Verbinding gesloten wegens time-out.');
        peerSocket.destroy();
        finalize(new Error('Verbinding time-out'));
      });

      peerSocket.on('error', (socketErr) => {
        if (finalized && (socketErr.code === 'ECONNRESET' || socketErr.code === 'EPIPE')) {
          return; // Ignore normal socket teardown errors after completion
        }
        console.error('[P2P Verzender] Socketfout:', socketErr.message);
        finalize(socketErr);
      });

      let peerBuffer = Buffer.alloc(0);
      let peerPublicKey = null;
      let state = 'WAITING_RSA';
      let sessionKey = null;
      let gotFinalAck = false;
      let sentAllChunks = false;
      let gotFailureReply = false;

      peerSocket.on('close', () => {
        if (state === 'STREAMING' && (gotFinalAck || (sentAllChunks && !gotFailureReply))) {
          finalize(null);
          return;
        }
        if (!finalized) {
          finalize(new Error('Verbinding met peer voortijdig gesloten'));
        }
      });

      peerSocket.on('data', dataBlok => {
        // Beveiliging: Limiteer buffer accumulatie in de client om DoS te voorkomen
        if (peerBuffer.length + dataBlok.length > 4096) {
          console.error('[P2P Verzender] Buffer limiet (4KB) overschreden. Connectie verbroken.');
          peerSocket.destroy();
          finalize(new Error('Buffer limiet overschreden'));
          return;
        }
        peerBuffer = Buffer.concat([peerBuffer, dataBlok]);

        if (state === 'WAITING_RSA') {
          const delimiter = '-----END RSA PUBLIC KEY-----';
          const delimiterIndex = peerBuffer.indexOf(delimiter);
          if (delimiterIndex === -1) return;

          const nlIndex = peerBuffer.indexOf('\n', delimiterIndex);
          if (nlIndex === -1) return;

          // Extraheer de RSA Public Key van de ontvanger (inclusief newline)
          peerPublicKey = peerBuffer.slice(0, nlIndex + 1).toString();
          peerBuffer = peerBuffer.slice(nlIndex + 1);
          console.log('[P2P Verzender] RSA Public Key ontvangen van peer.');

          // Genereer 32-byte symmetrische sleutel
          sessionKey = crypto.randomBytes(32);

          // Encrypt symmetrische sleutel (1e envelop)
          const envelope1 = crypto.publicEncrypt({
            key: peerPublicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
          }, sessionKey);

          // Encrypt metadata met ChaCha20-Poly1305 (inclusief session_token)
          const metadataJSON = JSON.stringify({
            username: myUsername,
            filename: filename,
            file_size: fileData.length,
            session_token: sessionToken
          });
          const nonce = crypto.randomBytes(12);
          const cipher = crypto.createCipheriv('chacha20-poly1305', sessionKey, nonce, { authTagLength: 16 });
          const ciphertext = Buffer.concat([cipher.update(Buffer.from(metadataJSON)), cipher.final()]);
          const tag = cipher.getAuthTag();

          // Verzend: [4b env1Len] + [env1] + [4b metadataLen] + [12b nonce] + [16b tag] + [ciphertext]
          const header = Buffer.alloc(8);
          header.writeUInt32BE(envelope1.length, 0);
          header.writeUInt32BE(ciphertext.length, 4);

          peerSocket.write(Buffer.concat([header, envelope1, nonce, tag, ciphertext]));
          state = 'WAITING_ACCEPT';
          console.log('[P2P Verzender] Gecodeerde metadata handshake verzonden. Wachten op acceptatie...');
        } else if (state === 'WAITING_ACCEPT') {
          const nl = peerBuffer.indexOf(10);
          if (nl === -1) return;

          const line = peerBuffer.slice(0, nl).toString().trim();
          peerBuffer = peerBuffer.slice(nl + 1);

          if (line === 'ACCEPT') {
            console.log('[P2P Verzender] Overdracht geaccepteerd! Start payload streaming...');
            state = 'STREAMING';

            const fileSha256 = crypto.createHash('sha256').update(fileData).digest('hex');

            // Maak en versleutel de 2e envelop met symmetrische sessionKey (om RSA sleutellimieten te omzeilen)
            const envelope2JSON = JSON.stringify({
              session_token: sessionToken,
              filename: filename,
              sha256: fileSha256
            });
            const env2Nonce = crypto.randomBytes(12);
            const env2Cipher = crypto.createCipheriv('chacha20-poly1305', sessionKey, env2Nonce, { authTagLength: 16 });
            const env2Ciphertext = Buffer.concat([env2Cipher.update(Buffer.from(envelope2JSON)), env2Cipher.final()]);
            const env2Tag = env2Cipher.getAuthTag();
            const envelope2 = Buffer.concat([env2Nonce, env2Tag, env2Ciphertext]);

            // Stuur [4b env2Len] + [envelope2]
            const env2LenBuf = Buffer.alloc(4);
            env2LenBuf.writeUInt32BE(envelope2.length, 0);
            peerSocket.write(env2LenBuf);
            peerSocket.write(envelope2);

            // Stream chunks
            const CHUNK_SIZE = 65536;
            let offset = 0;
            while (offset < fileData.length) {
              const chunk = fileData.slice(offset, offset + CHUNK_SIZE);
              const chunkNonce = crypto.randomBytes(12);

              const chunkCipher = crypto.createCipheriv('chacha20-poly1305', sessionKey, chunkNonce, { authTagLength: 16 });
              const chunkCiphertext = Buffer.concat([chunkCipher.update(chunk), chunkCipher.final()]);
              const chunkTag = chunkCipher.getAuthTag();

              peerSocket.write(Buffer.concat([chunkNonce, chunkCiphertext, chunkTag]));
              offset += chunk.length;
            }
            sentAllChunks = true;
            peerSocket.end();
          } else {
            console.error('[P2P Verzender] Overdracht geweigerd:', line);
            peerSocket.destroy();
            finalize(new Error(`Overdracht geweigerd: ${line}`));
          }
        } else if (state === 'STREAMING') {
          const nl = peerBuffer.indexOf(10);
          if (nl === -1) return;
          const line = peerBuffer.slice(0, nl).toString().trim();
          console.log('[P2P Verzender] Peer antwoord:', line);
          if (line.startsWith('OK')) {
            gotFinalAck = true;
          } else if (line.startsWith('FOUT')) {
            gotFailureReply = true;
            finalize(new Error(line));
          }
          peerSocket.destroy();
        }
      });
    };

    console.log(`[P2P Verzender] Maak anonieme verbinding via SOCKS5 proxy naar ${targetAddress}...`);
    connectSocks5(I2P_CONFIG.socksHost, I2P_CONFIG.socksPort, targetAddress, 80, (socksErr, peerSocket) => {
      if (socksErr) {
        console.error('[P2P Verzender] Kan niet verbinden via SOCKS5:', socksErr.message);
        finalize(socksErr);
        return;
      }
      verbindingKlaar(peerSocket);
    });
  });
}




let i2pChildProcess = null;

// Ruim het I2P-achtergrondproces op bij het afsluiten van Node
function cleanupI2p() {
  if (i2pChildProcess) {
    console.log('[I2P Manager] Stoppen van lokale i2pd daemon...');
    try {
      i2pChildProcess.kill();
    } catch (e) { }
    i2pChildProcess = null;
  }
}

process.on('exit', cleanupI2p);
process.on('SIGINT', () => {
  cleanupI2p();
  process.exit(0);
});
process.on('SIGTERM', () => {
  cleanupI2p();
  process.exit(0);
});

function startI2pProcess(exePath, callback) {
  try {
    i2pChildProcess = spawn(exePath, [
      '--sam.enabled=1',
      `--sam.port=${I2P_CONFIG.samPort}`,
      '--socksproxy.enabled=1',
      `--socksproxy.port=${I2P_CONFIG.socksPort}`,
      '--httpproxy.enabled=0',
      '--http.enabled=0'
    ], {
      detached: true,
      stdio: 'ignore'
    });

    i2pChildProcess.unref();

    console.log('[I2P Manager] i2pd daemon gestart in achtergrond. Wachten tot SAM Bridge online komt...');

    let retries = 0;
    const maxRetries = 120; // 120 seconden wachttijd (genoeg voor UAC / admin bevoegdheid verlenen)

    function checkSamOnline() {
      const socket = net.connect({ port: I2P_CONFIG.samPort, host: I2P_CONFIG.samHost }, () => {
        socket.destroy();
        console.log('[I2P Manager] SAM Bridge is online gekomen en luistert!');
        callback(null, i2pChildProcess);
      });

      socket.on('error', () => {
        retries++;
        if (retries % 5 === 0) {
          console.log(`[I2P Manager] Wachten tot SAM Bridge online komt... (poging ${retries}/${maxRetries})`);
        }
        if (retries >= maxRetries) {
          callback(new Error(`SAM Bridge startte niet op binnen de verwachte tijd (${maxRetries}s).`));
          return;
        }
        setTimeout(checkSamOnline, 1000);
      });
    }

    setTimeout(checkSamOnline, 1000);
  } catch (err) {
    callback(err);
  }
}

function checkAndInstallI2P(callback) {
  // Eerst testen of SAM Bridge al online is (poort 7656)
  const checkSocket = net.connect({ port: I2P_CONFIG.samPort, host: I2P_CONFIG.samHost }, () => {
    checkSocket.destroy();
    console.log('[I2P Manager] SAM Bridge is al actief op poort 7656.');
    callback(null, null); // Reeds actief
  });

  checkSocket.on('error', () => {
    // SAM Bridge is offline, we moeten kijken of we i2pd lokaal hebben
    const binDir = path.join(PROJECT_ROOT, 'bin', 'i2pd');
    const exePath = path.join(binDir, 'i2pd.exe');

    if (fs.existsSync(exePath)) {
      console.log('[I2P Manager] SAM Bridge offline, maar lokale i2pd.exe gevonden. Starten...');
      startI2pProcess(exePath, callback);
    } else {
      console.log('[I2P Manager] SAM Bridge offline en geen lokale i2pd.exe gevonden.');
      console.log('[I2P Manager] Downloaden van portable PurpleI2P i2pd (v2.60.0) voor Windows...');

      fs.mkdirSync(binDir, { recursive: true });
      const zipPath = path.join(binDir, 'i2pd.zip');
      const file = fs.createWriteStream(zipPath);

      const downloadUrl = 'https://github.com/PurpleI2P/i2pd/releases/download/2.60.0/i2pd_2.60.0_win64_mingw.zip';
      // SHA-256 published by the official PurpleI2P GitHub release for this exact archive.
      const expectedArchiveHash = '8be7f4c9bde7c8876b4056c9a3e46212331f37a944318c7e5cd5f48367b2e851';

      function downloadFile(url) {
        https.get(url, (response) => {
          if (response.statusCode === 302 || response.statusCode === 301) {
            downloadFile(response.headers.location);
            return;
          }
          if (response.statusCode !== 200) {
            callback(new Error(`Download mislukt met statuscode ${response.statusCode}`));
            return;
          }
          response.pipe(file);
          file.on('finish', () => {
            file.close(() => {
              const actualArchiveHash = crypto.createHash('sha256').update(fs.readFileSync(zipPath)).digest('hex');
              if (!crypto.timingSafeEqual(Buffer.from(actualArchiveHash, 'hex'), Buffer.from(expectedArchiveHash, 'hex'))) {
                fs.unlinkSync(zipPath);
                callback(new Error('i2pd archive integrity check failed; the download was discarded.'));
                return;
              }

              console.log('[I2P Manager] Download integrity check passed. Extracting ZIP via PowerShell...');
              try {
                const escapedZipPath = zipPath.replace(/'/g, "''");
                const escapedBinDir = binDir.replace(/'/g, "''");
                execSync(`powershell -Command "Expand-Archive -Path '${escapedZipPath}' -DestinationPath '${escapedBinDir}' -Force"`);
                fs.unlinkSync(zipPath); // Verwijder de ZIP

                // Zoek recursief naar i2pd.exe (in het geval van een geneste ZIP structuur)
                const foundExe = findFileRecursively(binDir, 'i2pd.exe');
                if (foundExe) {
                  if (foundExe !== exePath) {
                    fs.renameSync(foundExe, exePath);
                  }
                  console.log('[I2P Manager] Lokale i2pd succesvol geïnstalleerd. Starten...');
                  startI2pProcess(exePath, callback);
                } else {
                  callback(new Error('i2pd.exe niet gevonden na het uitpakken van de ZIP.'));
                }
              } catch (extractErr) {
                callback(new Error(`Fout bij uitpakken van ZIP: ${extractErr.message}`));
              }
            });
          });
        }).on('error', (err) => {
          fs.unlinkSync(zipPath);
          callback(err);
        });
      }

      downloadFile(downloadUrl);
    }
  });
}

function findFileRecursively(dir, filename) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      const res = findFileRecursively(fullPath, filename);
      if (res) return res;
    } else if (file.toLowerCase() === filename.toLowerCase()) {
      return fullPath;
    }
  }
}

function convertI2PBase64toBase32(base64Destination) {
  return destinationToBase32(base64Destination);
}

module.exports = {
  login,
  lookup,
  connectSocks5,
  convertI2PBase64toBase32,
  performSendFlow,
  startReceiver,
  checkAndInstallI2P,
  I2P_CONFIG,
  startWebUI,
};

// ═══════════════════════════════════════════════════════════════════════════
// WEB UI — Ingebouwde HTTP Server
// ═══════════════════════════════════════════════════════════════════════════

// Application state is intentionally in-memory only.
const webState = {
  isOnline: false,
  username: null,
  myBase32Address: null,
  authToken: null,
  samSocket: null,
  hasNewFiles: false,
};

const logger = new ApplicationLogger({ filePath: LOG_FILE, maxEntries: LOG_MAX });
const transferManager = new TransferManager();

function webLog(msg) {
  logger.info(msg);
}

function sendJSON(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req, maxSize = 10 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    const onData = c => {
      received += c.length;
      if (received > maxSize) {
        req.removeListener('data', onData);
        reject(new Error('Payload te groot'));
        return;
      }
      chunks.push(c);
    };
    req.on('data', onData);
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

function serveStaticFile(res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const mime = MIME_TYPES[ext] || 'application/octet-stream';
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not Found'); return; }
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
}

function serveIndex(res) {
  fs.readFile(path.join(PUBLIC_DIR, 'index.html'), 'utf8', (err, html) => {
    if (err) { res.writeHead(500); res.end('UI niet gevonden. Controleer of de public/ map aanwezig is.'); return; }
    // Injecteer het session token in de <meta> placeholder
    const injected = html.replace('__SESSION_TOKEN_PLACEHOLDER__', WEB_SESSION_TOKEN);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(injected);
  });
}



// ── Inkomende transfer UI callback ───────────────────────────────────────────
function onIncomingTransferUI(info, acceptFn, declineFn) {
  if (!webState.isOnline) {
    webLog(`[Ontvanger] Inkomende transfer geweigerd: node is offline/uitgelogd.`);
    declineFn();
    return;
  }
  const id = crypto.randomBytes(4).toString('hex');
  webLog(`[Ontvanger] Inkomend: '${info.filename}' van '${info.username}' (${(info.file_size / 1048576).toFixed(2)} MB) — wacht op UI-beslissing...`);
  transferManager.createReceive(id, {
    filename: info.filename,
    sender: info.username,
    received: 0,
    size: info.file_size,
    acceptFn,
    declineFn,
  });
}

// ── API handlers ─────────────────────────────────────────────────────────────

async function handleWebRegister(req, res) {
  let body;
  try { body = JSON.parse((await readBody(req)).toString()); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldig JSON verzoek.' }); }

  const { username, password } = body;
  if (!username || !password)
    return sendJSON(res, 400, { status: 'error', message: 'Gebruikersnaam en wachtwoord verplicht.' });

  webLog(`[Register] Registreren van '${username}'...`);

  sendAuthRequest({ action: 'register', username, password }, (err, r) => {
    if (err) {
      webLog(`[Register] Netwerkfout: ${err.message}`);
      return sendJSON(res, 503, { status: 'error', message: `Kan niet verbinden met auth server: ${err.message}` });
    }

    if (r.status === 'success') {
      webLog(`[Register] Succes: '${username}' aangemaakt.`);
      sendJSON(res, 200, { status: 'success', message: r.message });
    } else {
      webLog(`[Register] Mislukt: ${r.message}`);
      sendJSON(res, 400, { status: 'error', message: r.message || 'Registratie mislukt' });
    }
  });
}

async function handleWebLogin(req, res) {
  if (webState.isOnline)
    return sendJSON(res, 409, { status: 'error', message: 'Node is al actief. Log eerst uit.' });

  let body;
  try { body = JSON.parse((await readBody(req)).toString()); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldig JSON verzoek.' }); }

  const { username, password } = body;
  if (!username || !password)
    return sendJSON(res, 400, { status: 'error', message: 'Gebruikersnaam en wachtwoord verplicht.' });

  webLog(`[Login] Inloggen als '${username}'...`);

  login(username, password, i2pState.address || '', AUTH_HOST, AUTH_PORT_UI, (err, sessionToken) => {
    if (err) {
      webLog(`[Login] Mislukt: ${err.message}`);
      return sendJSON(res, 503, { status: 'error', message: err.message });
    }

    webState.isOnline = true;
    webState.username = username;
    webState.authToken = sessionToken;
    webState.myBase32Address = i2pState.address || null;

    webLog(`[Login] Online als '${username}'.`);

    // Koppel het I2P-adres als het al online is
    if (i2pState.status === 'online') {
      updateAddressOnCentralServer(sessionToken, i2pState.address);
    } else {
      webLog(`[Login] I2P tunnel is nog aan het opstarten op de achtergrond...`);
    }

    fs.mkdirSync(getCurrentUserReceivedDir(), { recursive: true });
    sendJSON(res, 200, { status: 'success', myBase32Address: webState.myBase32Address });
  });
}

async function handleWebSend(req, res) {
  if (!webState.isOnline)
    return sendJSON(res, 403, { status: 'error', message: 'Node is niet actief. Log eerst in.' });

  let body;
  // Base64 adds overhead; only accept enough JSON for the configured file limit.
  const maxRequestBytes = Math.ceil(MAX_UPLOAD_BYTES * 4 / 3) + 16 * 1024;
  try { body = JSON.parse((await readBody(req, maxRequestBytes)).toString()); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldig JSON verzoek.' }); }

  const { recipient, filename, fileData } = body;
  if (!recipient || !filename || !fileData)
    return sendJSON(res, 400, { status: 'error', message: 'Ontbrekende velden: recipient, filename, fileData.' });

  let safeFilename;
  try {
    safeFilename = normalizeFileName(filename);
  } catch {
    return sendJSON(res, 400, { status: 'error', message: 'Onveilige bestandsnaam. Alleen letters, cijfers, underscores (_), streepjes (-), punten (.) en spaties zijn toegestaan.' });
  }

  let fileBuffer;
  try { fileBuffer = decodeBase64(fileData); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldige Base64 data.' }); }
  if (fileBuffer.length === 0 || fileBuffer.length > MAX_UPLOAD_BYTES) {
    return sendJSON(res, 413, { status: 'error', message: `Bestand is leeg of groter dan de limiet van ${MAX_UPLOAD_BYTES} bytes.` });
  }

  const tmpDir = path.join(PROJECT_ROOT, 'sending_tmp');
  fs.mkdirSync(tmpDir, { recursive: true });
  const tmpFile = path.join(tmpDir, `${Date.now()}_${safeFilename}`);
  try {
    fs.writeFileSync(tmpFile, fileBuffer);
  } catch (err) {
    webLog(`[Verzender] Fout bij schrijven tijdelijk bestand: ${err.message}`);
    return sendJSON(res, 500, { status: 'error', message: 'Kan tijdelijk bestand niet opslaan.' });
  }

  const tid = crypto.randomBytes(4).toString('hex');
  transferManager.createSend(tid, {
    filename: safeFilename, target: recipient,
    sent: 0, size: fileBuffer.length,
  });

  webLog(`[Verzender] Start: '${safeFilename}' → '${recipient}'...`);

  performSendFlow(tmpFile, recipient, webState.username, webState.authToken, AUTH_HOST, AUTH_PORT_UI, (err) => {
    try { fs.unlinkSync(tmpFile); } catch { }
    if (err) transferManager.failSend(tid);
    else transferManager.completeSend(tid, fileBuffer.length);
    if (err) console.error(`[Verzender] Mislukt: ${err}`);
    else console.log(`[Verzender] '${safeFilename}' succesvol verzonden naar '${recipient}'.`);
  });

  sendJSON(res, 200, { status: 'success', message: `Verzending gestart voor '${safeFilename}'.` });
}

async function handleWebAccept(req, res) {
  let body;
  try { body = JSON.parse((await readBody(req)).toString()); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldig JSON.' }); }

  const t = transferManager.acceptReceive(body.transferId);
  if (!t)
    return sendJSON(res, 404, { status: 'error', message: 'Transfer niet gevonden of niet in wachtstatus.' });

  webLog(`[Ontvanger] Geaccepteerd: '${t.filename}' van '${t.sender}'.`);
  t.acceptFn();

  sendJSON(res, 200, { status: 'success', message: 'Transfer geaccepteerd.' });
}

async function handleWebDecline(req, res) {
  let body;
  try { body = JSON.parse((await readBody(req)).toString()); }
  catch { return sendJSON(res, 400, { status: 'error', message: 'Ongeldig JSON.' }); }

  const t = transferManager.declineReceive(body.transferId);
  if (!t)
    return sendJSON(res, 404, { status: 'error', message: 'Transfer niet gevonden of niet in wachtstatus.' });

  webLog(`[Ontvanger] Geweigerd: '${t.filename}' van '${t.sender}'.`);
  t.declineFn();
  sendJSON(res, 200, { status: 'success', message: 'Transfer geweigerd.' });
}

async function handleWebLogout(req, res) {
  if (!webState.isOnline)
    return sendJSON(res, 400, { status: 'error', message: 'Node is al offline.' });

  webLog('[Logout] Node sessie beëindigd door gebruiker.');
  webState.isOnline = false; webState.username = null;
  webState.myBase32Address = null; webState.authToken = null;
  transferManager.reset();
  sendJSON(res, 200, { status: 'success', message: 'Uitgelogd.' });
}

function handleWebStatus(req, res) {
  const url = new URL(req.url, `http://localhost:${UI_PORT}`);
  const offset = parseInt(url.searchParams.get('offset') || '0', 10);
  const newLogs = logger.entriesAfter(offset);

  const hadNewFiles = webState.hasNewFiles;
  webState.hasNewFiles = false;

  sendJSON(res, 200, {
    status: 'success',
    isOnline: webState.isOnline,
    username: webState.username,
    myBase32Address: webState.myBase32Address || i2pState.address,
    i2pStatus: i2pState.status,
    i2pError: i2pState.error,
    logs: newLogs,
    activeTransfers: transferManager.snapshot(),
    hasNewFiles: hadNewFiles,
  });
}

function handleWebFiles(req, res) {
  try {
    if (!webState.isOnline || !webState.username)
      return sendJSON(res, 403, { status: 'error', message: 'Node is niet actief. Log eerst in.' });

    const userReceivedDir = getCurrentUserReceivedDir();
    fs.mkdirSync(userReceivedDir, { recursive: true });
    const items = fs.readdirSync(userReceivedDir)
      .filter(f => !f.endsWith('.tmp'))
      .map(f => {
        const s = fs.statSync(path.join(userReceivedDir, f));
        return { name: f, size: s.size, mtime: s.mtimeMs };
      })
      .sort((a, b) => b.mtime - a.mtime);
    sendJSON(res, 200, { status: 'success', files: items });
  } catch (err) {
    sendJSON(res, 500, { status: 'error', message: err.message });
  }
}

function handleWebDownload(req, res) {
  if (!webState.isOnline || !webState.username) { res.writeHead(403); res.end('Node is niet actief. Log eerst in.'); return; }
  const url = new URL(req.url, `http://localhost:${UI_PORT}`);
  const filename = url.searchParams.get('file');
  if (!filename) { res.writeHead(400); res.end('Missing file parameter.'); return; }
  const safe = path.basename(filename);
  if (!safe || safe.includes('..') || safe !== filename || !/^[a-zA-Z0-9_\-\. ]+$/.test(safe)) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Invalid filename. Alleen letters, cijfers, underscores (_), streepjes (-), punten (.) en spaties zijn toegestaan.');
    return;
  }
  const filePath = path.join(getCurrentUserReceivedDir(), safe);
  if (!fs.existsSync(filePath)) { res.writeHead(404); res.end('File not found.'); return; }
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (err) {
    res.writeHead(500);
    res.end('File system error');
    return;
  }
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${safe}"`,
    'Content-Length': stat.size,
  });
  const stream = fs.createReadStream(filePath);
  stream.on('error', () => {
    if (!res.headersSent) {
      res.writeHead(500);
      res.end('File read error');
    }
  });
  stream.pipe(res);
}

function handleWebShutdown(req, res) {
  webLog('[Shutdown] Terminatie ontvangen. Server stopt...');
  sendJSON(res, 200, { status: 'success', message: 'Server wordt afgesloten.' });
  if (i2pState.samSocket) { try { i2pState.samSocket.destroy(); } catch { } }
  setTimeout(() => {
    logger.close();
    process.exit(0);
  }, 500);
}

// ── PHP Auth Server starten ────────────────────────────────────────────
function startPhpServer(callback) {
  if (AUTH_USE_HTTP) {
    webLog(`[PHP Server] Externe auth server geconfigureerd; lokale server.php wordt overgeslagen.`);
    callback();
    return;
  }

  // Check of poort 8000 al in gebruik is (server draait al)
  const testSocket = net.connect({ host: '127.0.0.1', port: AUTH_PORT_UI }, () => {
    testSocket.destroy();
    webLog('[PHP Server] Auth server is al actief op poort ' + AUTH_PORT_UI + '.');
    callback();
  });

  testSocket.on('error', () => {
    // Poort vrij — start php server.php
    const phpScript = path.join(PROJECT_ROOT, 'server.php');
    if (!fs.existsSync(phpScript)) {
      webLog('[PHP Server] WAARSCHUWING: server.php niet gevonden! Auth server niet gestart.');
      return callback();
    }

    webLog('[PHP Server] Starten van server.php op poort ' + AUTH_PORT_UI + '...');

    const phpProc = spawn('php', [phpScript, String(AUTH_PORT_UI)], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false,
    });

    phpProc.stdout.on('data', data => {
      const lines = data.toString().trim().split('\n');
      lines.forEach(l => l && webLog('[PHP] ' + l.trim()));
    });
    phpProc.stderr.on('data', data => {
      const lines = data.toString().trim().split('\n');
      lines.forEach(l => l && webLog('[PHP FOUT] ' + l.trim()));
    });

    phpProc.on('exit', (code) => {
      webLog(`[PHP Server] server.php beëindigd (code ${code}).`);
    });

    // Wacht tot de PHP server luistert (max 5s)
    let tries = 0;
    const checkReady = () => {
      const s = net.connect({ host: '127.0.0.1', port: AUTH_PORT_UI }, () => {
        s.destroy();
        webLog('[PHP Server] Auth server luistert op poort ' + AUTH_PORT_UI + '. Klaar!');
        callback();
      });
      s.on('error', () => {
        tries++;
        if (tries >= 10) {
          webLog('[PHP Server] FOUT: Auth server reageerde niet na 5s.');
          callback();
        } else {
          setTimeout(checkReady, 500);
        }
      });
    };
    setTimeout(checkReady, 500);

    // Ruim PHP op bij afsluiten Node
    process.on('exit', () => { try { phpProc.kill(); } catch {} });
    process.on('SIGINT', () => { try { phpProc.kill(); } catch {} process.exit(0); });
    process.on('SIGTERM', () => { try { phpProc.kill(); } catch {} process.exit(0); });
  });
}

// ── HTTP Server + Router ──────────────────────────────────────────────────────
function startWebUI() {
  WEB_SESSION_TOKEN = crypto.randomBytes(32).toString('hex');

  logger.info('Nexus Share application starting.');

  // Eerst PHP auth server starten, dan pas de web UI en I2P booten
  startPhpServer(() => {
    // Start I2P op de achtergrond
    bootI2P();

    const server = http.createServer(async (req, res) => {
    console.log(`[HTTP] Request: ${req.method} ${req.url} (Token: ${req.headers['x-session-token'] || 'none'})`);
    res.setHeader('Access-Control-Allow-Origin', `http://localhost:${UI_PORT}`);
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Session-Token');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none';");
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    const urlPath = req.url.split('?')[0];

    // Statische bestanden
    if (req.method === 'GET' && urlPath === '/') return serveIndex(res);
    if (req.method === 'GET' && ['/app.js', '/index.css'].includes(urlPath))
      return serveStaticFile(res, path.join(PUBLIC_DIR, urlPath));

    // API — vereist geldig session token
    if (urlPath.startsWith('/api/')) {
      if (req.headers['x-session-token'] !== WEB_SESSION_TOKEN)
        return sendJSON(res, 403, { status: 'error', message: 'Ongeldig session token.' });

      try {
        if (req.method === 'POST' && urlPath === '/api/register') return await handleWebRegister(req, res);
        if (req.method === 'POST' && urlPath === '/api/login') return await handleWebLogin(req, res);
        if (req.method === 'POST' && urlPath === '/api/send') return await handleWebSend(req, res);
        if (req.method === 'POST' && urlPath === '/api/accept') return await handleWebAccept(req, res);
        if (req.method === 'POST' && urlPath === '/api/decline') return await handleWebDecline(req, res);
        if (req.method === 'POST' && urlPath === '/api/logout') return await handleWebLogout(req, res);
        if (req.method === 'POST' && urlPath === '/api/shutdown') return handleWebShutdown(req, res);
        if (req.method === 'GET' && urlPath === '/api/status') return handleWebStatus(req, res);
        if (req.method === 'GET' && urlPath === '/api/files') return handleWebFiles(req, res);
        if (req.method === 'GET' && urlPath === '/api/download') return handleWebDownload(req, res);
      } catch (err) {
        webLog(`[Server Fout] ${err.message}`);
        return sendJSON(res, 500, { status: 'error', message: 'Interne serverfout: ' + err.message });
      }

      return sendJSON(res, 404, { status: 'error', message: `Endpoint niet gevonden: ${urlPath}` });
    }

    res.writeHead(404); res.end('Not Found');
    });

    server.listen(UI_PORT, '127.0.0.1', () => {
      console.log('');
      console.log('╔══════════════════════════════════════════════════╗');
      console.log('║         NEXUS SHARE — Web UI (p2p.js)            ║');
      console.log('╠══════════════════════════════════════════════════╣');
      console.log(`║  URL:  http://localhost:${UI_PORT}                      ║`);
      console.log(`║  Log:  nexus.log                                  ║`);
      console.log('╚══════════════════════════════════════════════════╝');
      console.log('');
      console.log(process.env.NEXUS_DESKTOP_MODE === '1'
        ? 'Desktopvenster wordt geopend. Druk CTRL+C om te stoppen.'
        : 'Browser opent automatisch. Druk CTRL+C om te stoppen.');
      webLog('[Server] Web UI actief op poort ' + UI_PORT + '.');
      if (process.env.NEXUS_DESKTOP_MODE !== '1') {
        exec(`start http://localhost:${UI_PORT}`);
      }
    });

    // Start een periodieke keepalive-taak (elke 60 seconden) om sessie-timeout te voorkomen
    setInterval(() => {
      if (webState.isOnline && webState.authToken && (webState.myBase32Address || i2pState.address)) {
        updateAddressOnCentralServer(webState.authToken, webState.myBase32Address || i2pState.address);
      }
    }, 60000);

    server.on('error', err => {
      if (err.code === 'EADDRINUSE')
        console.error(`\n[FOUT] Poort ${UI_PORT} is al in gebruik. Stop het andere programma.\n`);
      else
        console.error('[Server Fout]', err.message);
      process.exit(1);
    });
  }); // einde startPhpServer callback
}


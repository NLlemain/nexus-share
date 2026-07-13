const { spawn } = require('child_process');
const net = require('net');
const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');

const DIR_SERVER_PORT = 8600;
const ALICE_UI_PORT = 3001;
const BOB_UI_PORT = 3002;
const ALICE_P2P_PORT = 9091;
const BOB_P2P_PORT = 9092;

const phpScript = path.join(__dirname, '..', 'server.php');
const p2pScript = path.join(__dirname, '..', 'p2p.js');

const aliceDir = path.join(__dirname, 'received_alice');
const bobDir = path.join(__dirname, 'received_bob');
const aliceLog = path.join(__dirname, 'alice.log');
const bobLog = path.join(__dirname, 'bob.log');

// Clean up previous test artifacts
function cleanupDirs() {
  console.log('Cleaning up directories and log files...');
  const dataDir = path.join(__dirname, '..', 'nexus_data');
  if (fs.existsSync(dataDir)) {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
  for (const d of [aliceDir, bobDir]) {
    if (fs.existsSync(d)) {
      fs.rmSync(d, { recursive: true, force: true });
    }
    fs.mkdirSync(d, { recursive: true });
  }
  for (const f of [aliceLog, bobLog]) {
    if (fs.existsSync(f)) {
      fs.unlinkSync(f);
    }
  }
  console.log('Stopping any running i2pd.exe instances to prevent bind conflicts...');
  try {
    const { execSync } = require('child_process');
    execSync('taskkill /F /IM i2pd.exe', { stdio: 'ignore' });
  } catch (e) {
    // Ignore errors if i2pd is not running
  }
  console.log('Freeing up test ports 3001, 3002, 8600, 9091, 9092...');
  try {
    const { execSync } = require('child_process');
    execSync('powershell -Command "Stop-Process -Id (Get-NetTCPConnection -LocalPort 3001, 3002, 8600, 9091, 9092 -ErrorAction SilentlyContinue).OwningProcess -Force -ErrorAction SilentlyContinue"', { stdio: 'ignore' });
  } catch (e) {
    // Ignore if ports are already free
  }
}

function getSessionToken(port) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const interval = setInterval(() => {
      http.get(`http://127.0.0.1:${port}/`, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          const match = data.match(/meta name="x-session-token" content="([a-f0-9]+)"/);
          if (match && match[1]) {
            clearInterval(interval);
            resolve(match[1]);
          }
        });
      }).on('error', () => {
        if (Date.now() - start > 15000) {
          clearInterval(interval);
          reject(new Error(`Timeout waiting for Web UI session token on port ${port}`));
        }
      });
    }, 500);
  });
}

function makePostRequest(port, token, endpoint, payload) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(payload);
    const req = http.request({
      hostname: '127.0.0.1',
      port: port,
      path: endpoint,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-session-token': token,
        'Content-Length': Buffer.byteLength(postData)
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

function makeGetRequest(port, token, endpoint) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port: port,
      path: endpoint,
      method: 'GET',
      headers: {
        'x-session-token': token
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          resolve(data);
        }
      });
    });

    req.on('error', reject);
    req.end();
  });
}

function waitForI2PAddress(logPath, timeoutMs = 180000) {
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const interval = setInterval(() => {
      if (fs.existsSync(logPath)) {
        const content = fs.readFileSync(logPath, 'utf8');
        const match = content.match(/Base32 adres:\s+([a-z2-7]{52}\.b32\.i2p)/);
        if (match && match[1]) {
          clearInterval(interval);
          resolve(match[1]);
          return;
        }
      }
      if (Date.now() - start > timeoutMs) {
        clearInterval(interval);
        reject(new Error(`Timeout waiting for I2P address in log ${logPath}`));
      }
    }, 1000);
  });
}

async function runTest() {
  console.log('--- STARTING MULTI-NODE P2P TRANSFER TEST ---');
  let phpProc, aliceProc, bobProc;

  try {
    cleanupDirs();

    console.log('Starting PHP Directory Server on port', DIR_SERVER_PORT);
    phpProc = spawn('php', [phpScript, String(DIR_SERVER_PORT)], { stdio: 'inherit' });

    // Wait a brief moment for PHP server to bind
    await new Promise(r => setTimeout(r, 2000));

    console.log('Starting Bob (Receiver) on P2P port', BOB_P2P_PORT);
    bobProc = spawn('node', [p2pScript], {
      env: {
        ...process.env,
        UI_PORT: String(BOB_UI_PORT),
        LISTEN_PORT: String(BOB_P2P_PORT),
        RECEIVED_DIR: bobDir,
        AUTH_PORT_UI: String(DIR_SERVER_PORT),
        LOG_FILE: bobLog,
        AUTH_HOST: '127.0.0.1',
        AUTH_USE_HTTP: '0'
      },
      stdio: 'inherit'
    });

    console.log('Waiting for Bob to establish I2P SAM session first...');
    const bobI2pAddr = await waitForI2PAddress(bobLog, 180000);
    console.log(`Bob I2P Address: ${bobI2pAddr}`);

    console.log('Starting Alice (Sender) on P2P port', ALICE_P2P_PORT);
    aliceProc = spawn('node', [p2pScript], {
      env: {
        ...process.env,
        UI_PORT: String(ALICE_UI_PORT),
        LISTEN_PORT: String(ALICE_P2P_PORT),
        RECEIVED_DIR: aliceDir,
        AUTH_PORT_UI: String(DIR_SERVER_PORT),
        LOG_FILE: aliceLog,
        AUTH_HOST: '127.0.0.1',
        AUTH_USE_HTTP: '0'
      },
      stdio: 'inherit'
    });

    console.log('Waiting for Alice to establish I2P SAM session...');
    const aliceI2pAddr = await waitForI2PAddress(aliceLog, 180000);
    console.log(`Alice I2P Address: ${aliceI2pAddr}`);

    console.log('Waiting 30 seconds for I2P leasesets to propagate locally...');
    await new Promise(r => setTimeout(r, 30000));

    // Fetch UI tokens
    const aliceToken = await getSessionToken(ALICE_UI_PORT);
    const bobToken = await getSessionToken(BOB_UI_PORT);
    console.log('Session tokens obtained.');

    const bobUser = 'bob_' + crypto.randomBytes(4).toString('hex');
    const aliceUser = 'alice_' + crypto.randomBytes(4).toString('hex');

    // Register & Login Bob
    console.log(`Registering & logging in Bob as '${bobUser}'...`);
    await makePostRequest(BOB_UI_PORT, bobToken, '/api/register', { username: bobUser, password: 'password' });
    const bobLogin = await makePostRequest(BOB_UI_PORT, bobToken, '/api/login', { username: bobUser, password: 'password' });
    console.log('Bob login status:', bobLogin.status);

    // Register & Login Alice
    console.log(`Registering & logging in Alice as '${aliceUser}'...`);
    await makePostRequest(ALICE_UI_PORT, aliceToken, '/api/register', { username: aliceUser, password: 'password' });
    const aliceLogin = await makePostRequest(ALICE_UI_PORT, aliceToken, '/api/login', { username: aliceUser, password: 'password' });
    console.log('Alice login status:', aliceLogin.status);

    // Create test file for Alice
    const testFileContent = 'Real world P2P file transfer test content with high security. Key: ' + crypto.randomBytes(16).toString('hex');
    const testFileHash = crypto.createHash('sha256').update(testFileContent).digest('hex');
    const base64Content = Buffer.from(testFileContent).toString('base64');

    // Trigger Alice sending file to Bob
    console.log(`Triggering file transfer from Alice ('${aliceUser}') to Bob ('${bobUser}')...`);
    const sendRes = await makePostRequest(ALICE_UI_PORT, aliceToken, '/api/send', {
      recipient: bobUser,
      filename: 'test_transfer.txt',
      fileData: base64Content
    });
    console.log('Alice send command response:', sendRes);

    // Poll Bob's node for the incoming transfer
    console.log('Waiting for Bob to receive the incoming transfer notification...');
    let transferId = null;
    const pollStart = Date.now();
    while (Date.now() - pollStart < 45000) {
      const status = await makeGetRequest(BOB_UI_PORT, bobToken, '/api/status');
      const receives = status.activeTransfers.receives;
      const ids = Object.keys(receives);
      if (ids.length > 0) {
        transferId = ids[0];
        console.log(`Found incoming transfer on Bob. ID: ${transferId}, status: ${receives[transferId].status}`);
        break;
      }
      await new Promise(r => setTimeout(r, 1000));
    }

    if (!transferId) {
      throw new Error('Bob did not receive transfer notification within 45s');
    }

    // Accept transfer on Bob's side
    console.log('Accepting transfer on Bob...');
    const acceptRes = await makePostRequest(BOB_UI_PORT, bobToken, '/api/accept', { transferId });
    console.log('Bob accept response:', acceptRes);

    // Wait for the file to arrive in Bob's user-scoped directory and verify hash.
    console.log('Waiting for file transfer to complete and verify integrity...');
    const verificationStart = Date.now();
    let verified = false;
    const bobReceivedDir = path.join(bobDir, bobUser);

    while (Date.now() - verificationStart < 60000) {
      if (fs.existsSync(bobReceivedDir)) {
        const files = fs.readdirSync(bobReceivedDir);
        const transferFile = files.find(f => f.endsWith('test_transfer.txt'));
        if (transferFile) {
          const destFilePath = path.join(bobReceivedDir, transferFile);
          const content = fs.readFileSync(destFilePath, 'utf8');
          const calculatedHash = crypto.createHash('sha256').update(content).digest('hex');
          if (calculatedHash === testFileHash) {
            console.log('[SUCCESS] File received and verified successfully!');
            console.log(`File hash matches: ${testFileHash}`);
            verified = true;
            break;
          } else {
            throw new Error(`File hash mismatch. Expected ${testFileHash}, got ${calculatedHash}`);
          }
        }
      }
      await new Promise(r => setTimeout(r, 1000));
    }

    if (!verified) {
      throw new Error('File transfer verification timed out or file was not written.');
    }

    // Shutdown Alice and Bob
    console.log('Shutting down nodes...');
    await makePostRequest(ALICE_UI_PORT, aliceToken, '/api/shutdown', {});
    await makePostRequest(BOB_UI_PORT, bobToken, '/api/shutdown', {});

  } catch (e) {
    console.error('[FAIL] Test failed:', e);
    process.exitCode = 1;
  } finally {
    console.log('Stopping test servers and cleaning up processes...');
    try { phpProc.kill(); } catch (e) {}
    try { aliceProc.kill(); } catch (e) {}
    try { bobProc.kill(); } catch (e) {}
    console.log('Test execution completed.');
    process.exit();
  }
}

runTest();

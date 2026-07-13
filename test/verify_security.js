const { spawn } = require('child_process');
const net = require('net');
const path = require('path');
const fs = require('fs');

const TEST_PORT = 8500;
const phpScript = path.join(__dirname, '..', 'server.php');
const dataDirectory = path.join(__dirname, '..', 'nexus_data');

console.log('--- STARTING SECURITY TEST SUITE ---');

fs.rmSync(dataDirectory, { recursive: true, force: true });

// Start test PHP server
const phpProc = spawn('php', [phpScript, String(TEST_PORT)], { stdio: ['ignore', 'pipe', 'pipe'] });
let serverOutput = '';
phpProc.stdout.on('data', d => {
  serverOutput += d.toString();
  console.log('[PHP Server Output]', d.toString().trim());
});
phpProc.stderr.on('data', d => {
  console.error('[PHP Server Error]', d.toString().trim());
});

function sendRaw(data) {
  return new Promise((resolve, reject) => {
    const client = net.connect({ port: TEST_PORT, host: '127.0.0.1' }, () => {
      client.write(data + '\n');
    });
    
    let buffer = Buffer.alloc(0);
    client.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
    });
    client.on('end', () => {
      resolve(buffer.toString().trim());
    });
    client.on('error', err => {
      if (buffer.length > 0) {
        resolve(buffer.toString().trim());
        return;
      }
      reject(err);
    });
  });
}

function waitForServer(timeoutMs = 5_000) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const probe = () => {
      const socket = net.connect({ port: TEST_PORT, host: '127.0.0.1' }, () => {
        socket.destroy();
        resolve();
      });
      socket.on('error', () => {
        if (Date.now() >= deadline) {
          reject(new Error('Timed out waiting for the PHP test server.'));
          return;
        }
        setTimeout(probe, 100);
      });
    };
    probe();
  });
}

async function runTests() {
  await waitForServer();
  
  let passed = 0;
  let failed = 0;
  
  function assert(title, condition, extraInfo = '') {
    if (condition) {
      console.log(`[PASS] ${title}`);
      passed++;
    } else {
      console.error(`[FAIL] ${title} ${extraInfo}`);
      failed++;
    }
  }

  try {
    // 1. Test Malformed JSON / HTTP probe
    console.log('\nRunning Test 1: Malformed JSON...');
    const res1 = await sendRaw('GET / HTTP/1.1');
    let data1 = null;
    try { data1 = JSON.parse(res1); } catch(e) {}
    assert('Malformed JSON rejected with error status', data1 && data1.status === 'error', `Received: ${res1}`);
    assert('Server logged HACK POGING for JSON', serverOutput.includes('[HACK POGING] Ongeldige JSON-payload'));

    // 2. Test Username Injection Check
    console.log('\nRunning Test 2: Username Injection...');
    const res2 = await sendRaw(JSON.stringify({ action: 'register', username: "alice; DROP TABLE users; --", password: "pwd" }));
    let data2 = JSON.parse(res2);
    assert('Username injection rejected', data2 && data2.status === 'error' && data2.message.includes('ongeldige tekens'), `Received: ${res2}`);
    assert('Server logged HACK POGING for username', serverOutput.includes('[HACK POGING] Verdachte/ongeldige tekens in gebruikersnaam'));

    // 3. Test Optional Address Login
    console.log('\nRunning Test 3: Optional Address Login...');
    // Register testtest first
    await sendRaw(JSON.stringify({ action: 'register', username: 'testuser', password: 'securepassword' }));
    // Login without address
    const res3 = await sendRaw(JSON.stringify({ action: 'login', username: 'testuser', password: 'securepassword', address: '' }));
    let data3 = JSON.parse(res3);
    assert('Login without address succeeded', data3 && data3.status === 'success' && data3.session_token, `Received: ${res3}`);
    const sessionToken = data3.session_token;

    // 4. Test Address Injection Check
    console.log('\nRunning Test 4: Address Injection...');
    const res4 = await sendRaw(JSON.stringify({ action: 'update_address', session_token: sessionToken, address: 'if54.b32.i2p; rm -rf /' }));
    let data4 = JSON.parse(res4);
    assert('Address injection rejected', data4 && data4.status === 'error' && (data4.message.includes('verplicht') || data4.message.includes('adresformaat')), `Received: ${res4}`);
    assert('Server logged HACK POGING for address', serverOutput.includes('[HACK POGING] Update adres mislukt: adres is leeg of is geen geldig I2P Base32 adres') || serverOutput.includes('[HACK POGING] Mogelijk injectie-payload in adres gedetecteerd'));

    // 5. Test Session Token Tampering
    console.log('\nRunning Test 5: Session Token Tampering...');
    const res5 = await sendRaw(JSON.stringify({ action: 'update_address', session_token: 'bad_token_format', address: 'if54g5zpounalhl2ewljbijr5qqqupikemu2tccd2vji5ah7daqa.b32.i2p' }));
    let data5 = JSON.parse(res5);
    assert('Session token format tampering rejected', data5 && data5.status === 'error' && data5.message.includes('sessietoken'), `Received: ${res5}`);
    assert('Server logged HACK POGING for session token', serverOutput.includes('[HACK POGING] Ongeldig sessietoken formaat gedetecteerd'));

    // 6. Test Brute Force Detection
    console.log('\nRunning Test 6: Brute Force Detection...');
    for (let i = 0; i < 5; i++) {
      await sendRaw(JSON.stringify({ action: 'login', username: 'testuser', password: 'wrongpassword', address: '' }));
    }
    assert('Server logged HACK POGING for brute force', serverOutput.includes('[HACK POGING] Brute-force gedetecteerd voor gebruiker: testuser'));

  } catch(e) {
    console.error('Test execution failed:', e);
    failed++;
  } finally {
    // Shutdown PHP server
    console.log('\nStopping test Directory Server...');
    phpProc.kill();
    
    console.log('\n--- TESTS COMPLETED ---');
    console.log(`Passed: ${passed} / 10`);
    console.log(`Failed: ${failed} / 10`);
    
    process.exit(failed > 0 ? 1 : 0);
  }
}

runTests();

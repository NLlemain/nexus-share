'use strict';

const path = require('path');
const fs = require('fs');

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;

  for (const line of fs.readFileSync(filePath, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    const separator = trimmed.indexOf('=');
    if (separator <= 0) continue;

    const name = trimmed.slice(0, separator).trim();
    let value = trimmed.slice(separator + 1).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || Object.hasOwn(process.env, name)) continue;

    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    process.env[name] = value;
  }
}

loadEnvFile(path.join(__dirname, '..', '.env'));

function getIntegerEnv(name, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const value = process.env[name];
  if (value === undefined || value === '') return fallback;

  const parsed = Number.parseInt(value, 10);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}.`);
  }

  return parsed;
}

const authServerUrl = process.env.AUTH_SERVER_URL || '';
let parsedAuthUrl = null;
if (authServerUrl) {
  try {
    parsedAuthUrl = new URL(authServerUrl);
  } catch {
    throw new Error('AUTH_SERVER_URL must be a valid HTTP(S) URL.');
  }
}

const config = {
  uiPort: getIntegerEnv('UI_PORT', 3000, { max: 65535 }),
  publicDir: process.env.PUBLIC_DIR ? path.resolve(process.env.PUBLIC_DIR) : path.join(__dirname, '..', 'public'),
  receivedDir: process.env.RECEIVED_DIR ? path.resolve(process.env.RECEIVED_DIR) : path.join(__dirname, '..', 'received'),
  logFile: process.env.LOG_FILE ? path.resolve(process.env.LOG_FILE) : path.join(__dirname, '..', 'nexus.log'),
  maxUploadBytes: getIntegerEnv('MAX_UPLOAD_BYTES', 25 * 1024 * 1024),
  auth: {
    url: authServerUrl,
    useHttp: process.env.AUTH_USE_HTTP === '1' || parsedAuthUrl !== null,
    host: process.env.AUTH_HOST || (parsedAuthUrl ? parsedAuthUrl.hostname : '127.0.0.1'),
    port: getIntegerEnv(
      'AUTH_PORT_UI',
      parsedAuthUrl ? (parsedAuthUrl.port ? Number.parseInt(parsedAuthUrl.port, 10) : (parsedAuthUrl.protocol === 'https:' ? 443 : 80)) : 8000,
      { max: 65535 }
    ),
    path: process.env.AUTH_PATH || (parsedAuthUrl ? `${parsedAuthUrl.pathname}${parsedAuthUrl.search}` : '/server.php'),
    isHttps: parsedAuthUrl ? parsedAuthUrl.protocol === 'https:' : false,
  },
  i2p: {
    samHost: process.env.I2P_SAM_HOST || '127.0.0.1',
    samPort: getIntegerEnv('I2P_SAM_PORT', 7656, { max: 65535 }),
    socksHost: process.env.I2P_SOCKS_HOST || '127.0.0.1',
    socksPort: getIntegerEnv('I2P_SOCKS_PORT', 4447, { max: 65535 }),
    listenPort: getIntegerEnv('LISTEN_PORT', 9090, { max: 65535 }),
  },
  socketTimeout: getIntegerEnv('SOCKET_TIMEOUT', 30000),
};

module.exports = { config, getIntegerEnv };

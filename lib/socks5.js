'use strict';

const net = require('net');

const SOCKS_VERSION = 0x05;
const NO_AUTHENTICATION = 0x00;
const CONNECT_COMMAND = 0x01;
const DOMAIN_NAME_ADDRESS = 0x03;
const MAX_HANDSHAKE_BUFFER_BYTES = 1024;

/**
 * Establishes a SOCKS5 tunnel using the no-authentication method.
 * @param {{host: string, port: number, timeout: number}} proxy
 * @param {{host: string, port: number}} target
 * @param {(error: Error | null, socket?: import('net').Socket) => void} callback
 */
function connectSocks5(proxy, target, callback) {
  if (!proxy || !target || typeof callback !== 'function') {
    throw new TypeError('A proxy, target, and callback are required.');
  }
  if (!Number.isInteger(proxy.port) || proxy.port < 1 || proxy.port > 65535) {
    callback(new Error('SOCKS5 proxy port must be between 1 and 65535.'));
    return;
  }
  if (!Number.isInteger(target.port) || target.port < 1 || target.port > 65535) {
    callback(new Error('SOCKS5 target port must be between 1 and 65535.'));
    return;
  }

  let completed = false;
  const complete = (error, socket) => {
    if (completed) return;
    completed = true;
    callback(error, socket);
  };

  const socket = net.connect({ host: proxy.host, port: proxy.port });
  socket.setTimeout(Number.isInteger(proxy.timeout) && proxy.timeout > 0 ? proxy.timeout : 30000);

  let state = 'greeting';
  let buffer = Buffer.alloc(0);

  socket.once('connect', () => {
    socket.write(Buffer.from([SOCKS_VERSION, 0x01, NO_AUTHENTICATION]));
  });

  socket.on('timeout', () => {
    socket.destroy();
    complete(new Error('SOCKS5 handshake timed out.'));
  });

  socket.on('error', error => complete(error));

  socket.on('data', chunk => {
    if (buffer.length + chunk.length > MAX_HANDSHAKE_BUFFER_BYTES) {
      socket.destroy();
      complete(new Error('SOCKS5 handshake response exceeded the maximum size.'));
      return;
    }
    buffer = Buffer.concat([buffer, chunk]);

    if (state === 'greeting') {
      if (buffer.length < 2) return;
      const [version, method] = buffer;
      buffer = buffer.subarray(2);

      if (version !== SOCKS_VERSION || method !== NO_AUTHENTICATION) {
        socket.destroy();
        complete(new Error('SOCKS5 proxy does not support no-authentication mode.'));
        return;
      }

      const hostname = Buffer.from(target.host, 'utf8');
      if (hostname.length === 0 || hostname.length > 255) {
        socket.destroy();
        complete(new Error('SOCKS5 target hostname must be between 1 and 255 bytes.'));
        return;
      }

      const request = Buffer.alloc(7 + hostname.length);
      request.set([SOCKS_VERSION, CONNECT_COMMAND, 0x00, DOMAIN_NAME_ADDRESS, hostname.length]);
      hostname.copy(request, 5);
      request.writeUInt16BE(target.port, hostname.length + 5);
      state = 'connect';
      socket.write(request);
    }

    if (state === 'connect') {
      if (buffer.length < 5) return;
      const addressType = buffer[3];
      if (![0x01, DOMAIN_NAME_ADDRESS, 0x04].includes(addressType)) {
        socket.destroy();
        complete(new Error('SOCKS5 proxy returned an unsupported address type.'));
        return;
      }
      const addressLength = addressType === 0x01 ? 4 : addressType === 0x04 ? 16 : buffer[4];
      const responseLength = 4 + (addressType === DOMAIN_NAME_ADDRESS ? 1 : 0) + addressLength + 2;
      if (buffer.length < responseLength) return;

      const [version, reply] = buffer;
      buffer = buffer.subarray(responseLength);
      if (version !== SOCKS_VERSION || reply !== 0x00) {
        socket.destroy();
        complete(new Error(`SOCKS5 connection failed with reply code ${reply}.`));
        return;
      }

      socket.setTimeout(0);
      socket.removeAllListeners('data');
      if (buffer.length > 0) socket.unshift(buffer);
      complete(null, socket);
    }
  });
}

module.exports = { connectSocks5 };

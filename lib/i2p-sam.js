'use strict';

const crypto = require('crypto');
const net = require('net');

function createSamSession({ host, port }, callback) {
  let completed = false;
  const complete = (...args) => {
    if (completed) return;
    completed = true;
    callback(...args);
  };

  const sessionId = `p2psession-${crypto.randomBytes(4).toString('hex')}`;
  const socket = net.connect({ host, port });
  let state = 'hello';
  let buffer = Buffer.alloc(0);

  socket.once('connect', () => socket.write('HELLO VERSION MIN=3.0 MAX=3.1\n'));
  socket.on('error', error => complete(new Error(`Unable to connect to the I2P SAM bridge: ${error.message}`)));
  socket.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk]);
    let newline;
    while ((newline = buffer.indexOf(10)) !== -1) {
      const line = buffer.subarray(0, newline).toString('utf8').trim();
      buffer = buffer.subarray(newline + 1);
      if (!line.includes('RESULT=OK')) {
        socket.destroy();
        complete(new Error(`I2P SAM ${state} request failed: ${line}`));
        return;
      }

      if (state === 'hello') {
        state = 'session';
        socket.write(`SESSION CREATE STYLE=STREAM DESTINATION=TRANSIENT ID=${sessionId}\n`);
      } else if (state === 'session') {
        state = 'lookup';
        socket.write('NAMING LOOKUP NAME=ME\n');
      } else {
        const destination = line.split(' ').find(part => part.startsWith('VALUE='))?.slice(6);
        if (!destination) {
          socket.destroy();
          complete(new Error('I2P SAM bridge did not return a destination.'));
          return;
        }
        complete(null, { sessionId, destination, socket });
      }
    }
  });
}

function destinationToBase32(destination) {
  const bytes = Buffer.from(destination.replace(/-/g, '+').replace(/~/g, '/'), 'base64');
  const digest = crypto.createHash('sha256').update(bytes).digest();
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let value = 0;
  let bitCount = 0;
  let result = '';

  for (const byte of digest) {
    value = (value << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      result += alphabet[(value >>> (bitCount - 5)) & 31];
      bitCount -= 5;
    }
  }
  if (bitCount > 0) result += alphabet[(value << (5 - bitCount)) & 31];
  return `${result}.b32.i2p`;
}

module.exports = { createSamSession, destinationToBase32 };

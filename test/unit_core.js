'use strict';

const assert = require('assert');
const { TransferManager } = require('../lib/transfer-manager');
const { decodeBase64, normalizeFileName, sanitizeUsernameForPath } = require('../lib/validators');

function expectThrows(action, message) {
  assert.throws(action, undefined, message);
}

function testValidators() {
  assert.strictEqual(normalizeFileName('report 2026.txt'), 'report 2026.txt');
  expectThrows(() => normalizeFileName('../secret.txt'), 'Path traversal must be rejected.');
  expectThrows(() => normalizeFileName('nested/file.txt'), 'Path separators must be rejected.');
  assert.strictEqual(decodeBase64('aGVsbG8=').toString('utf8'), 'hello');
  expectThrows(() => decodeBase64('not base64!'), 'Malformed Base64 must be rejected.');
  assert.strictEqual(sanitizeUsernameForPath('alice@example.com'), 'alice_example_com');
}

function testTransferManager() {
  const manager = new TransferManager();
  manager.createSend('send-1', { filename: 'report.txt', target: 'bob', sent: 0, size: 5 });
  manager.completeSend('send-1', 5);

  manager.createReceive('receive-1', {
    filename: 'report.txt',
    sender: 'alice',
    received: 0,
    size: 5,
    acceptFn: () => {},
    declineFn: () => {},
  });

  const accepted = manager.acceptReceive('receive-1');
  assert.strictEqual(accepted.status, 'receiving');
  manager.completeReceiveByFile('alice', 'report.txt', 5);

  const snapshot = manager.snapshot();
  assert.strictEqual(snapshot.sends['send-1'].status, 'complete');
  assert.strictEqual(snapshot.sends['send-1'].sent, 5);
  assert.strictEqual(snapshot.receives['receive-1'].status, 'complete');
  assert.strictEqual(snapshot.receives['receive-1'].received, 5);
  assert.strictEqual(snapshot.receives['receive-1'].acceptFn, undefined);
}

testValidators();
testTransferManager();
console.log('Core module unit tests passed.');

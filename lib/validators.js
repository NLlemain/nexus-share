'use strict';

const path = require('path');

const USERNAME_PATTERN = /^[A-Za-z0-9_-]{3,32}$/;
const FILE_NAME_PATTERN = /^[A-Za-z0-9_. -]+$/;

function sanitizeUsernameForPath(username) {
  return String(username ?? '').replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 64);
}

function isValidUsername(username) {
  return typeof username === 'string' && USERNAME_PATTERN.test(username);
}

function normalizeFileName(filename) {
  if (typeof filename !== 'string' || filename.length === 0) {
    throw new Error('A filename is required.');
  }

  const normalized = path.basename(filename);
  if (
    normalized !== filename ||
    normalized === '.' ||
    normalized === '..' ||
    !FILE_NAME_PATTERN.test(normalized)
  ) {
    throw new Error('The filename contains unsupported characters or a path segment.');
  }

  return normalized;
}

function decodeBase64(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 4 !== 0) {
    throw new Error('Invalid Base64 payload.');
  }

  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error('Invalid Base64 payload.');
  }

  return Buffer.from(value, 'base64');
}

module.exports = {
  decodeBase64,
  isValidUsername,
  normalizeFileName,
  sanitizeUsernameForPath,
};

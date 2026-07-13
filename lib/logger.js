'use strict';

const fs = require('fs');

class ApplicationLogger {
  #entries = [];
  #stream;

  constructor({ filePath, maxEntries = 500 }) {
    this.maxEntries = maxEntries;
    this.#stream = fs.createWriteStream(filePath, { flags: 'a', mode: 0o600 });
  }

  info(message, metadata) {
    this.#write('INFO', message, metadata, console.log);
  }

  warn(message, metadata) {
    this.#write('WARN', message, metadata, console.warn);
  }

  error(message, metadata) {
    this.#write('ERROR', message, metadata, console.error);
  }

  entriesAfter(offset = 0) {
    const safeOffset = Number.isSafeInteger(offset) && offset >= 0 ? offset : 0;
    return this.#entries.slice(safeOffset);
  }

  close() {
    this.#stream.end();
  }

  #write(level, message, metadata, output) {
    const context = metadata ? ` ${JSON.stringify(metadata)}` : '';
    const line = `[${new Date().toISOString()}] [${level}] ${message}${context}`;
    output(line);
    this.#stream.write(`${line}\n`);
    this.#entries.push(line);
    if (this.#entries.length > this.maxEntries) this.#entries.shift();
  }
}

module.exports = { ApplicationLogger };

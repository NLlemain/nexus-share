'use strict';

class TransferManager {
  #sends = new Map();
  #receives = new Map();

  createSend(id, transfer) {
    this.#sends.set(id, { ...transfer, status: 'sending' });
  }

  createReceive(id, transfer) {
    this.#receives.set(id, { ...transfer, status: 'waiting_approval' });
  }

  getReceive(id) {
    return this.#receives.get(id);
  }

  acceptReceive(id) {
    const transfer = this.getReceive(id);
    if (!transfer || transfer.status !== 'waiting_approval') return null;
    transfer.status = 'receiving';
    return transfer;
  }

  declineReceive(id) {
    const transfer = this.getReceive(id);
    if (!transfer || transfer.status !== 'waiting_approval') return null;
    this.#receives.delete(id);
    return transfer;
  }

  completeSend(id, sent) {
    this.#complete(this.#sends, id, sent);
  }

  completeReceiveByFile(sender, filename, received) {
    for (const [id, transfer] of this.#receives) {
      if (transfer.sender === sender && transfer.filename === filename) {
        this.#complete(this.#receives, id, received);
        return;
      }
    }
  }

  failSend(id) {
    const transfer = this.#sends.get(id);
    if (transfer) {
      transfer.status = 'failed';
      this.#removeLater(this.#sends, id);
    }
  }

  reset() {
    this.#sends.clear();
    this.#receives.clear();
  }

  snapshot() {
    return {
      sends: Object.fromEntries(this.#sends.entries()),
      receives: Object.fromEntries([...this.#receives].map(([id, transfer]) => [id, this.#publicReceive(transfer)])),
    };
  }

  #complete(collection, id, received) {
    const transfer = collection.get(id);
    if (!transfer) return;
    transfer.status = 'complete';
    transfer.sent = transfer.target ? received : transfer.sent;
    transfer.received = transfer.sender ? received : transfer.received;
    this.#removeLater(collection, id);
  }

  #removeLater(collection, id) {
    setTimeout(() => collection.delete(id), 10_000).unref?.();
  }

  #publicReceive({ acceptFn, declineFn, ...transfer }) {
    return transfer;
  }
}

module.exports = { TransferManager };

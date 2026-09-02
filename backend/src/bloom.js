// Keyed Bloom filter for membership pre-checks — Section 5.2, "blind lookups".
//
// MFS-B needs to ask "is this destination wallet flagged" without MFS-A
// learning which wallets MFS-B is curious about, and without MFS-B being able
// to download MFS-A's flag list. The filter is keyed, so it cannot be
// enumerated offline; false positives are resolved by a private set
// intersection round before any hold is applied.
//
// The PSI round is out of scope for the prototype and is named as such in the
// README rather than faked.

import crypto from 'node:crypto';

const K = 7; // hash functions

export class KeyedBloom {
  constructor(bits = 1 << 16, key = crypto.randomBytes(32)) {
    this.bits = bits;
    this.key = key;
    this.buf = Buffer.alloc(Math.ceil(bits / 8));
    this.count = 0;
  }

  #positions(value) {
    const out = [];
    for (let i = 0; i < K; i++) {
      const h = crypto.createHmac('sha256', this.key).update(`${i}:${value}`).digest();
      out.push(h.readUInt32BE(0) % this.bits);
    }
    return out;
  }

  add(value) {
    for (const p of this.#positions(value)) {
      this.buf[p >> 3] |= 1 << (p & 7);
    }
    this.count++;
  }

  // A true answer means "possibly flagged, resolve it properly".
  // A false answer is definitive.
  maybeContains(value) {
    return this.#positions(value).every((p) => (this.buf[p >> 3] >> (p & 7)) & 1);
  }

  falsePositiveRate() {
    const m = this.bits, n = this.count;
    if (n === 0) return 0;
    return Math.pow(1 - Math.exp((-K * n) / m), K);
  }
}

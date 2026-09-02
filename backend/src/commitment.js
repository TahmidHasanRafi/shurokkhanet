// Keyed commitments — Section 5.2, Equation 3.
//
//   c = HMAC-SHA256( k_e , m || d )
//
// m is the identifier, d a domain separator, k_e a 256-bit epoch key that
// never touches the ledger. In production k_e lives in each member's HSM and
// is split into shares so no single organisation holds a whole key
// (Section 5.3). Here it is held by SoftHSM, or by a file for the demo.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// Domain separators. A different d per chaincode and per collection means the
// same subscriber has different commitments in each context, so a member
// cannot link them (Section 5.2, "domain separation").
export const DOMAIN = {
  ASSERTION_SRC: 'shurokkhanet/assertion/src/v1',
  ASSERTION_DST: 'shurokkhanet/assertion/dst/v1',
  SIGNAL_SUBJECT: 'shurokkhanet/signal/subject/v1',
  AGENT_REGISTRY: 'shurokkhanet/agent/v1',
  AUDIT_TARGET: 'shurokkhanet/audit/target/v1',
};

const KEY_DIR = process.env.SHUROKKHA_KEY_DIR || path.join(process.cwd(), '.keys');

/**
 * Epoch keys rotate quarterly. The epoch travels with the commitment on the
 * ledger so older commitments stay verifiable after a rotation.
 */
export function currentEpoch(at = new Date()) {
  return at.getUTCFullYear() * 4 + Math.floor(at.getUTCMonth() / 3) + 1;
}

function keyPath(epoch) {
  return path.join(KEY_DIR, `epoch-${epoch}.key`);
}

/**
 * Loads the epoch key, creating it on first use. Creating it here stands in
 * for the shared key ceremony described in Section 5.3 — the ceremony is a
 * governance event, not a code path, and the whitepaper should not pretend
 * otherwise.
 */
export function epochKey(epoch = currentEpoch()) {
  fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
  const p = keyPath(epoch);
  if (!fs.existsSync(p)) {
    fs.writeFileSync(p, crypto.randomBytes(32), { mode: 0o600 });
  }
  return fs.readFileSync(p);
}

/** c = HMAC-SHA256(k_e, m || d), hex encoded. */
export function commit(identifier, domain, epoch = currentEpoch()) {
  if (!identifier) throw new Error('identifier is required');
  if (!domain) throw new Error('domain separator is required');
  const h = crypto.createHmac('sha256', epochKey(epoch));
  h.update(String(identifier), 'utf8');
  h.update('\u0000', 'utf8'); // length-unambiguous concatenation
  h.update(domain, 'utf8');
  return h.digest('hex');
}

/**
 * The naive construction Section 5.1 rejects: a bare SHA-256 of a phone
 * number. Exported so the prototype can demonstrate the attack against it
 * rather than only assert that it works.
 */
export function nakedDigest(identifier) {
  return crypto.createHash('sha256').update(String(identifier), 'utf8').digest('hex');
}

/**
 * Salted, non-reversible handle written to the audit log. It proves a lookup
 * happened without the log becoming a second copy of the flag list
 * (Section 5.2, "blind lookups with an audit trail").
 */
export function auditHandle(commitment, epoch = currentEpoch()) {
  const h = crypto.createHmac('sha256', epochKey(epoch));
  h.update(commitment, 'utf8');
  h.update(DOMAIN.AUDIT_TARGET, 'utf8');
  return h.digest('hex').slice(0, 32);
}

/**
 * Amount bands. The exact figure stays in the private collection; the shared
 * channel sees only the band (Table 4). Bands are wide enough that the band
 * itself is not an identifier.
 */
export function amountBand(taka) {
  const n = Number(taka);
  if (!Number.isFinite(n) || n < 0) throw new Error('amount must be a non-negative number');
  if (n < 5_000) return 'BAND_LT_5K';
  if (n < 25_000) return 'BAND_5K_25K';
  if (n < 100_000) return 'BAND_25K_100K';
  if (n < 500_000) return 'BAND_100K_500K';
  if (n < 2_500_000) return 'BAND_500K_25L';
  return 'BAND_GT_25L';
}

/** SHA-256 over the JSON-canonicalised evidence bundle (RFC 8785 in spirit). */
export function evidenceDigest(bundle) {
  const canonical = canonicalise(bundle);
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

function canonicalise(v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonicalise).join(',') + ']';
  const keys = Object.keys(v).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalise(v[k])).join(',') + '}';
}

export function assertionId() {
  return crypto.randomBytes(16).toString('hex'); // random 128-bit, per Table 4
}

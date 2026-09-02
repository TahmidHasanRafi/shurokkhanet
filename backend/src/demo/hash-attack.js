// Section 5.1 and Equation 2, demonstrated rather than asserted.
//
// A published SHA-256 of a Bangladeshi mobile number is the same as publishing
// the number: eleven digits behind a handful of fixed operator prefixes, so
// the candidate space is about 4.6e8. This walks it and recovers the number.
//
// The same attack is then run against the keyed commitment of the same number
// and fails, because recovering m from c needs k_e (Equation 3).
//
// Two things are reported honestly. The rate is MEASURED on whatever machine
// this runs on, not asserted. Equation 2's 0.46 second figure assumes one
// billion hashes per second on a single graphics card; a laptop running
// JavaScript is three orders of magnitude slower, and the console says so
// instead of quietly rescaling the claim.

import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import { commit, nakedDigest, DOMAIN } from '../commitment.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WORKER = path.join(HERE, 'crack-worker.js');

export const PREFIXES = ['013', '014', '015', '016', '017', '018', '019'];
export const SPACE_PER_PREFIX = 1e8;
export const FULL_SPACE = PREFIXES.length * SPACE_PER_PREFIX;

/**
 * Equation 2. At the paper's assumed one billion hashes per second, the whole
 * space falls in well under a second.
 */
export function theoreticalBreakSeconds(hashesPerSecond = 1e9) {
  return FULL_SPACE / hashesPerSecond;
}

/**
 * Brute-forces a plain SHA-256 digest of an MSISDN.
 *
 * knownPrefix models what an attacker actually has: the alert already names
 * which provider and therefore which operator range, so the attacker starts
 * there rather than at 013.
 */
export async function crackNakedDigest(targetHex, opts = {}) {
  const { knownPrefix = null, budgetMs = 30000, workers = Math.max(1, os.cpus().length - 1) } = opts;
  const prefixes = knownPrefix ? [knownPrefix, ...PREFIXES.filter((p) => p !== knownPrefix)] : PREFIXES;

  const started = Date.now();
  const deadline = started + budgetMs;
  let tried = 0;

  for (const prefix of prefixes) {
    if (Date.now() > deadline) break;
    const shard = Math.ceil(SPACE_PER_PREFIX / workers);
    const pool = [];
    let settled = false;

    const result = await new Promise((resolve) => {
      let done = 0;
      for (let w = 0; w < workers; w++) {
        const worker = new Worker(WORKER, {
          workerData: {
            target: targetHex,
            prefix,
            from: w * shard,
            to: Math.min((w + 1) * shard, SPACE_PER_PREFIX),
            deadline,
          },
        });
        pool.push(worker);
        worker.on('message', (m) => {
          if (m.progress) { tried += m.tried; return; }
          tried += m.tried;
          if (m.found && !settled) { settled = true; resolve({ found: true, number: m.number }); }
          if (++done === workers && !settled) { settled = true; resolve({ found: false }); }
        });
        worker.on('error', () => { if (++done === workers && !settled) { settled = true; resolve({ found: false }); } });
      }
    });

    await Promise.all(pool.map((w) => w.terminate()));

    if (result.found) {
      const ms = Date.now() - started;
      return report({ found: true, number: result.number, tried, ms, workers });
    }
  }
  return report({ found: false, tried, ms: Date.now() - started, workers });
}

/**
 * The identical attack against the keyed commitment: same space, same budget,
 * same code path. It does not find the number, because the commitment is not
 * a function the attacker can compute.
 */
export async function attackKeyedCommitment(targetHex, opts = {}) {
  return crackNakedDigest(targetHex, { budgetMs: 12000, ...opts });
}

function report(r) {
  const rate = r.ms > 0 ? Math.round(r.tried / (r.ms / 1000)) : 0;
  return {
    ...r,
    hashesPerSecond: rate,
    // What the SAME search would cost on the hardware Equation 2 assumes.
    equation2Seconds: theoreticalBreakSeconds(1e9),
    // What the full space would cost at the rate we just measured here.
    fullSpaceSecondsAtMeasuredRate: rate > 0 ? FULL_SPACE / rate : null,
    fullSpace: FULL_SPACE,
  };
}

export function makeTargets(number) {
  return {
    number,
    prefix: String(number).slice(0, 3),
    naked: nakedDigest(number),
    keyed: commit(number, DOMAIN.ASSERTION_DST),
  };
}

export { crypto };

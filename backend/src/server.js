// ShurokkhaNet REST adapter — Section 4.10.
//
// This is the fraud operations layer, the thin thing that sits between a
// member's existing risk engine and the ledger. It does three jobs that the
// chaincode deliberately does not:
//
//   1. Holds the epoch key and turns wallet identifiers into commitments,
//      so no plaintext identifier ever reaches a peer (Section 5.2).
//   2. Records every membership check in audit-cc before answering it.
//   3. Measures t_p — the real one, from the raising member's clock to the
//      moment the other member's event listener sees the alert.

import express from 'express';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { MockLedger } from './mock.js';
import {
  commit, amountBand, evidenceDigest, assertionId, currentEpoch, auditHandle, DOMAIN,
} from './commitment.js';
import { crackNakedDigest, attackKeyedCommitment, makeTargets, theoreticalBreakSeconds } from './demo/hash-attack.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3000);
const MOCK = process.env.MOCK_MODE === '1' || !process.env.FABRIC_SAMPLES;

let ledger;
if (MOCK) {
  ledger = await MockLedger.create();
  console.warn('\n  MOCK MODE. No Fabric network is attached.');
  console.warn('  Chaincode rules are reimplemented in memory for interface work only.');
  console.warn('  Set FABRIC_SAMPLES and unset MOCK_MODE for the real ledger.\n');
} else {
  const { FabricLedger } = await import('./fabric.js');
  ledger = await FabricLedger.create();
  console.log('Connected to Fabric on channel', process.env.CHANNEL_NAME || 'shurokkhanet');
}

// assertionId -> the raising member's clock at submit. Kept here rather than
// on the ledger, because it is a measurement, not a fact about the case.
const raisedAt = new Map();

const app = express();
app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(HERE, '..', '..', 'frontend')));

const seatOf = (req) => {
  const s = req.get('x-seat') || req.body?.seat || req.query.seat || 'MFS-A';
  if (!['MFS-A', 'MFS-B', 'OVERSIGHT'].includes(s)) throw new Error(`unknown seat ${s}`);
  return s;
};

const wrap = (fn) => async (req, res) => {
  try {
    res.json(await fn(req, res));
  } catch (err) {
    // Chaincode rejections arrive with a lot of gRPC scaffolding. Show the
    // sentence the contract actually wrote, because in this system a refusal
    // is a feature and the operator needs to read it.
    const raw = err?.details?.[0]?.message || err.message || String(err);
    const clean = raw.replace(/^.*?chaincode response 500,?\s*/i, '').trim();
    res.status(400).json({ error: clean || raw });
  }
};

app.get('/api/status', wrap(async () => ({
  mock: !!ledger.mock,
  channel: process.env.CHANNEL_NAME || 'shurokkhanet',
  epoch: currentEpoch(),
  ruleVersion: 'rules-2026.08.1',
  seats: {
    'MFS-A': 'Org1MSP — victim-side provider',
    'MFS-B': 'Org2MSP — destination-side provider',
    'OVERSIGHT': 'Org3MSP — Bangladesh Bank / BFIU',
  },
})));

// --- Fraud officer console ------------------------------------------------

// Raise an alert. Wallet identifiers arrive here in the clear from the
// member's own case system and are turned into commitments before anything
// leaves this process.
app.post('/api/alerts', wrap(async (req) => {
  const seat = seatOf(req);
  const { srcWallet, dstWallet, amount, caseRef, victimStatement, fraudAt, reportedAt } = req.body;
  if (!srcWallet || !dstWallet) throw new Error('srcWallet and dstWallet are required');

  const epoch = currentEpoch();
  const id = assertionId();
  const bundle = {
    caseRef, srcWallet, dstWallet, amount,
    reportedAt: reportedAt || Math.floor(Date.now() / 1000),
    fraudAt: fraudAt || null,
  };

  const t0 = Date.now();
  raisedAt.set(id, t0);

  const out = await ledger.submit(seat, 'assertion-cc', 'RaiseAssertion', [
    id,
    commit(srcWallet, DOMAIN.ASSERTION_SRC, epoch),
    commit(dstWallet, DOMAIN.ASSERTION_DST, epoch),
    amountBand(amount || 0),
    evidenceDigest(bundle),
    epoch,
  ], {
    caseRef: caseRef || '',
    exactAmount: Number(amount || 0),
    srcWallet, dstWallet,
    victimStatement: victimStatement || '',
    reportedAt: bundle.reportedAt,
    fraudAt: bundle.fraudAt || 0,
  });

  return { ...out, assertionId: id, raisedAt: t0 };
}));

app.post('/api/alerts/:id/corroborate', wrap(async (req) =>
  ledger.submit(seatOf(req), 'assertion-cc', 'Corroborate', [req.params.id, req.body.evidenceDigest || ''])));

app.post('/api/alerts/:id/escalate', wrap(async (req) =>
  ledger.submit(seatOf(req), 'assertion-cc', 'EndorseT3', [req.params.id, req.body.basis || ''])));

app.post('/api/alerts/:id/renew', wrap(async (req) =>
  ledger.submit(seatOf(req), 'assertion-cc', 'RenewT3', [req.params.id])));

app.post('/api/alerts/:id/reverse', wrap(async (req) =>
  ledger.submit(seatOf(req), 'assertion-cc', 'Reverse', [
    req.params.id, req.body.reason || '', req.body.wrongfulHold === true,
  ])));

app.post('/api/alerts/:id/expire', wrap(async (req) =>
  ledger.submit(seatOf(req), 'assertion-cc', 'Expire', [req.params.id])));

app.get('/api/alerts/:id', wrap(async (req) => {
  const seat = seatOf(req);
  const a = await ledger.evaluate(seat, 'assertion-cc', 'GetAssertion', [req.params.id]);
  const tp = ledger.propagationMs(req.params.id, raisedAt.get(req.params.id));
  let reversal = null;
  try { reversal = (await ledger.evaluate(seat, 'assertion-cc', 'GetReversal', [req.params.id])).result; } catch { /* none */ }
  return { ...a, propagationMs: tp, reversal };
}));

app.get('/api/alerts', wrap(async (req) => {
  const out = await ledger.evaluate(seatOf(req), 'assertion-cc', 'ListAssertions', []);
  const list = (out.result || []).map((a) => ({ ...a, propagationMs: ledger.propagationMs(a.assertionId, raisedAt.get(a.assertionId)) }));
  return { ...out, result: list.sort((x, y) => y.assertedAt - x.assertedAt) };
}));

// --- The hot path ---------------------------------------------------------

// MFS-B asks whether a destination wallet is under a hold, before letting a
// cash-out through. The lookup is written to audit-cc first, so a member that
// asks about wallets it has no business with leaves a trail (Section 5.2).
app.post('/api/check', wrap(async (req) => {
  const seat = seatOf(req);
  const { wallet, purpose } = req.body;
  if (!wallet) throw new Error('wallet is required');
  const epoch = currentEpoch();
  const c = commit(wallet, DOMAIN.ASSERTION_DST, epoch);

  const started = Date.now();
  const hits = await ledger.evaluate(seat, 'assertion-cc', 'CheckCommitment', [c]);
  const active = (hits.result || []).filter((a) => a.status === 'ACTIVE');

  const audit = await ledger.submit(seat, 'audit-cc', 'RecordLookup', [
    crypto.randomBytes(8).toString('hex'),
    auditHandle(c, epoch),
    purpose || 'cash-out authorisation',
    active.length > 0,
  ]);

  const top = active.sort((a, b) => tierRank(b.tier) - tierRank(a.tier))[0] || null;
  return {
    commitment: c,
    held: !!top,
    tier: top?.tier || null,
    decision: decisionFor(top),
    assertions: active,
    lookupMs: Date.now() - started,
    audit: audit.result,
    mock: !!ledger.mock,
  };
}));

const tierRank = (t) => ({ T1: 1, T2: 2, T3: 3 }[t] || 0);

// Section 4.6. T1 stops cash-out only, because cash-out is the step that
// cannot be undone; person-to-person and merchant payments keep working.
function decisionFor(a) {
  if (!a) return { cashOut: 'ALLOW', transfer: 'ALLOW', note: 'No active hold on this wallet.' };
  if (a.tier === 'T1') return { cashOut: 'BLOCK', transfer: 'ALLOW', note: 'Soft hold. Cash-out blocked, payments continue, step-up authentication applied.' };
  if (a.tier === 'T2') return { cashOut: 'BLOCK', transfer: 'BLOCK', note: 'Outgoing transfers and cash-out held. Customer notified with the appeal route.' };
  return { cashOut: 'BLOCK', transfer: 'BLOCK', note: 'Full freeze pending investigation.' };
}

// --- Private collection ---------------------------------------------------

app.get('/api/case/:id', wrap(async (req) => ledger.evaluate(seatOf(req), 'assertion-cc', 'GetCaseFile', [req.params.id])));

// Anyone can confirm the private payload matches the hash on the shared
// channel, without seeing the payload. This is the "hash present, contents
// absent" demonstration in Section 10.
app.get('/api/case/:id/verify', wrap(async (req) => ledger.evaluate(seatOf(req), 'assertion-cc', 'VerifyCaseFile', [req.params.id])));

// --- Oversight ------------------------------------------------------------

app.post('/api/breakglass', wrap(async (req) => {
  const { assertionId: id, purpose, approver1, approver2, windowSeconds } = req.body;
  const rec = await ledger.submit('OVERSIGHT', 'audit-cc', 'RecordBreakGlass', [
    crypto.randomBytes(8).toString('hex'), id || '', purpose || '',
    approver1 || '', approver2 || '', Number(windowSeconds || 900),
  ]);
  // The record is written BEFORE the read. If the read fails, the attempt is
  // still on the ledger, which is the point.
  const file = await ledger.evaluate('OVERSIGHT', 'assertion-cc', 'GetCaseFile', [id]);
  return { access: rec.result, caseFile: file.result };
}));

app.get('/api/audit/:type', wrap(async (req) => ledger.evaluate(seatOf(req), 'audit-cc', 'AuditTrail', [req.params.type.toUpperCase()])));

// --- Signals --------------------------------------------------------------

app.post('/api/signals', wrap(async (req) => {
  const { msisdn, signalType, occurredAt } = req.body;
  const epoch = currentEpoch();
  return ledger.submit(seatOf(req), 'signal-cc', 'PublishSignal', [
    crypto.randomBytes(8).toString('hex'),
    commit(msisdn, DOMAIN.SIGNAL_SUBJECT, epoch),
    signalType || 'SIM_SWAP',
    Number(occurredAt || Math.floor(Date.now() / 1000)),
    epoch,
  ]);
}));

app.post('/api/simswap', wrap(async (req) => {
  const { msisdn, withinSeconds } = req.body;
  return ledger.evaluate(seatOf(req), 'signal-cc', 'CheckSimSwap', [
    commit(msisdn, DOMAIN.SIGNAL_SUBJECT, currentEpoch()),
    Number(withinSeconds || 86400),
  ]);
}));

// --- Explorer -------------------------------------------------------------

app.get('/api/events', wrap(async () => ({ events: ledger.recentEvents() })));

// --- Section 5.1 demonstration -------------------------------------------

app.get('/api/demo/targets', wrap(async (req) => {
  const number = String(req.query.msisdn || '01712000000');
  return { ...makeTargets(number), equation2Seconds: theoreticalBreakSeconds(1e9) };
}));

app.post('/api/demo/crack', wrap(async (req) => {
  const { digest, prefix, budgetMs, keyed } = req.body;
  if (!digest) throw new Error('digest is required');
  const run = keyed ? attackKeyedCommitment : crackNakedDigest;
  return run(digest, { knownPrefix: prefix || null, budgetMs: Number(budgetMs || 30000) });
}));

const server = app.listen(PORT, () => {
  console.log(`ShurokkhaNet consoles on http://localhost:${PORT}`);
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, async () => {
    server.close();
    await ledger.close();
    process.exit(0);
  });
}

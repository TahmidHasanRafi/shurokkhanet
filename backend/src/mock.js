// In-memory stand-in for the Fabric network.
//
// This exists so the consoles can be built and rehearsed without Docker
// running. It reimplements the chaincode's rules — tier thresholds, expiry,
// who may do what, collection visibility — so behaviour matches, but it is NOT
// a ledger: there is no endorsement, no ordering, no tamper evidence.
//
// Every response it produces is tagged mock:true, and the consoles show a
// banner. A demo recorded in this mode would be a demo of a web app, not of a
// consortium ledger, and should not be presented as one.

import crypto from 'node:crypto';

const T1 = 6 * 3600, T2 = 24 * 3600, T3 = 72 * 3600;
const MSP = { 'MFS-A': 'Org1MSP', 'MFS-B': 'Org2MSP', 'OVERSIGHT': 'Org3MSP' };
const isOversight = (seat) => seat === 'OVERSIGHT';

const nowS = () => Math.floor(Date.now() / 1000);

export class MockLedger {
  constructor() {
    this.mock = true;
    this.assertions = new Map();
    this.cases = new Map();
    this.reversals = new Map();
    this.lookups = [];
    this.breakGlass = [];
    this.signals = [];
    this.events = [];
    this.propagation = new Map();
    this.block = 6;
  }

  static async create() { return new MockLedger(); }

  #settle(a) {
    if (a.status === 'ACTIVE' && nowS() >= a.expiresAt) a.status = 'EXPIRED';
    return a;
  }

  #emit(name, payload) {
    this.block++;
    this.events.unshift({ name, blockNumber: this.block, at: Date.now(), payload });
    this.events = this.events.slice(0, 200);
    if (payload.assertionId) this.propagation.set(payload.assertionId, Date.now());
  }

  propagationMs(id, raisedAt) {
    const seen = this.propagation.get(id);
    return seen && raisedAt ? Math.max(seen - raisedAt, 1) : null;
  }

  recentEvents() { return this.events; }

  async submit(seat, cc, fn, args, transient) {
    const started = Date.now();
    const result = this.#dispatch(seat, cc, fn, args, transient);
    return {
      result, mock: true,
      txId: crypto.randomBytes(16).toString('hex'),
      blockNumber: this.block,
      endorseMs: Date.now() - started,
      commitMs: Date.now() - started,
    };
  }

  async evaluate(seat, cc, fn, args) {
    const started = Date.now();
    return { result: this.#dispatch(seat, cc, fn, args), mock: true, ms: Date.now() - started };
  }

  #dispatch(seat, cc, fn, args, transient) {
    const msp = MSP[seat];
    const t = nowS();

    switch (`${cc}.${fn}`) {
      case 'assertion-cc.RaiseAssertion': {
        const [assertionId, srcCommit, dstCommit, amountBand, evidenceDigest, epoch] = args;
        if (isOversight(seat)) throw new Error(`${msp} is an oversight member and cannot raise alerts (Table 7)`);
        if (this.assertions.has(assertionId)) throw new Error(`assertion ${assertionId} already exists`);
        let collectionHash = '';
        if (transient) {
          const payload = { ...transient, assertionId, filedByOrg: msp };
          this.cases.set(assertionId, payload);
          collectionHash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
        }
        const a = {
          docType: 'ASSERT', assertionId, srcCommit, dstCommit, amountBand,
          tier: 'T1', status: 'ACTIVE', assertedAt: t, expiresAt: t + T1,
          evidenceDigest, assertingOrg: msp, officerCert: `mock:${msp}`,
          ruleVersion: 'rules-2026.08.1', collectionHash, epoch: Number(epoch),
          corroborations: [msp],
        };
        this.assertions.set(assertionId, a);
        this.#emit('AssertionRaised', a);
        return a;
      }

      case 'assertion-cc.Corroborate': {
        const [id, digest] = args;
        const a = this.#settle(this.#need(id));
        if (isOversight(seat)) throw new Error('oversight members do not corroborate; use EndorseT3');
        if (a.status !== 'ACTIVE') throw new Error(`assertion ${id} is ${a.status} and cannot be corroborated`);
        if (a.corroborations.includes(msp)) throw new Error(`${msp} already corroborated ${id}`);
        a.corroborations.push(msp);
        if (a.corroborations.length >= 2 && a.tier === 'T1') { a.tier = 'T2'; a.expiresAt = t + T2; }
        if (digest) a.evidenceDigest = digest;
        this.#emit('TierChanged', a);
        return a;
      }

      case 'assertion-cc.EndorseT3': {
        const [id, basis] = args;
        if (!isOversight(seat)) throw new Error(`Tier 3 needs BFIU endorsement; ${msp} is not an oversight member`);
        if (!basis) throw new Error('a basis is required: BFIU endorsement or a filed police complaint');
        const a = this.#settle(this.#need(id));
        if (a.status !== 'ACTIVE') throw new Error(`assertion ${id} is ${a.status}`);
        if (!a.collectionHash) throw new Error(`no case file on record for ${id}; Tier 3 requires evidence`);
        a.tier = 'T3'; a.expiresAt = t + T3; a.bfiuEndorsedBy = msp;
        this.#emit('TierChanged', a);
        return a;
      }

      case 'assertion-cc.RenewT3': {
        const [id] = args;
        if (!isOversight(seat)) throw new Error('only an oversight member can renew a Tier 3 hold');
        const a = this.#settle(this.#need(id));
        if (a.tier !== 'T3') throw new Error(`assertion ${id} is at ${a.tier}, not Tier 3`);
        a.expiresAt = t + T3;
        this.#emit('TierRenewed', a);
        return a;
      }

      case 'assertion-cc.Reverse': {
        const [id, reason, wrongful] = args;
        const a = this.#need(id);
        if (msp !== a.assertingOrg && !isOversight(seat)) {
          throw new Error(`${msp} cannot reverse an alert raised by ${a.assertingOrg}`);
        }
        if (a.status === 'REVERSED') throw new Error(`assertion ${id} is already reversed`);
        const wrongfulHold = wrongful === true || wrongful === 'true';
        const r = {
          docType: 'REVERSAL', assertionId: id, reason, wrongfulHold,
          heldSeconds: t - a.assertedAt, decidedBy: msp, decidedAt: t,
          tariffApplied: wrongfulHold,
        };
        a.status = 'REVERSED';
        this.reversals.set(id, r);
        this.#emit('AssertionReversed', r);
        return r;
      }

      case 'assertion-cc.Expire': {
        const a = this.#settle(this.#need(args[0]));
        return a;
      }

      case 'assertion-cc.GetAssertion': return this.#settle(this.#need(args[0]));

      case 'assertion-cc.CheckCommitment':
        return [...this.assertions.values()].filter((a) => a.dstCommit === args[0]).map((a) => this.#settle(a));

      case 'assertion-cc.GetCaseFile': {
        const cf = this.cases.get(args[0]);
        if (!cf) throw new Error(`no case file for ${args[0]} in this collection`);
        return cf;
      }

      case 'assertion-cc.VerifyCaseFile': {
        const a = this.#need(args[0]);
        if (!a.collectionHash) throw new Error(`no collection entry for ${args[0]}`);
        return a.collectionHash;
      }

      case 'assertion-cc.GetReversal': {
        const r = this.reversals.get(args[0]);
        if (!r) throw new Error(`no reversal for ${args[0]}`);
        return r;
      }

      case 'assertion-cc.ListAssertions':
        return [...this.assertions.values()].map((a) => this.#settle(a));

      case 'audit-cc.RecordLookup': {
        const [lookupId, targetHash, purpose, hit] = args;
        const windowCount = this.lookups.filter((l) => l.byOrg === msp && l.at >= t - 60).length + 1;
        const rec = {
          docType: 'LOOKUP', lookupId, byOrg: msp, targetHash,
          hit: hit === true || hit === 'true', at: t, windowCount,
          overBudget: windowCount > 20, purpose,
        };
        this.lookups.push(rec);
        if (rec.overBudget) this.#emit('LookupBudgetExceeded', rec);
        return rec;
      }

      case 'audit-cc.RecordBreakGlass': {
        const [accessId, assertionId, purpose, a1, a2, windowSeconds] = args;
        if (!isOversight(seat)) throw new Error(`emergency access is available to oversight members only; ${msp} is not one`);
        if (!a1 || !a2 || a1 === a2) throw new Error('two distinct named approvers are required');
        if (!purpose) throw new Error('a stated purpose is required');
        const rec = {
          docType: 'BREAKGLASS', accessId, byOrg: msp, assertionId, purpose,
          approver1: a1, approver2: a2, windowFrom: t, windowTo: t + Number(windowSeconds), at: t,
        };
        this.breakGlass.push(rec);
        this.#emit('EmergencyAccess', rec);
        return rec;
      }

      case 'audit-cc.AuditTrail': {
        if (args[0] === 'LOOKUP') return this.lookups;
        if (args[0] === 'BREAKGLASS') return this.breakGlass;
        return [];
      }

      case 'signal-cc.PublishSignal': {
        const [signalId, subjectCommit, signalType, occurredAt, epoch] = args;
        if (seat === 'MFS-A' || seat === 'MFS-B') {
          throw new Error(`only a licensed mobile operator or BTRC may publish signals; ${msp} may not`);
        }
        const sig = {
          docType: 'SIGNAL', signalId, subjectCommit, signalType,
          occurredAt: Number(occurredAt), publishedAt: t, byOrg: msp, epoch: Number(epoch),
        };
        this.signals.push(sig);
        this.#emit('SignalPublished', sig);
        return sig;
      }

      case 'signal-cc.CheckSimSwap': {
        const [subjectCommit, within] = args;
        const cutoff = t - Number(within);
        const hits = this.signals.filter((s) => s.subjectCommit === subjectCommit && s.signalType === 'SIM_SWAP' && s.occurredAt >= cutoff);
        return {
          subjectCommit, swapped: hits.length > 0,
          lastSwapAt: hits.length ? Math.max(...hits.map((h) => h.occurredAt)) : undefined,
          withinSeconds: Number(within),
        };
      }

      default:
        throw new Error(`mock ledger does not implement ${cc}.${fn}`);
    }
  }

  #need(id) {
    const a = this.assertions.get(id);
    if (!a) throw new Error(`assertion ${id} not found`);
    return a;
  }

  async close() { /* nothing to close */ }
}

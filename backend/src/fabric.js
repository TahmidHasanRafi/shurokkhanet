// Fabric Gateway adapter. One connection per consortium seat, because the
// whole point of the design is that MFS-A and MFS-B act under their own
// signing identities and neither can act as the other.
//
// Section 4.10: integration sits at the fraud operations layer. This file is
// that layer's client, not a replacement for anything in core banking.

import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import * as grpc from '@grpc/grpc-js';
import { connect, hash, signers } from '@hyperledger/fabric-gateway';

const utf8 = new TextDecoder();
const enc = new TextEncoder();

const CHANNEL = process.env.CHANNEL_NAME || 'shurokkhanet';
const SAMPLES = process.env.FABRIC_SAMPLES;

// Consortium seat -> test-network organisation (see network/scripts/env.sh).
export const ORGS = {
  'MFS-A': { org: 'org1', mspId: 'Org1MSP', peer: 'peer0.org1.example.com', port: 7051, label: 'MFS-A (victim side)' },
  'MFS-B': { org: 'org2', mspId: 'Org2MSP', peer: 'peer0.org2.example.com', port: 9051, label: 'MFS-B (destination side)' },
  'OVERSIGHT': { org: 'org3', mspId: 'Org3MSP', peer: 'peer0.org3.example.com', port: 11051, label: 'Bangladesh Bank / BFIU' },
};

function orgRoot(org) {
  return path.join(SAMPLES, 'test-network', 'organizations', 'peerOrganizations', `${org}.example.com`);
}

async function firstFile(dir) {
  const files = await fs.readdir(dir);
  if (!files.length) throw new Error(`no files in ${dir}`);
  return path.join(dir, files[0]);
}

async function newGrpc(cfg) {
  const tlsCert = await fs.readFile(path.join(orgRoot(cfg.org), 'peers', cfg.peer, 'tls', 'ca.crt'));
  return new grpc.Client(`localhost:${cfg.port}`, grpc.credentials.createSsl(tlsCert), {
    'grpc.ssl_target_name_override': cfg.peer,
  });
}

async function newIdentitySigner(cfg) {
  const userDir = path.join(orgRoot(cfg.org), 'users', `User1@${cfg.org}.example.com`, 'msp');
  const certPath = await firstFile(path.join(userDir, 'signcerts'));
  const keyPath = await firstFile(path.join(userDir, 'keystore'));
  const credentials = await fs.readFile(certPath);
  const privateKey = crypto.createPrivateKey(await fs.readFile(keyPath));
  return {
    identity: { mspId: cfg.mspId, credentials },
    signer: signers.newPrivateKeySigner(privateKey),
    certFingerprint: crypto.createHash('sha256').update(credentials).digest('hex').slice(0, 16),
  };
}

export class FabricLedger {
  constructor() {
    this.gateways = new Map();
    this.clients = [];
    // assertionId -> ms since epoch when MFS-B's listener saw the event.
    // This is the measured t_p in Equation 1, not a modelled one.
    this.propagation = new Map();
    this.events = [];
    this.mock = false;
  }

  static async create() {
    if (!SAMPLES) throw new Error('FABRIC_SAMPLES is not set');
    const l = new FabricLedger();
    for (const [seat, cfg] of Object.entries(ORGS)) {
      const client = await newGrpc(cfg);
      const { identity, signer, certFingerprint } = await newIdentitySigner(cfg);
      const gateway = connect({
        client, identity, signer, hash: hash.sha256,
        evaluateOptions: () => ({ deadline: Date.now() + 5000 }),
        endorseOptions: () => ({ deadline: Date.now() + 15000 }),
        submitOptions: () => ({ deadline: Date.now() + 5000 }),
        commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
      });
      l.clients.push(client);
      l.gateways.set(seat, { gateway, cfg, certFingerprint });
    }
    await l.#listen('MFS-B');
    return l;
  }

  contract(seat, name) {
    const g = this.gateways.get(seat);
    if (!g) throw new Error(`unknown seat ${seat}`);
    return g.gateway.getNetwork(CHANNEL).getContract(name);
  }

  // MFS-B's risk engine listening for cross-provider alerts. The timestamp
  // taken here is the honest end of t_p: it is when the other institution
  // could first have acted.
  async #listen(seat) {
    const network = this.gateways.get(seat).gateway.getNetwork(CHANNEL);
    const it = await network.getChaincodeEvents('assertion-cc');
    (async () => {
      try {
        for await (const ev of it) {
          const at = Date.now();
          let payload = {};
          try { payload = JSON.parse(utf8.decode(ev.payload)); } catch { /* opaque event */ }
          if (payload.assertionId) this.propagation.set(payload.assertionId, at);
          this.events.unshift({ name: ev.eventName, blockNumber: Number(ev.blockNumber), at, payload });
          this.events = this.events.slice(0, 200);
        }
      } catch { /* listener closed */ }
    })();
    this.eventIterator = it;
  }

  propagationMs(assertionId, raisedAt) {
    const seen = this.propagation.get(assertionId);
    return seen && raisedAt ? seen - raisedAt : null;
  }

  recentEvents() { return this.events; }

  async submit(seat, cc, fn, args, transient) {
    const contract = this.contract(seat, cc);
    const opts = { arguments: args.map(String) };
    if (transient) opts.transientData = { case: enc.encode(JSON.stringify(transient)) };
    const started = Date.now();
    const proposal = contract.newProposal(fn, opts);
    const txn = await proposal.endorse();
    const endorsedAt = Date.now();
    const committed = await txn.submit();
    const status = await committed.getStatus();
    if (!status.successful) throw new Error(`transaction ${status.transactionId} failed: ${status.code}`);
    let result = null;
    try { result = JSON.parse(utf8.decode(txn.getResult())); } catch { /* void */ }
    return {
      result,
      txId: status.transactionId,
      blockNumber: Number(status.blockNumber),
      endorseMs: endorsedAt - started,
      commitMs: Date.now() - started,
    };
  }

  async evaluate(seat, cc, fn, args) {
    const started = Date.now();
    const bytes = await this.contract(seat, cc).evaluateTransaction(fn, ...args.map(String));
    const text = utf8.decode(bytes);
    let result = null;
    if (text) { try { result = JSON.parse(text); } catch { result = text; } }
    return { result, ms: Date.now() - started };
  }

  async close() {
    try { this.eventIterator?.close(); } catch { /* already closed */ }
    for (const { gateway } of this.gateways.values()) gateway.close();
    for (const c of this.clients) c.close();
  }
}

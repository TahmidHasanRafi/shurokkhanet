# ShurokkhaNet — working prototype

Team Syndicate Busters · Blockchain Olympiad Bangladesh 2026

A permissioned consortium ledger that lets one mobile financial services provider's fraud
detection produce action inside another provider's system, before stolen money reaches a
cash-out agent. This repository is the prototype for the whitepaper: three Fabric contracts,
a REST adapter at the fraud operations layer, and the operator consoles.

---

## Why this is on Hyperledger Fabric and not a public chain

Your own whitepaper answers this in Table 3, and the prototype has to agree with it or the
judges will find the gap in Q&A. Putting the argument here so it is easy to give back:

**A public chain, Sepolia included, cannot carry this system.**

1. **Fraud flags cannot be public.** On a public chain every alert is world-readable forever.
   A flagged wallet commitment plus a timestamp plus an amount band is competitive
   intelligence about a rival's customer base, and it never expires. Section 3.2 point 4 is
   the reason the largest provider would refuse to join.
2. **Private data collections are load-bearing, not a nice-to-have.** The entire privacy
   argument in Section 5 rests on two institutions sharing a case file that no third party
   sees, while everyone can still verify it has not changed. There is no equivalent on a
   public EVM chain. Encrypting the payload and putting the ciphertext on-chain is not the
   same thing: the ciphertext is permanent, so "destroy the key, not the record"
   (Section 5.5, point 2) stops being an erasure story and becomes a bet that the cipher
   holds for as long as the chain exists.
3. **Retention law.** Fabric can be told to delete collection data when the retention window
   closes. A public chain cannot delete anything. The Personal Data Protection Act argument
   in Section 5.5 does not survive the move.
4. **Timing.** The budget is `t_p < 3 s` at the 95th percentile. Sepolia blocks are ~12 s and
   finality is longer. That alone rules it out for Equation 1.
5. **Legality.** Section 4.9: Bangladesh Bank prohibits cryptocurrency. Anything requiring a
   public token to pay gas cannot be operated by a licensed institution here.
6. **Identity.** Members must be licensed institutions with revocable certificates
   (Section 6.1). Fabric MSPs give that natively; a public chain gives pseudonymous
   addresses and you would have to rebuild the whole membership layer on top.

**Your Sepolia experience still transfers.** The parts that carry over are the ones that
matter: transaction lifecycle, keys and signing, events and listeners, and a client library
that submits and then waits for commitment. What is new is three things —
*endorsement before ordering* (several organisations must run and agree on the same
transaction before it is ordered), *MSPs* (a caller has an organisational identity, not just
an address), and *private data collections* (state that only some organisations hold).

**If Fabric will not stand up in time,** the documented fallback in Table 3 is Besu or
Quorum in IBFT mode, where your Solidity and ethers.js knowledge applies directly. Take that
route only as a last resort and say so in the presentation, because you lose private data
collections and with them most of Section 5. It is a weaker submission, not a different one.

---

## What is here

```
chaincode/assertion/   assertion-cc  alerts, tiers, expiry, reversal, private collection
chaincode/audit/       audit-cc      lookups, break-glass, rule versions
chaincode/signal/      signal-cc     SIM swap and device signals, GSMA-shaped
network/               collections config and lifecycle scripts
backend/               REST adapter, commitment library, Bloom filter, Section 5.1 attack
frontend/              fraud desk, cash-out counter, oversight, ledger and commitment consoles
```

## Running it

### Option A — consoles only, no Fabric (5 minutes)

Use this to build and rehearse the interface. It reimplements the contract rules in memory.
**Do not record the demo video in this mode**; the consoles show a warning banner and you
would be demonstrating a web app, not a ledger.

```bash
cd backend
npm install
npm run mock
# http://localhost:3000
```

### Option B — the real network (the one to record)

Prerequisites: Docker, Docker Compose, Go 1.21+, Node 20+, and a `fabric-samples` checkout
with the 2.5 binaries.

```bash
# once
curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh | bash -s -- --fabric-version 2.5.9
export FABRIC_SAMPLES=$PWD/fabric-samples

# every session
cd network/scripts
./up.sh          # test-network + addOrg3, channel 'shurokkhanet', CouchDB, TLS
./deploy.sh      # package, install on all three orgs, approve, commit
./smoke.sh       # end-to-end check straight from the peer CLI

cd ../../backend
npm install
FABRIC_SAMPLES=$FABRIC_SAMPLES npm start
```

Seats map onto test-network organisations:

| Console seat | Org | MSP | Consortium role |
|---|---|---|---|
| MFS-A | org1 | Org1MSP | victim-side provider |
| MFS-B | org2 | Org2MSP | destination-side provider |
| BFIU | org3 | Org3MSP | Bangladesh Bank / BFIU oversight |

To show automatic collection deletion, redeploy with the short retention window:

```bash
COLLECTIONS=$PWD/../collections/assertion_collections_demo.json SEQ=2 ./deploy.sh
```

After roughly 40 blocks the case file is gone from the collection while the hash stays on
the shared channel — `VerifyCaseFile` still answers, `GetCaseFile` no longer does.

---

## The demo, in the order Section 10 lists it

Each of these is a real transaction, not a scripted animation.

1. **The commitment scheme under attack.** *Commitments* tab. Compute both digests for a
   number, then attack each. The plain SHA-256 falls; the keyed commitment does not. The
   console reports the rate measured on your laptop and the Equation 2 extrapolation
   separately, so nobody can accuse you of quietly rescaling the claim.

2. **A hold across a boundary.** *Fraud desk* as MFS-A: raise the alert. The clock draws
   `t_r` (what you entered), `t_p` (measured from MFS-B's event listener) and `t_a`
   (measured endorsement) against the assumed `t_c`. Then *Cash-out counter* as MFS-B:
   check the destination wallet. It refuses the payout at Tier 1 while leaving normal
   payments alone.

3. **Being wrong safely.** Corroborate as MFS-B to reach Tier 2. Switch to BFIU, escalate to
   Tier 3 with a basis, then reverse it as a wrongful hold. The reversal entry, the held
   duration and the tariff flag all land on the ledger. Say out loud that the entry is
   written whether or not you were wrong — that is what turns Equation 4 into a real cost.

4. **A blind lookup.** *Cash-out counter*: "Run 25 lookups in a burst". The contract answers
   every one and marks the rows past the per-member budget. The point is not that the sweep
   is blocked; it is that it is now signed, attributable and chargeable.

5. **The regulator under observation.** *Oversight* as BFIU: emergency access with two named
   approvers. The break-glass record is written to the shared channel before the private
   read happens. Show the plaintext wallet numbers appearing, then point out they came from
   the collection and never crossed the shared channel.

6. **Hash present, contents absent.** *Ledger* tab: verify the collection hash from a seat
   in the collection, then read the contents. On the real network, add a fourth organisation
   and verify from there to show the hash resolving while the read is refused.

Rehearsed order for a five-minute video: 1 → 2 → 4 → 3 → 5 → 6.

---

## What this prototype does not do

Say these before a judge finds them.

- **Three organisations, not four.** The whitepaper's Section 10 says four organisations and
  RAFT across three. This runs Org1/Org2/Org3 on the test-network topology. The trust
  separation is the same; the fourth seat (a mobile operator) is added with the same
  `addOrg` pattern. Until it exists, `signal-cc` lets the oversight seat stand in as BTRC,
  and the code says so in a comment rather than hiding it.
- **No HSM.** The epoch key is a file under `.keys/`. Section 5.3 calls for SoftHSM in the
  prototype and split shares in production. The commitment construction is the real one; the
  custody is not.
- **No private set intersection.** `backend/src/bloom.js` implements the keyed Bloom filter.
  The PSI round that resolves its false positives before a hold is applied is described in
  Section 5.2 and is not built.
- **No zero-knowledge circuits, no live operator integration, no token, no mobile app.**
  These were excluded on purpose in Section 10 and remain excluded.
- **`t_c` is assumed, not measured.** The clock draws the cash-out wall at 300 seconds
  because we do not have the distribution. That is Appendix A item 1 and Section 4.7's open
  question, and the console labels it "assumed" on screen rather than presenting it as data.

---

## Things in the whitepaper worth fixing before the final round

Found while building against it.

1. **Section 4.8 has a heading and no body.** "On chain and off chain" runs straight into
   Table 6. Same in **Section 8.1**, "Direct competition", which runs straight into Table 11.
   A judge reading the PDF will see two empty sections.
2. **Equation 2's prefix count.** The text says "the four or five prefixes in use" and gets
   4.6×10⁸. Bangladesh has seven live mobile prefixes — 013, 014, 015, 016, 017, 018, 019 —
   which gives 7×10⁸ and about 0.7 seconds. The conclusion is unchanged and the larger figure
   is easier to defend. The prototype uses seven.
3. **Section 2.4's percentages sum to 107.** 52.6 + 42.1 + 12.3 does not partition anything.
   If the TIB categories overlap, one clause saying so protects the number; as written it
   reads like an arithmetic error.
4. **Table 5 says holds are "graded by evidence", and the code agrees, but the whitepaper
   never states what happens when two members disagree** — one raises, another has evidence
   the transfer was legitimate. The contract currently has no counter-assertion. Either add
   one to Section 4.6 or say plainly that the appeal route is the only channel.

Everything else checked out arithmetically: the Tk 742.56 million unrecovered figure, all
three rows of Table 9, and the 21 percent break-even in Equation 6.

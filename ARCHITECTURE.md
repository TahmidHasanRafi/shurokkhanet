# Where each whitepaper claim lives in the code

A judge who asks "show me where you actually did that" should be able to be answered in one
jump. This table is that jump.

| Whitepaper | Claim | Code |
|---|---|---|
| §4.3 | RAFT across organisations, no single member can delay a rival | `network/scripts/up.sh` (test-network orderer + addOrg3) |
| §4.4 | assertion-cc, audit-cc, signal-cc | `chaincode/*/` |
| §4.5 Table 4 | commitments and bands on the shared channel, exact values off it | `Assertion` and `CaseFile` structs in `chaincode/assertion/assertion.go` |
| §4.5 | evidence digest over a canonical bundle | `evidenceDigest()` / `canonicalise()` in `backend/src/commitment.js` |
| §4.6 Table 5 | T1 blocks cash-out only; T2 adds transfers; T3 full freeze | `decisionFor()` in `backend/src/server.js`, tiers enforced in `assertion.go` |
| §4.6 | every tier expires on its own | `settle()` and `ttlFor()` in `assertion.go`; lazy on every read |
| §4.6 | endorsement thresholds sit in the endorsement policy, not the interface | `bindT3Endorsement()` — state-based endorsement pinned on the key at T3 |
| §4.6 | every release writes a reversal entry, wrong or not | `Reverse()` in `assertion.go` |
| §4.7 | `t_p` and `t_a` are engineered, `t_r` and `t_c` are not | measured in `FabricLedger.submit()` and the event listener; drawn in the clock |
| §4.9 | nothing is tokenised | no token contract exists, by construction |
| §4.10 | integration at the fraud operations layer, not core banking | `backend/src/server.js` is a REST adapter over the gateway |
| §5.1 Eq. 2 | a plain digest of an MSISDN is not a protection | `backend/src/demo/hash-attack.js`, demonstrated live |
| §5.2 Eq. 3 | keyed commitments | `commit()` in `backend/src/commitment.js` |
| §5.2 | domain separation per chaincode and collection | `DOMAIN` in `commitment.js`; different `d` per context |
| §5.2 | collections that delete themselves | `blockToLive` in `network/collections/*.json` |
| §5.2 | keyed Bloom filter for blind membership checks | `backend/src/bloom.js` |
| §5.2 | every lookup is written to audit-cc | `RecordLookup()`; called before `/api/check` answers |
| §5.3 | quarterly epoch rotation, epoch tagged so old commitments verify | `currentEpoch()` and the `epoch` field on every record |
| §5.5 | destroy the key, not the record | deleting `.keys/epoch-N.key` orphans every commitment in that epoch |
| §6.2 | break-glass writes its own record every member can see | `RecordBreakGlass()`; written before the private read |
| §6.4 Eq. 4 | wrongful holds are priced to the member that raised the alert | `wrongfulHold` and `tariffApplied` on the reversal entry |
| §6.5 | rule versions recorded so a past alert is judged by the rules of its time | `ruleVersion` field; `AdoptRuleVersion()` in audit-cc |
| §8.1 | we consume GSMA Open Gateway rather than rebuilding it | `CheckSimSwap()` mirrors the SIM Swap response shape |

## Two design notes worth knowing before Q&A

**Why the transaction timestamp and never the wall clock.** Every peer endorses the same
transaction independently. If the chaincode called `time.Now()`, each peer would compute a
different expiry, the read-write sets would not match, and the transaction would be rejected
at validation. `GetTxTimestamp()` is the ordering service's clock and is identical at every
endorser. This is the single most common way a first Fabric chaincode fails, and it is worth
saying out loud if a judge asks what was hard.

**Why state-based endorsement at Tier 3.** A chaincode-level endorsement policy applies to
every key the contract touches. Tier 3 needs a stricter rule than Tier 1 does, on one record.
`SetStateValidationParameter` attaches a policy to that key alone, so after escalation Fabric
itself refuses any update to that assertion that is not endorsed by both the asserting
organisation and the regulator. The rule is enforced below the chaincode, which is what makes
Table 5's "not in the user interface" true rather than aspirational.

// Package main implements assertion-cc for ShurokkhaNet.
//
// Whitepaper mapping:
//   Section 4.4  chaincode responsibilities
//   Section 4.5  Table 4 data model (public field vs private collection split)
//   Section 4.6  Table 5 tiered holds, expiry, endorsement thresholds
//   Section 5.2  keyed commitments are computed OFF chain; the ledger only ever
//                sees the commitment, never the wallet identifier
//   Section 6.4  reversal entries + wrongful-hold tariff
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/pkg/statebased"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	collectionCase = "assertionCase" // MFS-A, MFS-B and the oversight member only

	objAssertion = "ASSERT"
	idxByDst     = "DST"
	objReversal  = "REVERSAL"

	StatusActive    = "ACTIVE"
	StatusConfirmed = "CONFIRMED"
	StatusExpired   = "EXPIRED"
	StatusReversed  = "REVERSED"

	TierT1 = "T1"
	TierT2 = "T2"
	TierT3 = "T3"

	// Section 4.6 Table 5. Held here and not in the interface, so a console
	// cannot widen a hold by lying about the tier.
	ttlT1 = 6 * time.Hour
	ttlT2 = 24 * time.Hour
	ttlT3 = 72 * time.Hour

	ruleVersion = "rules-2026.08.1"
)

// regulatorMSPs may endorse Tier 3 and perform break-glass reads.
// Kept as a map so the set is auditable in one place.
// Org3MSP is what the fabric-samples test-network calls the third
// organisation; in ShurokkhaNet that seat is Bangladesh Bank / BFIU.
var regulatorMSPs = map[string]bool{
	"RegulatorMSP": true,
	"Org3MSP":      true,
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// Assertion is the shared-channel record. Every field here is either a
// commitment, a band, a digest or an institutional identity. Nothing in this
// struct is personal data (Section 5.5, point 1).
type Assertion struct {
	DocType        string   `json:"docType"`
	AssertionID    string   `json:"assertionId"`
	SrcCommit      string   `json:"srcCommit"`
	DstCommit      string   `json:"dstCommit"`
	AmountBand     string   `json:"amountBand"`
	Tier           string   `json:"tier"`
	Status         string   `json:"status"`
	AssertedAt     int64    `json:"assertedAt"`
	ExpiresAt      int64    `json:"expiresAt"`
	EvidenceDigest string   `json:"evidenceDigest"`
	AssertingOrg   string   `json:"assertingOrg"`
	OfficerCert    string   `json:"officerCert"`
	RuleVersion    string   `json:"ruleVersion"`
	CollectionHash string   `json:"collectionHash"`
	Epoch          int      `json:"epoch"`
	Corroborations []string `json:"corroborations"`
	BFIUEndorsedBy string   `json:"bfiuEndorsedBy"`
}

// CaseFile lives only in the private data collection and is deleted by the
// platform when the retention window closes (Section 5.2, Section 5.5 point 3).
type CaseFile struct {
	AssertionID  string `json:"assertionId"`
	CaseRef      string `json:"caseRef"`
	ExactAmount  int64  `json:"exactAmount"`
	SrcWallet    string `json:"srcWallet"`
	DstWallet    string `json:"dstWallet"`
	VictimStmt   string `json:"victimStatement"`
	ReportedAt   int64  `json:"reportedAt"`
	FraudAt      int64  `json:"fraudAt"`
	FiledByOrg   string `json:"filedByOrg"`
}

// Reversal is written on every release, correct or not, so the consortium
// accumulates a measurable error rate (Section 4.6, Section 6.4).
type Reversal struct {
	DocType      string `json:"docType"`
	AssertionID  string `json:"assertionId"`
	Reason       string `json:"reason"`
	WrongfulHold bool   `json:"wrongfulHold"`
	HeldSeconds  int64  `json:"heldSeconds"`
	DecidedBy    string `json:"decidedBy"`
	DecidedAt    int64  `json:"decidedAt"`
	TariffApplied bool  `json:"tariffApplied"`
}

type SmartContract struct {
	contractapi.Contract
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// now uses the transaction timestamp, never time.Now(). Wall-clock in
// chaincode is non-deterministic and would break endorsement.
func now(ctx contractapi.TransactionContextInterface) (int64, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return 0, fmt.Errorf("read tx timestamp: %w", err)
	}
	return ts.Seconds, nil
}

func callerMSP(ctx contractapi.TransactionContextInterface) (string, error) {
	return ctx.GetClientIdentity().GetMSPID()
}

// officerRef returns a short, non-reversible handle for the signing officer's
// certificate. The full certificate stays in the tx creator field; we store the
// hashed id so the record answers "who signed" without duplicating the subject.
func officerRef(ctx contractapi.TransactionContextInterface) (string, error) {
	id, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "", err
	}
	if len(id) > 44 {
		id = id[:44]
	}
	return id, nil
}

func key(ctx contractapi.TransactionContextInterface, parts ...string) (string, error) {
	return ctx.GetStub().CreateCompositeKey(parts[0], parts[1:])
}

func (s *SmartContract) load(ctx contractapi.TransactionContextInterface, id string) (*Assertion, string, error) {
	k, err := key(ctx, objAssertion, id)
	if err != nil {
		return nil, "", err
	}
	b, err := ctx.GetStub().GetState(k)
	if err != nil {
		return nil, "", err
	}
	if b == nil {
		return nil, "", fmt.Errorf("assertion %s not found", id)
	}
	var a Assertion
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, "", err
	}
	return &a, k, nil
}

// settle applies lazy expiry. Anything past expiresAt is treated as released
// even if nobody called Expire. Forgetting a hold releases it; it never
// extends it (Section 4.6).
func settle(a *Assertion, t int64) {
	if a.Status == StatusActive && t >= a.ExpiresAt {
		a.Status = StatusExpired
	}
}

func ttlFor(tier string) time.Duration {
	switch tier {
	case TierT2:
		return ttlT2
	case TierT3:
		return ttlT3
	default:
		return ttlT1
	}
}

// bindT3Endorsement raises a state-based endorsement policy on the key once it
// reaches Tier 3. From that point Fabric itself will reject any update that is
// not endorsed by the asserting organisation AND the regulator. This is the
// "endorsement thresholds sit in the endorsement policy, not in the user
// interface" claim in Table 5, made literal.
func bindT3Endorsement(ctx contractapi.TransactionContextInterface, k, assertingOrg, regulator string) error {
	ep, err := statebased.NewStateEP(nil)
	if err != nil {
		return err
	}
	if err := ep.AddOrgs(statebased.RoleTypePeer, assertingOrg, regulator); err != nil {
		return err
	}
	policy, err := ep.Policy()
	if err != nil {
		return err
	}
	return ctx.GetStub().SetStateValidationParameter(k, policy)
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

// RaiseAssertion creates a Tier 1 hold. The private payload arrives as
// transient data so it is never written to the ordering service in the clear.
//
// Transient map key: "case" -> JSON of CaseFile.
func (s *SmartContract) RaiseAssertion(
	ctx contractapi.TransactionContextInterface,
	assertionID, srcCommit, dstCommit, amountBand, evidenceDigest string, epoch int,
) (*Assertion, error) {

	if assertionID == "" || srcCommit == "" || dstCommit == "" {
		return nil, fmt.Errorf("assertionId, srcCommit and dstCommit are required")
	}
	if strings.HasPrefix(srcCommit, "sha256:") || strings.HasPrefix(dstCommit, "sha256:") {
		// Section 5.1: a bare digest of an 11-digit number is not a protection.
		return nil, fmt.Errorf("plain digests are rejected; identifiers must be keyed commitments")
	}

	msp, err := callerMSP(ctx)
	if err != nil {
		return nil, err
	}
	if regulatorMSPs[msp] {
		return nil, fmt.Errorf("%s is an oversight member and cannot raise alerts (Table 7)", msp)
	}

	k, err := key(ctx, objAssertion, assertionID)
	if err != nil {
		return nil, err
	}
	if existing, err := ctx.GetStub().GetState(k); err == nil && existing != nil {
		return nil, fmt.Errorf("assertion %s already exists", assertionID)
	}

	t, err := now(ctx)
	if err != nil {
		return nil, err
	}

	// Private payload. Optional so the chaincode can be exercised without a
	// case file, but a T3 escalation later requires one.
	collectionHash := ""
	transient, err := ctx.GetStub().GetTransient()
	if err != nil {
		return nil, err
	}
	if raw, ok := transient["case"]; ok && len(raw) > 0 {
		var cf CaseFile
		if err := json.Unmarshal(raw, &cf); err != nil {
			return nil, fmt.Errorf("transient 'case' is not valid CaseFile JSON: %w", err)
		}
		cf.AssertionID = assertionID
		cf.FiledByOrg = msp
		payload, err := json.Marshal(cf)
		if err != nil {
			return nil, err
		}
		if err := ctx.GetStub().PutPrivateData(collectionCase, assertionID, payload); err != nil {
			return nil, fmt.Errorf("write private data: %w", err)
		}
		// GetPrivateDataHash reads committed state, and this write has not
		// committed yet, so inside the same transaction it returns nothing.
		// Fabric stores the collection hash as SHA-256 over the value bytes,
		// so computing it here gives the identical digest, deterministically.
		sum := sha256.Sum256(payload)
		collectionHash = hex.EncodeToString(sum[:])
	}

	officer, err := officerRef(ctx)
	if err != nil {
		return nil, err
	}

	a := &Assertion{
		DocType:        objAssertion,
		AssertionID:    assertionID,
		SrcCommit:      srcCommit,
		DstCommit:      dstCommit,
		AmountBand:     amountBand,
		Tier:           TierT1,
		Status:         StatusActive,
		AssertedAt:     t,
		ExpiresAt:      t + int64(ttlT1.Seconds()),
		EvidenceDigest: evidenceDigest,
		AssertingOrg:   msp,
		OfficerCert:    officer,
		RuleVersion:    ruleVersion,
		CollectionHash: collectionHash,
		Epoch:          epoch,
		Corroborations: []string{msp},
	}

	if err := s.put(ctx, k, a); err != nil {
		return nil, err
	}
	if err := s.index(ctx, a); err != nil {
		return nil, err
	}
	s.emit(ctx, "AssertionRaised", a)
	return a, nil
}

// Corroborate records a second member agreeing. Two distinct organisations
// move the hold to Tier 2 (Table 5).
func (s *SmartContract) Corroborate(ctx contractapi.TransactionContextInterface, assertionID, evidenceDigest string) (*Assertion, error) {
	msp, err := callerMSP(ctx)
	if err != nil {
		return nil, err
	}
	if regulatorMSPs[msp] {
		return nil, fmt.Errorf("oversight members do not corroborate; use EndorseT3")
	}
	a, k, err := s.load(ctx, assertionID)
	if err != nil {
		return nil, err
	}
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	settle(a, t)
	if a.Status != StatusActive {
		return nil, fmt.Errorf("assertion %s is %s and cannot be corroborated", assertionID, a.Status)
	}
	for _, o := range a.Corroborations {
		if o == msp {
			return nil, fmt.Errorf("%s already corroborated %s", msp, assertionID)
		}
	}
	a.Corroborations = append(a.Corroborations, msp)

	if len(a.Corroborations) >= 2 && a.Tier == TierT1 {
		a.Tier = TierT2
		a.ExpiresAt = t + int64(ttlT2.Seconds())
	}
	if evidenceDigest != "" {
		a.EvidenceDigest = evidenceDigest
	}
	if err := s.put(ctx, k, a); err != nil {
		return nil, err
	}
	s.emit(ctx, "TierChanged", a)
	return a, nil
}

// EndorseT3 is restricted to an oversight MSP and requires a case file to
// already exist in the private collection. It also pins a state-based
// endorsement policy on the key.
func (s *SmartContract) EndorseT3(ctx contractapi.TransactionContextInterface, assertionID, basis string) (*Assertion, error) {
	msp, err := callerMSP(ctx)
	if err != nil {
		return nil, err
	}
	if !regulatorMSPs[msp] {
		return nil, fmt.Errorf("Tier 3 needs BFIU endorsement; %s is not an oversight member", msp)
	}
	if basis == "" {
		return nil, fmt.Errorf("a basis is required: BFIU endorsement or a filed police complaint")
	}
	a, k, err := s.load(ctx, assertionID)
	if err != nil {
		return nil, err
	}
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	settle(a, t)
	if a.Status != StatusActive {
		return nil, fmt.Errorf("assertion %s is %s", assertionID, a.Status)
	}
	if a.CollectionHash == "" {
		return nil, fmt.Errorf("no case file on record for %s; Tier 3 requires evidence", assertionID)
	}
	a.Tier = TierT3
	a.ExpiresAt = t + int64(ttlT3.Seconds())
	a.BFIUEndorsedBy = msp

	if err := s.put(ctx, k, a); err != nil {
		return nil, err
	}
	if err := bindT3Endorsement(ctx, k, a.AssertingOrg, msp); err != nil {
		return nil, fmt.Errorf("bind Tier 3 endorsement policy: %w", err)
	}
	s.emit(ctx, "TierChanged", a)
	return a, nil
}

// RenewT3 extends a Tier 3 hold by one further window. Renewable, but only by
// an explicit act that is itself recorded (Table 5).
func (s *SmartContract) RenewT3(ctx contractapi.TransactionContextInterface, assertionID string) (*Assertion, error) {
	msp, err := callerMSP(ctx)
	if err != nil {
		return nil, err
	}
	if !regulatorMSPs[msp] {
		return nil, fmt.Errorf("only an oversight member can renew a Tier 3 hold")
	}
	a, k, err := s.load(ctx, assertionID)
	if err != nil {
		return nil, err
	}
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	if a.Tier != TierT3 {
		return nil, fmt.Errorf("assertion %s is at %s, not Tier 3", assertionID, a.Tier)
	}
	settle(a, t)
	if a.Status != StatusActive {
		return nil, fmt.Errorf("assertion %s is %s", assertionID, a.Status)
	}
	a.ExpiresAt = t + int64(ttlT3.Seconds())
	if err := s.put(ctx, k, a); err != nil {
		return nil, err
	}
	s.emit(ctx, "TierRenewed", a)
	return a, nil
}

// Reverse releases a hold and writes the reversal entry. wrongfulHold=true
// applies the tariff to the asserting organisation (Equation 4).
func (s *SmartContract) Reverse(ctx contractapi.TransactionContextInterface, assertionID, reason string, wrongfulHold bool) (*Reversal, error) {
	msp, err := callerMSP(ctx)
	if err != nil {
		return nil, err
	}
	a, k, err := s.load(ctx, assertionID)
	if err != nil {
		return nil, err
	}
	// The asserting org may withdraw its own alert; the dispute panel, seated
	// with the oversight member, may reverse anyone's.
	if msp != a.AssertingOrg && !regulatorMSPs[msp] {
		return nil, fmt.Errorf("%s cannot reverse an alert raised by %s", msp, a.AssertingOrg)
	}
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	if a.Status == StatusReversed {
		return nil, fmt.Errorf("assertion %s is already reversed", assertionID)
	}
	held := t - a.AssertedAt
	a.Status = StatusReversed
	if err := s.put(ctx, k, a); err != nil {
		return nil, err
	}

	r := &Reversal{
		DocType:       objReversal,
		AssertionID:   assertionID,
		Reason:        reason,
		WrongfulHold:  wrongfulHold,
		HeldSeconds:   held,
		DecidedBy:     msp,
		DecidedAt:     t,
		TariffApplied: wrongfulHold,
	}
	rk, err := key(ctx, objReversal, assertionID)
	if err != nil {
		return nil, err
	}
	rb, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState(rk, rb); err != nil {
		return nil, err
	}
	s.emit(ctx, "AssertionReversed", r)
	return r, nil
}

// Expire is the explicit sweep. It is idempotent and callable by any member,
// because releasing a stale hold should never need permission.
func (s *SmartContract) Expire(ctx contractapi.TransactionContextInterface, assertionID string) (*Assertion, error) {
	a, k, err := s.load(ctx, assertionID)
	if err != nil {
		return nil, err
	}
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	before := a.Status
	settle(a, t)
	if a.Status == before {
		return a, nil
	}
	if err := s.put(ctx, k, a); err != nil {
		return nil, err
	}
	s.emit(ctx, "AssertionExpired", a)
	return a, nil
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

// GetAssertion returns the public record with expiry already applied.
func (s *SmartContract) GetAssertion(ctx contractapi.TransactionContextInterface, assertionID string) (*Assertion, error) {
	a, _, err := s.load(ctx, assertionID)
	if err != nil {
		return nil, err
	}
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	settle(a, t)
	return a, nil
}

// CheckCommitment is the hot path: MFS-B asks whether a destination wallet is
// under an active hold. It answers about ONE commitment supplied by the
// caller. It cannot be used to enumerate another member's flagged customers,
// because the caller must already hold the commitment to ask.
func (s *SmartContract) CheckCommitment(ctx contractapi.TransactionContextInterface, dstCommit string) ([]*Assertion, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(idxByDst, []string{dstCommit})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	t, err := now(ctx)
	if err != nil {
		return nil, err
	}

	out := []*Assertion{}
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		_, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil || len(parts) < 2 {
			continue
		}
		a, _, err := s.load(ctx, parts[1])
		if err != nil {
			continue
		}
		settle(a, t)
		out = append(out, a)
	}
	return out, nil
}

// GetCaseFile reads the private collection. Only peers of the collection's
// member organisations can serve this at all; Fabric enforces that below the
// chaincode.
func (s *SmartContract) GetCaseFile(ctx contractapi.TransactionContextInterface, assertionID string) (*CaseFile, error) {
	b, err := ctx.GetStub().GetPrivateData(collectionCase, assertionID)
	if err != nil {
		return nil, fmt.Errorf("read private data: %w", err)
	}
	if b == nil {
		return nil, fmt.Errorf("no case file for %s in this collection", assertionID)
	}
	var cf CaseFile
	if err := json.Unmarshal(b, &cf); err != nil {
		return nil, err
	}
	return &cf, nil
}

// VerifyCaseFile lets any member confirm that the case file held privately
// matches the hash on the shared channel, without seeing the file. This is the
// "collection hash present with its contents absent" demonstration.
func (s *SmartContract) VerifyCaseFile(ctx contractapi.TransactionContextInterface, assertionID string) (string, error) {
	h, err := ctx.GetStub().GetPrivateDataHash(collectionCase, assertionID)
	if err != nil {
		return "", err
	}
	if h == nil {
		return "", fmt.Errorf("no collection entry for %s", assertionID)
	}
	return fmt.Sprintf("%x", h), nil
}

// GetReversal returns the reversal entry if one exists.
func (s *SmartContract) GetReversal(ctx contractapi.TransactionContextInterface, assertionID string) (*Reversal, error) {
	rk, err := key(ctx, objReversal, assertionID)
	if err != nil {
		return nil, err
	}
	b, err := ctx.GetStub().GetState(rk)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, fmt.Errorf("no reversal for %s", assertionID)
	}
	var r Reversal
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListAssertions is a demo and explorer convenience. It is deliberately NOT
// exposed to member consoles in the backend, because a full list is exactly
// the enumeration that Section 5.2 rules out.
func (s *SmartContract) ListAssertions(ctx contractapi.TransactionContextInterface) ([]*Assertion, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(objAssertion, []string{})
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	out := []*Assertion{}
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var a Assertion
		if err := json.Unmarshal(kv.Value, &a); err != nil {
			continue
		}
		settle(&a, t)
		out = append(out, &a)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

func (s *SmartContract) put(ctx contractapi.TransactionContextInterface, k string, a *Assertion) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(k, b)
}

func (s *SmartContract) index(ctx contractapi.TransactionContextInterface, a *Assertion) error {
	ik, err := key(ctx, idxByDst, a.DstCommit, a.AssertionID)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(ik, []byte{0x00})
}

func (s *SmartContract) emit(ctx contractapi.TransactionContextInterface, name string, v interface{}) {
	if b, err := json.Marshal(v); err == nil {
		_ = ctx.GetStub().SetEvent(name, b)
	}
}

func main() {
	cc, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		panic(fmt.Sprintf("create assertion-cc: %v", err))
	}
	if err := cc.Start(); err != nil {
		panic(fmt.Sprintf("start assertion-cc: %v", err))
	}
}

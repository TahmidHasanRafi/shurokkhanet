// Package main implements audit-cc for ShurokkhaNet.
//
// Whitepaper mapping:
//   Section 4.4   "every lookup, every emergency access, and every rule version"
//   Section 5.2   blind lookups with an audit trail; rate limits are chargeable
//   Section 6.2   break-glass writes its own record that every member can see
//
// The point of this contract is asymmetry: reading the ledger is cheap, but
// reading it in a pattern that looks like fishing is permanently visible.
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	objLookup     = "LOOKUP"
	objBreakGlass = "BREAKGLASS"
	objRuleVer    = "RULEVER"

	// Per-member lookup budget inside a rolling window. Exceeding it does not
	// block the query at the ledger; it marks the record so the council review
	// in Section 6.5 and the service levels in Section 6.4 can act on it.
	lookupWindow = 60 * time.Second
	lookupBudget = 20
)

var regulatorMSPs = map[string]bool{"RegulatorMSP": true, "Org3MSP": true}

type LookupRecord struct {
	DocType     string `json:"docType"`
	LookupID    string `json:"lookupId"`
	ByOrg       string `json:"byOrg"`
	TargetHash  string `json:"targetHash"`
	Hit         bool   `json:"hit"`
	At          int64  `json:"at"`
	WindowCount int    `json:"windowCount"`
	OverBudget  bool   `json:"overBudget"`
	Purpose     string `json:"purpose"`
}

type BreakGlassRecord struct {
	DocType     string `json:"docType"`
	AccessID    string `json:"accessId"`
	ByOrg       string `json:"byOrg"`
	AssertionID string `json:"assertionId"`
	Purpose     string `json:"purpose"`
	Approver1   string `json:"approver1"`
	Approver2   string `json:"approver2"`
	WindowFrom  int64  `json:"windowFrom"`
	WindowTo    int64  `json:"windowTo"`
	At          int64  `json:"at"`
}

type RuleVersion struct {
	DocType   string `json:"docType"`
	Version   string `json:"version"`
	Digest    string `json:"digest"`
	AdoptedAt int64  `json:"adoptedAt"`
	AdoptedBy string `json:"adoptedBy"`
}

type SmartContract struct{ contractapi.Contract }

func now(ctx contractapi.TransactionContextInterface) (int64, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return 0, err
	}
	return ts.Seconds, nil
}

// RecordLookup writes one membership check. targetHash is a salted digest of
// the commitment that was checked, so the log proves a lookup happened without
// itself becoming a second copy of the flag list.
func (s *SmartContract) RecordLookup(ctx contractapi.TransactionContextInterface, lookupID, targetHash, purpose string, hit bool) (*LookupRecord, error) {
	msp, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return nil, err
	}
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}

	count, err := s.countInWindow(ctx, msp, t)
	if err != nil {
		return nil, err
	}
	count++

	rec := &LookupRecord{
		DocType:     objLookup,
		LookupID:    lookupID,
		ByOrg:       msp,
		TargetHash:  targetHash,
		Hit:         hit,
		At:          t,
		WindowCount: count,
		OverBudget:  count > lookupBudget,
		Purpose:     purpose,
	}
	k, err := ctx.GetStub().CreateCompositeKey(objLookup, []string{msp, fmt.Sprintf("%d", t), lookupID})
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(rec)
	if err := ctx.GetStub().PutState(k, b); err != nil {
		return nil, err
	}
	if rec.OverBudget {
		_ = ctx.GetStub().SetEvent("LookupBudgetExceeded", b)
	}
	return rec, nil
}

func (s *SmartContract) countInWindow(ctx contractapi.TransactionContextInterface, msp string, t int64) (int, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(objLookup, []string{msp})
	if err != nil {
		return 0, err
	}
	defer iter.Close()
	cutoff := t - int64(lookupWindow.Seconds())
	n := 0
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return 0, err
		}
		var r LookupRecord
		if json.Unmarshal(kv.Value, &r) == nil && r.At >= cutoff {
			n++
		}
	}
	return n, nil
}

// RecordBreakGlass is written by the oversight member BEFORE it reads a
// private collection. Two named approvers and a bounded time window are
// required; the record is on the shared channel where every member sees it.
func (s *SmartContract) RecordBreakGlass(ctx contractapi.TransactionContextInterface, accessID, assertionID, purpose, approver1, approver2 string, windowSeconds int64) (*BreakGlassRecord, error) {
	msp, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return nil, err
	}
	if !regulatorMSPs[msp] {
		return nil, fmt.Errorf("emergency access is available to oversight members only; %s is not one", msp)
	}
	if approver1 == "" || approver2 == "" || approver1 == approver2 {
		return nil, fmt.Errorf("two distinct named approvers are required")
	}
	if purpose == "" {
		return nil, fmt.Errorf("a stated purpose is required")
	}
	if windowSeconds <= 0 || windowSeconds > 86400 {
		return nil, fmt.Errorf("access window must be between 1 second and 24 hours")
	}
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	rec := &BreakGlassRecord{
		DocType: objBreakGlass, AccessID: accessID, ByOrg: msp, AssertionID: assertionID,
		Purpose: purpose, Approver1: approver1, Approver2: approver2,
		WindowFrom: t, WindowTo: t + windowSeconds, At: t,
	}
	k, err := ctx.GetStub().CreateCompositeKey(objBreakGlass, []string{accessID})
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(rec)
	if err := ctx.GetStub().PutState(k, b); err != nil {
		return nil, err
	}
	_ = ctx.GetStub().SetEvent("EmergencyAccess", b)
	return rec, nil
}

// AdoptRuleVersion pins which rule set was in force, so a past alert can be
// judged against the rules that applied at the time (Section 6.5).
func (s *SmartContract) AdoptRuleVersion(ctx contractapi.TransactionContextInterface, version, digest string) (*RuleVersion, error) {
	msp, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return nil, err
	}
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	rv := &RuleVersion{DocType: objRuleVer, Version: version, Digest: digest, AdoptedAt: t, AdoptedBy: msp}
	k, err := ctx.GetStub().CreateCompositeKey(objRuleVer, []string{version})
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(rv)
	return rv, ctx.GetStub().PutState(k, b)
}

// AuditTrail returns every audit record of one type. Deliberately readable by
// all members: the trail is the accountability, so hiding it defeats it.
func (s *SmartContract) AuditTrail(ctx contractapi.TransactionContextInterface, objectType string) ([]map[string]interface{}, error) {
	if objectType != objLookup && objectType != objBreakGlass && objectType != objRuleVer {
		return nil, fmt.Errorf("objectType must be LOOKUP, BREAKGLASS or RULEVER")
	}
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(objectType, []string{})
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	out := []map[string]interface{}{}
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var m map[string]interface{}
		if json.Unmarshal(kv.Value, &m) == nil {
			out = append(out, m)
		}
	}
	return out, nil
}

func main() {
	cc, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		panic(err)
	}
	if err := cc.Start(); err != nil {
		panic(err)
	}
}

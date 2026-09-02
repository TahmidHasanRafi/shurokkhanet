// Package main implements signal-cc for ShurokkhaNet.
//
// Whitepaper mapping:
//   Section 4.4  SIM replacement and device change signals, in a schema that
//                matches the GSMA Open Gateway SIM Swap API so operator
//                signals are consumed rather than rebuilt
//   Section 8.1  Table 11 - we consume Open Gateway, we do not compete with it
//
// The GSMA SIM Swap API answers "was this MSISDN's SIM swapped in the last N
// seconds". We keep that shape exactly, but the MSISDN never appears: the
// operator publishes a keyed commitment of it (Equation 3).
package main

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const (
	objSignal = "SIGNAL"
	objRevoke = "SENDERREVOKE"

	SignalSIMSwap      = "SIM_SWAP"
	SignalDeviceChange = "DEVICE_CHANGE"
	SignalPortOut      = "PORT_OUT"
)

// operatorMSPs may publish signals. MFS members may only read them (Table 7:
// "mobile operator member ... signals only").
var operatorMSPs = map[string]bool{"OperatorMSP": true, "Org4MSP": true}

// BTRC is the telecom regulator and a member in its own right (Section 4.1).
// Until the fourth organisation joins in Phase 2, the oversight seat carries
// operator signals so signal-cc can be exercised on a three-org network.
var regulatorMSPs = map[string]bool{"RegulatorMSP": true, "Org3MSP": true}

type Signal struct {
	DocType     string `json:"docType"`
	SignalID    string `json:"signalId"`
	SubjCommit  string `json:"subjectCommit"`
	SignalType  string `json:"signalType"`
	OccurredAt  int64  `json:"occurredAt"`
	PublishedAt int64  `json:"publishedAt"`
	ByOrg       string `json:"byOrg"`
	Epoch       int    `json:"epoch"`
}

// SenderRevocation covers emergency revocation of corporate SMS sender
// identifiers, the masking-abuse route behind most OTP phishing.
type SenderRevocation struct {
	DocType   string `json:"docType"`
	SenderID  string `json:"senderId"`
	Reason    string `json:"reason"`
	RevokedBy string `json:"revokedBy"`
	RevokedAt int64  `json:"revokedAt"`
}

type SwapCheck struct {
	SubjectCommit string `json:"subjectCommit"`
	Swapped       bool   `json:"swapped"`
	LastSwapAt    int64  `json:"lastSwapAt"`
	WithinSeconds int64  `json:"withinSeconds"`
}

type SmartContract struct{ contractapi.Contract }

func now(ctx contractapi.TransactionContextInterface) (int64, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return 0, err
	}
	return ts.Seconds, nil
}

func (s *SmartContract) PublishSignal(ctx contractapi.TransactionContextInterface, signalID, subjectCommit, signalType string, occurredAt int64, epoch int) (*Signal, error) {
	msp, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return nil, err
	}
	if !operatorMSPs[msp] && !regulatorMSPs[msp] {
		return nil, fmt.Errorf("only a licensed mobile operator or BTRC may publish signals; %s may not", msp)
	}
	switch signalType {
	case SignalSIMSwap, SignalDeviceChange, SignalPortOut:
	default:
		return nil, fmt.Errorf("unknown signal type %q", signalType)
	}
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	sig := &Signal{
		DocType: objSignal, SignalID: signalID, SubjCommit: subjectCommit,
		SignalType: signalType, OccurredAt: occurredAt, PublishedAt: t,
		ByOrg: msp, Epoch: epoch,
	}
	k, err := ctx.GetStub().CreateCompositeKey(objSignal, []string{subjectCommit, fmt.Sprintf("%d", occurredAt), signalID})
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(sig)
	if err := ctx.GetStub().PutState(k, b); err != nil {
		return nil, err
	}
	_ = ctx.GetStub().SetEvent("SignalPublished", b)
	return sig, nil
}

// CheckSimSwap mirrors the GSMA Open Gateway SIM Swap response shape.
func (s *SmartContract) CheckSimSwap(ctx contractapi.TransactionContextInterface, subjectCommit string, withinSeconds int64) (*SwapCheck, error) {
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey(objSignal, []string{subjectCommit})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	res := &SwapCheck{SubjectCommit: subjectCommit, WithinSeconds: withinSeconds}
	cutoff := t - withinSeconds
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var sig Signal
		if json.Unmarshal(kv.Value, &sig) != nil {
			continue
		}
		if sig.SignalType != SignalSIMSwap {
			continue
		}
		if sig.OccurredAt >= cutoff {
			res.Swapped = true
			if sig.OccurredAt > res.LastSwapAt {
				res.LastSwapAt = sig.OccurredAt
			}
		}
	}
	return res, nil
}

func (s *SmartContract) RevokeSenderID(ctx contractapi.TransactionContextInterface, senderID, reason string) (*SenderRevocation, error) {
	msp, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return nil, err
	}
	if !operatorMSPs[msp] && !regulatorMSPs[msp] {
		return nil, fmt.Errorf("sender id revocation is for operators and BTRC only")
	}
	t, err := now(ctx)
	if err != nil {
		return nil, err
	}
	r := &SenderRevocation{DocType: objRevoke, SenderID: senderID, Reason: reason, RevokedBy: msp, RevokedAt: t}
	k, err := ctx.GetStub().CreateCompositeKey(objRevoke, []string{senderID})
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(r)
	if err := ctx.GetStub().PutState(k, b); err != nil {
		return nil, err
	}
	_ = ctx.GetStub().SetEvent("SenderRevoked", b)
	return r, nil
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

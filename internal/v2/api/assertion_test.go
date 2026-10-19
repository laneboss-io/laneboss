package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func assertionTransaction(t *testing.T) Transaction {
	t.Helper()
	request := HumanConfirmRequest{ChallengeID: "challenge", CredentialID: "credential",
		ClientDataJSON: []byte("client assertion"), AuthenticatorData: []byte("authenticator data"), Signature: []byte("signature")}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	actor := Actor{Kind: "human", ID: "principal"}
	evidence := BlobRef{ID: "assertion", SHA256: Digest(hex.EncodeToString(sum[:])), Bytes: int64(len(raw)), Class: "artifact"}
	ref := ProofRef{ID: "proof", RequestSHA256: Digest(strings.Repeat("1", 64)), ExpiresAt: "2026-01-01T00:02:00Z"}
	proof := VerifiedHumanProof{EndpointClass: EndpointHuman, EndpointGeneration: 3, AssertionEvidence: evidence,
		Ref: ref, Config: "demo", PrincipalID: actor.ID, CredentialID: request.CredentialID, NonceID: request.ChallengeID,
		Target:       HumanChallengeRequest{Method: "ticket.issue", TargetID: "root", RequestSHA256: ref.RequestSHA256, BaseGeneration: 1},
		ConnectionID: "confirm-connection", VerifiedAt: "2026-01-01T00:00:00Z"}
	reply, err := json.Marshal(ref)
	if err != nil {
		t.Fatal(err)
	}
	return Transaction{Scope: Scope{Config: "demo", Actor: actor, EndpointGeneration: 3,
		Request: Request{Method: "human.confirm", Params: raw}}, Reply: &RPCReply{Result: reply},
		Writes: StateWrites{Proofs: []VerifiedHumanProof{proof},
			Objects: []ObjectWrite{{ObjectKey: evidence.ID, Class: evidence.Class, Bytes: raw, SHA256: evidence.SHA256,
				ACL: ObjectACL{Config: "demo", Owner: actor, Audience: "private", Generation: 1}, Origin: "identity"}},
			Challenges: []StoredChallenge{{EndpointClass: EndpointHuman, EndpointGeneration: 3, PrincipalID: actor.ID,
				ConnectionID: "challenge-connection", Generation: 2, Consumed: true,
				Challenge: HumanChallenge{ID: request.ChallengeID, Config: "demo", Method: proof.Target.Method,
					TargetID: proof.Target.TargetID, RequestSHA256: ref.RequestSHA256, BaseGeneration: 1, ExpiresAt: ref.ExpiresAt}}},
			Counters: []CredentialCounterChange{{CredentialID: request.CredentialID, ExpectedGeneration: 2, Before: 7, After: 8}}},
		Events: []Event{{Config: "demo", Kind: "human.confirmed", Actor: actor, Payload: reply}}}
}

func TestConfirmEvidence(t *testing.T) {
	if err := ValidateTransactionShape(assertionTransaction(t)); err != nil {
		t.Fatalf("atomic private assertion evidence was refused: %v", err)
	}
	for name, mutate := range map[string]func(*Transaction){
		"unreferenced":     func(tx *Transaction) { tx.Writes.Objects[0].ObjectKey = "other-evidence" },
		"foreign_owner":    func(tx *Transaction) { tx.Writes.Objects[0].ACL.Owner.ID = "other-principal" },
		"foreign_config":   func(tx *Transaction) { tx.Writes.Objects[0].ACL.Config = "other-config" },
		"shared":           func(tx *Transaction) { tx.Writes.Objects[0].ACL.Audience = "tree" },
		"participant":      func(tx *Transaction) { tx.Writes.Objects[0].ACL.Participants = []ID{"other-principal"} },
		"life":             func(tx *Transaction) { tx.Writes.Objects[0].ACL.LifeID = "another-life" },
		"class":            func(tx *Transaction) { tx.Writes.Objects[0].Class = "record" },
		"proof_principal":  func(tx *Transaction) { tx.Writes.Proofs[0].PrincipalID = "other-principal" },
		"challenge":        func(tx *Transaction) { tx.Writes.Challenges[0].Consumed = false },
		"counter":          func(tx *Transaction) { tx.Writes.Counters = nil },
		"missing_evidence": func(tx *Transaction) { tx.Writes.Objects = nil },
		"extra_evidence":   func(tx *Transaction) { tx.Writes.Objects = append(tx.Writes.Objects, tx.Writes.Objects[0]) },
		"other_method":     func(tx *Transaction) { tx.Scope.Request.Method = "human.challenge" },
		"unrelated_bytes": func(tx *Transaction) {
			object := &tx.Writes.Objects[0]
			object.Bytes = []byte("different assertion")
			sum := sha256.Sum256(object.Bytes)
			object.SHA256 = Digest(hex.EncodeToString(sum[:]))
			tx.Writes.Proofs[0].AssertionEvidence.Bytes = int64(len(object.Bytes))
			tx.Writes.Proofs[0].AssertionEvidence.SHA256 = object.SHA256
		},
	} {
		t.Run(name, func(t *testing.T) {
			tx := assertionTransaction(t)
			mutate(&tx)
			var typed *Error
			if err := ValidateTransactionShape(tx); !errors.As(err, &typed) || typed.Code != CodeInvalid {
				t.Fatalf("unbound or exposed assertion evidence was accepted: %v", err)
			}
		})
	}
}

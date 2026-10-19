package secrets

import "testing"

func TestCredentialRotationPolicy(t *testing.T) {
	tests := []struct {
		name  string
		input CredentialRotationPolicyInput
		want  CredentialRotationPolicyDecision
	}{
		{
			name:  "normal stop retires the lane copy",
			input: CredentialRotationPolicyInput{Cause: CredentialStopNormal},
			want:  CredentialRotationPolicyDecision{RetireLaneCopy: true, RotationRequired: true},
		},
		{
			name:  "cancel keeps the seat blocked",
			input: CredentialRotationPolicyInput{Cause: CredentialStopCancel},
			want:  CredentialRotationPolicyDecision{RotationRequired: true, BlockSeat: true},
		},
		{
			name:  "revoke keeps the seat blocked",
			input: CredentialRotationPolicyInput{Cause: CredentialStopRevoke},
			want:  CredentialRotationPolicyDecision{RotationRequired: true, BlockSeat: true},
		},
		{
			name:  "LB-301 leak hit keeps the seat blocked",
			input: CredentialRotationPolicyInput{Cause: CredentialStopNormal, LeakHit: true},
			want:  CredentialRotationPolicyDecision{RotationRequired: true, BlockSeat: true},
		},
		{
			name:  "unknown cause fails closed",
			input: CredentialRotationPolicyInput{Cause: CredentialStop("future")},
			want:  CredentialRotationPolicyDecision{RotationRequired: true, BlockSeat: true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := EvaluateCredentialRotationPolicy(test.input); got != test.want {
				t.Fatalf("policy=%+v, want %+v", got, test.want)
			}
		})
	}
}

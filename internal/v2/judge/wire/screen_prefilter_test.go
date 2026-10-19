package wire

import (
	"strings"
	"testing"
)

func TestAssignmentMatchEnds(t *testing.T) {
	for _, prefix := range []string{"", "ordinary.", "A_b.c-", "界", strings.Repeat("q", 4096)} {
		for _, word := range []string{"token", "seCREt", "API_KEY", "prİvate-key", "toKen", "paſſword", "credentials"} {
			for _, separator := range []string{"=", ":", ":=", "=>", "' =", "\"\t:", "==", "::"} {
				text := prefix + word + separator + "redacted token=$EXAMPLE_KEY"
				want := fix1Assignment.FindAllStringIndex(text, -1)
				got := assignment.FindAllStringIndex(text, -1)
				if len(want) != len(got) {
					t.Fatal("assignment match count changed")
				}
				for i := range want {
					if want[i][1] != got[i][1] {
						t.Fatal("assignment value start changed")
					}
				}
			}
		}
	}
}

func TestScreenFoldedShapes(t *testing.T) {
	a := strings.Repeat("a1", 24)
	for _, text := range []string{
		"AUTHORIZATION: BAſIC " + a,
		"Authorİzatıon: TOKEN " + a,
		"BEARER " + a,
		"DİſCORD.COM/api/webhooks/12345/abcdef",
		"HOOKſ.ſLACK.COM/services/" + "TAAAAA/BAAAAA/abcdef",
		"ſCRİPT.GOOGLE.COM/macros/s/" + a,
	} {
		if !fix1CredentialText(text) || !credentialText(text) {
			t.Fatal("folded signature escaped")
		}
	}
}

func TestCredentialShapeBranches(t *testing.T) {
	var values []string
	for _, kind := range "pousr" {
		values = append(values, "gh"+string(kind)+"_"+strings.Repeat("a1", 16))
	}
	values = append(values, "github_pat_"+strings.Repeat("a1", 16), "glpat-"+strings.Repeat("a1", 12))
	for _, kind := range "abposr" {
		values = append(values, "xox"+string(kind)+"-"+strings.Repeat("a1", 8))
	}
	for _, kind := range "MNO" {
		values = append(values, string(kind)+strings.Repeat("a", 23)+"."+strings.Repeat("b", 6)+"."+strings.Repeat("c", 27))
	}
	for _, prefix := range []string{"AKIA", "ASIA", "ABIA", "ACCA"} {
		values = append(values, prefix+strings.Repeat("A1", 8))
	}
	for _, prefix := range []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"} {
		values = append(values, prefix+strings.Repeat("a1", 8))
	}
	for _, value := range values {
		if !fix1CredentialText(value) || !credentialText(value) {
			t.Fatal("credential shape branch escaped")
		}
	}
}

func TestNamedExtraGrammar(t *testing.T) {
	for _, key := range []string{"password", "client_secret", "item.auth-token"} {
		for _, value := range []string{"\"\"value9", " 'redacted'value9", "<VALUE REF>value9", "{{ VALUE }}value9"} {
			text := key + "=" + value
			if fix1Sensitive(text, "") || namedScreenExtra(text) == "" || !Sensitive(text, "") {
				t.Fatal("named extra grammar escaped")
			}
		}
		for _, value := range []string{"\"\"", " 'redacted'; next", "<VALUE REF>, next", "{{ VALUE }} next", "\"$EXAMPLE_KEY\"\u2003next"} {
			text := key + "=" + value
			if namedScreenExtra(text) != "" || fix1Sensitive(text, "") || Sensitive(text, "") {
				t.Fatal("named extra withheld benign input")
			}
		}
	}
}

package sandbox

import (
	"strings"
	"testing"
)

func TestSeatbeltProfileDeniesNetworkWhenDisabled(t *testing.T) {
	p := seatbeltProfile(isolationRequest{AllowNetwork: false}, "/Users/test")
	if !strings.Contains(p, "(deny network*)") {
		t.Fatalf("expected network deny rule, got:\n%s", p)
	}
}

func TestSeatbeltProfileAllowsNetworkWhenEnabled(t *testing.T) {
	p := seatbeltProfile(isolationRequest{AllowNetwork: true}, "/Users/test")
	if strings.Contains(p, "(deny network*)") {
		t.Fatalf("network must not be denied when allowed, got:\n%s", p)
	}
}

func TestSeatbeltProfileDeniesCredentialVaults(t *testing.T) {
	p := seatbeltProfile(isolationRequest{}, "/Users/test")
	for _, vault := range []string{"/Users/test/.ssh", "/Users/test/.aws", "/Users/test/.gnupg"} {
		if !strings.Contains(p, `(deny file-read* (subpath "`+vault+`"))`) {
			t.Fatalf("missing read deny for %s, got:\n%s", vault, p)
		}
		if !strings.Contains(p, `(deny file-write* (subpath "`+vault+`"))`) {
			t.Fatalf("missing write deny for %s, got:\n%s", vault, p)
		}
	}
}

func TestSeatbeltProfileEmptyHomeDisablesVaultRules(t *testing.T) {
	p := seatbeltProfile(isolationRequest{}, "")
	if strings.Contains(p, "subpath") {
		t.Fatalf("no vault rules expected with empty home, got:\n%s", p)
	}
}

func TestSeatbeltProfileFailsSafe(t *testing.T) {
	p := seatbeltProfile(isolationRequest{}, "/Users/test")
	if !strings.HasPrefix(p, "(version 1)\n") {
		t.Fatalf("profile must start with version, got:\n%s", p)
	}
	if !strings.Contains(p, "(allow default)\n") {
		t.Fatalf("profile must allow default so unknown ops stay working, got:\n%s", p)
	}
}

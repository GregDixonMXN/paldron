package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GregDixonMXN/paldron/internal/sandbox"
)

func verdictStub(t *testing.T, secret, hostile float64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"answers": map[string]any{
				"secret_exposure": map[string]any{"noul": secret},
				"hostile_action":  map[string]any{"noul": hostile},
			},
		})
	}))
}

func TestJevVerdictDisabledNeedsNothing(t *testing.T) {
	t.Setenv("JEV_API_KEY", "")
	if got := jevOutputVerdict(&Policy{}, []string{"echo", "hi"}, &sandbox.ExecuteResult{Stdout: "hi"}); got != "" {
		t.Errorf("disabled verdict = %q, want empty", got)
	}
}

func TestJevVerdictAllowsCleanOutput(t *testing.T) {
	srv := verdictStub(t, 0.02, 0.01)
	defer srv.Close()
	t.Setenv("JEV_API_KEY", "test-key")
	t.Setenv("JEV_API_URL", srv.URL)
	p := &Policy{JevVerdict: true}
	if got := jevOutputVerdict(p, []string{"echo", "hi"}, &sandbox.ExecuteResult{Stdout: "hi"}); got != "" {
		t.Errorf("clean verdict = %q, want empty", got)
	}
}

func TestJevVerdictDeniesSecretExposure(t *testing.T) {
	srv := verdictStub(t, 0.93, 0.05)
	defer srv.Close()
	t.Setenv("JEV_API_KEY", "test-key")
	t.Setenv("JEV_API_URL", srv.URL)
	got := jevOutputVerdict(&Policy{JevVerdict: true}, []string{"env"}, &sandbox.ExecuteResult{Stdout: "TOKEN=abc"})
	if !strings.Contains(got, "exposes secrets") || !strings.Contains(got, "p=0.93") {
		t.Errorf("verdict = %q", got)
	}
}

func TestJevVerdictDeniesHostileAction(t *testing.T) {
	srv := verdictStub(t, 0.1, 0.88)
	defer srv.Close()
	t.Setenv("JEV_API_KEY", "test-key")
	t.Setenv("JEV_API_URL", srv.URL)
	got := jevOutputVerdict(&Policy{JevVerdict: true}, []string{"sh"}, &sandbox.ExecuteResult{Stdout: "fetching payload"})
	if !strings.Contains(got, "hostile action") {
		t.Errorf("verdict = %q", got)
	}
}

func TestJevVerdictHonorsCustomThreshold(t *testing.T) {
	srv := verdictStub(t, 0.6, 0.0)
	defer srv.Close()
	t.Setenv("JEV_API_KEY", "test-key")
	t.Setenv("JEV_API_URL", srv.URL)
	res := &sandbox.ExecuteResult{Stdout: "maybe"}
	if got := jevOutputVerdict(&Policy{JevVerdict: true, JevThreshold: 0.9}, nil, res); got != "" {
		t.Errorf("high threshold should allow p=0.6, got %q", got)
	}
	if got := jevOutputVerdict(&Policy{JevVerdict: true, JevThreshold: 0.5}, nil, res); got == "" {
		t.Error("low threshold should deny p=0.6")
	}
}

func TestJevVerdictFailsClosedByDefault(t *testing.T) {
	t.Setenv("JEV_API_KEY", "test-key")
	t.Setenv("JEV_API_URL", "http://127.0.0.1:1/") // refused
	if got := jevOutputVerdict(&Policy{JevVerdict: true}, nil, &sandbox.ExecuteResult{}); !strings.Contains(got, "unavailable") {
		t.Errorf("verdict = %q, want fail-closed", got)
	}
}

func TestJevVerdictFailsOpenWhenConfigured(t *testing.T) {
	t.Setenv("JEV_API_KEY", "test-key")
	t.Setenv("JEV_API_URL", "http://127.0.0.1:1/") // refused
	if got := jevOutputVerdict(&Policy{JevVerdict: true, JevOnError: "allow"}, nil, &sandbox.ExecuteResult{}); got != "" {
		t.Errorf("verdict = %q, want empty", got)
	}
}

func TestPolicyValidatesJevKeys(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "p.toml")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p, err := LoadPolicy(write("jev_verdict = true\njev_threshold = 0.8\njev_on_error = \"allow\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !p.JevVerdict || p.JevThreshold != 0.8 || p.JevOnError != "allow" {
		t.Errorf("policy = %+v", p)
	}
	if _, err := LoadPolicy(write("jev_on_error = \"sometimes\"\n")); err == nil {
		t.Error("expected error on bad jev_on_error")
	}
	if _, err := LoadPolicy(write("jev_threshold = 2\n")); err == nil {
		t.Error("expected error on out-of-range jev_threshold")
	}
}

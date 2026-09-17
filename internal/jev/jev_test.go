package jev

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func stubServer(t *testing.T, secret, hostile float64, check func(t *testing.T, body map[string]any)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("missing Authorization header")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if check != nil {
			check(t, body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"answers": map[string]any{
				"secret_exposure": map[string]any{"noul": secret},
				"hostile_action":  map[string]any{"noul": hostile},
			},
		})
	}))
}

func withEnv(t *testing.T, key, value string) {
	t.Helper()
	oldKey, hadKey := os.LookupEnv("JEV_API_KEY")
	oldURL, hadURL := os.LookupEnv("JEV_API_URL")
	t.Cleanup(func() {
		if hadKey {
			_ = os.Setenv("JEV_API_KEY", oldKey)
		} else {
			_ = os.Unsetenv("JEV_API_KEY")
		}
		if hadURL {
			_ = os.Setenv("JEV_API_URL", oldURL)
		} else {
			_ = os.Unsetenv("JEV_API_URL")
		}
	})
	_ = os.Setenv("JEV_API_KEY", key)
	_ = os.Setenv("JEV_API_URL", value)
}

func TestJudgeOutputMapsBothQuestions(t *testing.T) {
	srv := stubServer(t, 0.91, 0.04, func(t *testing.T, body map[string]any) {
		if body["model"] != "jev-latest" {
			t.Errorf("model = %v", body["model"])
		}
		q := body["questions"].(map[string]any)
		for _, name := range []string{"secret_exposure", "hostile_action"} {
			qq, ok := q[name].(map[string]any)
			if !ok || qq["type"] != "noul" {
				t.Errorf("question %s missing or not noul: %v", name, q[name])
			}
		}
		state := body["state"].(map[string]any)
		if state["stdout"] != "AKIA..." {
			t.Errorf("stdout not passed through: %v", state["stdout"])
		}
	})
	defer srv.Close()
	withEnv(t, "test-key", srv.URL)
	v, err := JudgeOutput(RunContext{Argv: []string{"cat", ".env"}, Stdout: "AKIA..."})
	if err != nil {
		t.Fatal(err)
	}
	if v.SecretExposure != 0.91 || v.HostileAction != 0.04 {
		t.Errorf("verdict = %+v", v)
	}
}

func TestJudgeOutputTruncatesLongOutput(t *testing.T) {
	long := make([]byte, maxStdoutChars+5000)
	for i := range long {
		long[i] = 'x'
	}
	srv := stubServer(t, 0, 0, func(t *testing.T, body map[string]any) {
		got := body["state"].(map[string]any)["stdout"].(string)
		if len([]rune(got)) != maxStdoutChars {
			t.Errorf("stdout chars = %d, want %d", len([]rune(got)), maxStdoutChars)
		}
	})
	defer srv.Close()
	withEnv(t, "test-key", srv.URL)
	if _, err := JudgeOutput(RunContext{Stdout: string(long)}); err != nil {
		t.Fatal(err)
	}
}

func TestJudgeOutputRequiresKey(t *testing.T) {
	old, had := os.LookupEnv("JEV_API_KEY")
	_ = os.Unsetenv("JEV_API_KEY")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("JEV_API_KEY", old)
		}
	})
	if _, err := JudgeOutput(RunContext{}); err == nil {
		t.Error("expected error with no key")
	}
}

func TestJudgeOutputRejectsBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	withEnv(t, "test-key", srv.URL)
	if _, err := JudgeOutput(RunContext{}); err == nil {
		t.Error("expected error on 401")
	}
}

func TestJudgeOutputRejectsMissingAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"answers": map[string]any{}})
	}))
	defer srv.Close()
	withEnv(t, "test-key", srv.URL)
	if _, err := JudgeOutput(RunContext{}); err == nil {
		t.Error("expected error on missing answers")
	}
}

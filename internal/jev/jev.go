// Package jev judges sandboxed run output through TypeSafe's System One
// model. Two Noul questions (secret exposure, hostile action) over one
// shared state, asked together. Opt-in only: no key, no cloud, no call.
package jev

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const defaultEndpoint = "https://api.typesafe.ai/v1/systemone"

// Output caps: judgments need the shape of the output, not all of it.
const maxStdoutChars = 8000
const maxStderrChars = 4000

// RunContext is what the model judges: the invoked command and what it
// produced. Outputs are truncated to the caps above before sending.
type RunContext struct {
	Argv     []string
	ExitCode int
	Stdout   string
	Stderr   string
}

// Verdict holds the two judged probabilities in [0,1].
type Verdict struct {
	SecretExposure float64
	HostileAction  float64
}

type noulAnswer struct {
	Noul float64 `json:"noul"`
}

type systemOneResponse struct {
	Answers map[string]noulAnswer `json:"answers"`
}

func clampOutput(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

// JudgeOutput returns the verdict for a finished run, or an error when the
// judgment could not be obtained (no key, network failure, bad response).
// Callers decide fail-open vs fail-closed; this package never guesses.
func JudgeOutput(rc RunContext) (Verdict, error) {
	key := os.Getenv("JEV_API_KEY")
	if key == "" {
		return Verdict{}, fmt.Errorf("jev: JEV_API_KEY is not set")
	}
	endpoint := os.Getenv("JEV_API_URL")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	body, err := json.Marshal(map[string]any{
		"model": "jev-latest",
		"state": map[string]any{
			"argv":      rc.Argv,
			"exit_code": rc.ExitCode,
			"stdout":    clampOutput(rc.Stdout, maxStdoutChars),
			"stderr":    clampOutput(rc.Stderr, maxStderrChars),
		},
		"questions": map[string]any{
			"secret_exposure": map[string]any{
				"type":         "noul",
				"instructions": "Does this command output expose secret material (credentials, tokens, private keys, .env contents, session cookies)?",
				"criteria": map[string]any{
					"true":  "The output contains credentials, tokens, keys, or other secret material",
					"false": "No secret material visible in the output",
				},
			},
			"hostile_action": map[string]any{
				"type":         "noul",
				"instructions": "Does this command output show the command doing something hostile or evasive (exfiltration, payload download, privilege escalation, covering tracks)?",
				"criteria": map[string]any{
					"true":  "The command acted hostilely or evasively",
					"false": "Routine output with no sign of hostile or evasive behavior",
				},
			},
		},
	})
	if err != nil {
		return Verdict{}, fmt.Errorf("jev: encode request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Verdict{}, fmt.Errorf("jev: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return Verdict{}, fmt.Errorf("jev: request failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("jev: endpoint returned %s", res.Status)
	}
	var decoded systemOneResponse
	if err := json.NewDecoder(res.Body).Decode(&decoded); err != nil {
		return Verdict{}, fmt.Errorf("jev: decode response: %w", err)
	}
	secret, ok := decoded.Answers["secret_exposure"]
	if !ok {
		return Verdict{}, fmt.Errorf("jev: response missing secret_exposure")
	}
	hostile, ok := decoded.Answers["hostile_action"]
	if !ok {
		return Verdict{}, fmt.Errorf("jev: response missing hostile_action")
	}
	return Verdict{SecretExposure: secret.Noul, HostileAction: hostile.Noul}, nil
}

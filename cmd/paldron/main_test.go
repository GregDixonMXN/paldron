package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Bare subcommands must not be treated as paths: EvalPath denies anything
// outside allow_paths, so checking them denies every real invocation
// (e.g. `cargo build` denied on "build").
func TestLooksLikePath(t *testing.T) {
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(cwd, "srcdir"), 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		in   string
		want bool
	}{
		{"build", false},               // cargo subcommand
		{"test", false},                // cargo/go subcommand
		{"--offline", false},           // flag shape (also skipped earlier)
		{"src/main.rs", true},          // separator
		{"./tool.py", true},            // dot-prefix
		{"../evil", true},              // separator (still denied downstream)
		{"/etc/passwd", true},          // absolute (still denied downstream)
		{"notes.txt", true},            // extension + exists on disk
		{"srcdir", true},               // exists on disk
		{"Cargo.toml", true},           // extension
		{"touch canary-outside", true}, // sh -c fragment: fail closed
		{"cargo build", true},          // command string: fail closed
		{"~/.ssh/id_rsa", true},        // tilde + separator
	}
	for _, c := range cases {
		if got := looksLikePath(cwd, c.in); got != c.want {
			t.Errorf("looksLikePath(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

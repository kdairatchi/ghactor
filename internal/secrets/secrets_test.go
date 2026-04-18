package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixture strings for known-bad patterns. Split across string literals so that
// GitHub push-protection and repo-wide secret scanners do not see a contiguous
// token matching AWS / Stripe / Slack / Google formats. The compiled runtime
// value is identical to the joined string — the tests still exercise each
// pattern's regex end-to-end.
var (
	fakeAWSAccess      = "AKIA" + "IOSFODNN7" + "REALVAL"
	fakeAWSSecret      = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY0"
	fakeStripeLive     = "sk_" + "live_" + "ABCDEFGHIJKLMNOPQRSTUVWXyz"
	fakeStripeLiveAlt  = "sk_" + "live_" + "ABCDEFGHIJKLMNOPQRSTUVWX"
	fakeStripeTest     = "sk_" + "test_" + "ABCDEFGHIJKLMNOPQRSTUVWXyz"
	fakeSlackBotToken  = "xoxb-" + "1234567890-abcdefghij"
	fakeSlackBotLong   = "xoxb-" + "1234567890-abcdefghijklmnop"
	fakeGoogleAPIKey   = "AIza" + "SyABCDEFGHIJKLMNOPQRSTUVWXYZ01234567"
	fakeGitHubPAT      = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// ---- redact ----

func TestRedact(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		keepLeading int
		want        string
	}{
		{"short string", "abc", 4, "****"},
		{"exactly 8 chars", "12345678", 4, "****"},
		{"9 chars", "123456789", 4, "1234****89"},
		{"normal token", "AKIAIOSFODNN7EXAMPLE", 4, "AKIA****LE"},
		{"zero keepLeading", "AKIAIOSFODNN7EXAMPLE", 0, "****LE"},
		{"keepLeading exceeds safe", "ABCDEFGHIJ", 9, "ABCDEFGH****IJ"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redact(tt.input, tt.keepLeading)
			if got != tt.want {
				t.Errorf("redact(%q, %d) = %q; want %q", tt.input, tt.keepLeading, got, tt.want)
			}
			// Critical invariant: output must never equal the full input when input > 8 chars.
			if len(tt.input) > 8 && got == tt.input {
				t.Errorf("redact returned the raw secret unchanged: %q", got)
			}
		})
	}
}

// ---- allowlist ----

func TestIsAllowlisted(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"AKIAIOSFODNN7EXAMPLE", true},  // contains "example"
		{"sk_live_fakekeyvalue00000000", true},  // contains "fake"
		{"dummy-token-here-123456789012", true},  // contains "dummy"
		{"test-key-abcdefghijklmnopqrs", true},  // contains "test-key"
		{"YOUR_KEY_HERE_abcdefghijklmno", true},  // contains "YOUR_KEY_HERE"
		{fakeAWSAccess, false},
		{fakeStripeLiveAlt, false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if got := isAllowlisted(tt.value); got != tt.want {
				t.Errorf("isAllowlisted(%q) = %v; want %v", tt.value, got, tt.want)
			}
		})
	}
}

// ---- isIgnored ----

func TestIsIgnored(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"  TOKEN: sk_live_abc  # ghactor:ignore secrets", true},
		{"  TOKEN: sk_live_abc  # pragma: ignore-secrets", true},
		{"  TOKEN: sk_live_abc  # safe value", false},
		{"  TOKEN: sk_live_abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			if got := isIgnored(tt.line); got != tt.want {
				t.Errorf("isIgnored(%q) = %v; want %v", tt.line, got, tt.want)
			}
		})
	}
}

// ---- shannonEntropy ----

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input   string
		wantMin float64
		wantMax float64
	}{
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaa", 0, 0.1},    // zero entropy
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZ01", 4.5, 5.0},  // near-uniform
		{"password", 2.5, 3.5},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := shannonEntropy(tt.input)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("shannonEntropy(%q) = %.4f; want [%.2f, %.2f]",
					tt.input, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

// ---- pattern positive and negative fixtures ----

// patternCase holds a positive or negative fixture for a pattern.
type patternCase struct {
	patternID string
	input     string
	wantMatch bool
}

var patternFixtures = []patternCase{
	// aws_access_key
	{
		patternID: "aws_access_key",
		input:     "AWS_ACCESS_KEY_ID: " + fakeAWSAccess,
		wantMatch: true,
	},
	{
		patternID: "aws_access_key",
		input:     "AWS_ACCESS_KEY_ID: BKIAIOSFODNN7REALVAL", // wrong prefix
		wantMatch: false,
	},
	// aws_secret_key
	{
		patternID: "aws_secret_key",
		input:     "aws_secret_access_key: " + fakeAWSSecret,
		wantMatch: true,
	},
	{
		patternID: "aws_secret_key",
		input:     "some_other_field: " + fakeAWSSecret, // no aws/secret context
		wantMatch: false,
	},
	// github_pat — ghp_ (prefix 4 chars + 36 alphanumeric = 40 total)
	{
		patternID: "github_pat",
		input:     "GITHUB_TOKEN: " + fakeGitHubPAT,
		wantMatch: true,
	},
	// github_pat — ghs_
	{
		patternID: "github_pat",
		input:     "token: ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		wantMatch: true,
	},
	// github_pat — github_pat_ prefix (prefix 11 chars + 82 alphanumeric/underscore = 93 total)
	{
		patternID: "github_pat",
		input:     "token: github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRST",
		wantMatch: true,
	},
	{
		patternID: "github_pat",
		input:     "GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}", // expression reference — no literal
		wantMatch: false,
	},
	// github_oauth — gho_ (prefix 4 chars + 36 alphanumeric = 40 total)
	{
		patternID: "github_oauth",
		input:     "token: gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		wantMatch: true,
	},
	{
		patternID: "github_oauth",
		input:     "token: ghi_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01", // wrong prefix
		wantMatch: false,
	},
	// slack_token
	{
		patternID: "slack_token",
		input:     "SLACK_TOKEN: " + fakeSlackBotToken,
		wantMatch: true,
	},
	{
		patternID: "slack_token",
		input:     "SLACK_TOKEN: xoxz-1234567890-abcdefghij", // wrong letter
		wantMatch: false,
	},
	// slack_webhook
	{
		patternID: "slack_webhook",
		input:     "SLACK_WEBHOOK: https://hooks.slack.com/services/TABCDEFGH/BABCDEFGH/ABCDEFGHIJKLMNOPQRSTUVWxy",
		wantMatch: true,
	},
	{
		patternID: "slack_webhook",
		input:     "SLACK_WEBHOOK: https://hooks.slack.com/services/", // incomplete
		wantMatch: false,
	},
	// stripe_live
	{
		patternID: "stripe_live",
		input:     "STRIPE_KEY: " + fakeStripeLive,
		wantMatch: true,
	},
	{
		patternID: "stripe_live",
		input:     "STRIPE_KEY: pk_live_ABCDEFGHIJKLMNOPQRSTUVWXyz", // pk_ not sk_
		wantMatch: false,
	},
	// stripe_test
	{
		patternID: "stripe_test",
		input:     "STRIPE_KEY: " + fakeStripeTest,
		wantMatch: true,
	},
	{
		patternID: "stripe_test",
		input:     "STRIPE_KEY: " + fakeStripeLive, // live not test
		wantMatch: false,
	},
	// openai_key — sk- style
	{
		patternID: "openai_key",
		input:     "OPENAI_API_KEY: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv",
		wantMatch: true,
	},
	// openai_key — sk-proj- style
	{
		patternID: "openai_key",
		input:     "OPENAI_API_KEY: sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
		wantMatch: true,
	},
	{
		patternID: "openai_key",
		input:     "OPENAI_API_KEY: sk-short", // too short
		wantMatch: false,
	},
	// anthropic_key
	{
		patternID: "anthropic_key",
		input:     "ANTHROPIC_KEY: sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
		wantMatch: true,
	},
	{
		patternID: "anthropic_key",
		input:     "ANTHROPIC_KEY: sk-ant-short", // too short
		wantMatch: false,
	},
	// google_api_key
	{
		patternID: "google_api_key",
		input:     "GOOGLE_KEY: " + fakeGoogleAPIKey,
		wantMatch: true,
	},
	{
		patternID: "google_api_key",
		input:     "GOOGLE_KEY: BIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ01234567", // wrong prefix
		wantMatch: false,
	},
	// private_key_block
	{
		patternID: "private_key_block",
		input:     "    -----BEGIN RSA PRIVATE KEY-----",
		wantMatch: true,
	},
	{
		patternID: "private_key_block",
		input:     "    -----BEGIN OPENSSH PRIVATE KEY-----",
		wantMatch: true,
	},
	{
		patternID: "private_key_block",
		input:     "    -----BEGIN PUBLIC KEY-----", // public key, not private
		wantMatch: false,
	},
	// jwt
	{
		patternID: "jwt",
		input:     "token: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		wantMatch: true,
	},
	{
		patternID: "jwt",
		input:     "token: eyJshort.eyJsho.short", // segments too short
		wantMatch: false,
	},
}

// patternByID returns the Pattern with the given ID, or panics.
func patternByID(t *testing.T, id string) Pattern {
	t.Helper()
	for _, p := range Patterns {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("no pattern with ID %q", id)
	return Pattern{}
}

func TestPatterns(t *testing.T) {
	for _, tc := range patternFixtures {
		tc := tc
		name := tc.patternID + "/" + tc.input[:min(30, len(tc.input))]
		t.Run(name, func(t *testing.T) {
			pat := patternByID(t, tc.patternID)
			got := pat.Regex.MatchString(tc.input)
			if got != tc.wantMatch {
				t.Errorf("pattern %q on input %q: match=%v; want %v",
					tc.patternID, tc.input, got, tc.wantMatch)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---- file-level scan ----

// writeTempWorkflow creates a temporary YAML file with the given content,
// returning its path and a cleanup function.
func writeTempWorkflow(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "workflow.yml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return p
}

func TestScanFile_AWSAccessKey(t *testing.T) {
	content := "\nname: deploy\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - run: |\n          aws s3 sync\n        env:\n" +
		"          AWS_ACCESS_KEY_ID: " + fakeAWSAccess + "\n"
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "aws_access_key", "error")
	assertNoRawSecret(t, findings, fakeAWSAccess)
}

func TestScanFile_GitHubPAT(t *testing.T) {
	content := "\nname: ci\nenv:\n  TOKEN: " + fakeGitHubPAT + "\n"
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "github_pat", "error")
	assertNoRawSecret(t, findings, fakeGitHubPAT)
}

func TestScanFile_IgnoreLine_GhactorDirective(t *testing.T) {
	content := "\nname: ci\nenv:\n  TOKEN: ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01" + " # ghactor:ignore secrets\n"
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Rule == "github_pat" {
			t.Errorf("expected finding to be suppressed by ignore directive, but got: %+v", f)
		}
	}
}

func TestScanFile_IgnoreLine_Pragma(t *testing.T) {
	content := "\nname: ci\nenv:\n  TOKEN: ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01" + " # pragma: ignore-secrets\n"
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Rule == "github_pat" {
			t.Errorf("expected finding to be suppressed by pragma, but got: %+v", f)
		}
	}
}

func TestScanFile_AllowlistExample(t *testing.T) {
	content := `
name: docs
env:
  AWS_KEY: AKIAIOSFODNN7EXAMPLE
`
	// "AKIAIOSFODNN7EXAMPLE" contains "EXAMPLE" (case-insensitive allowlist hit).
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Rule == "aws_access_key" {
			t.Errorf("expected AKIAIOSFODNN7EXAMPLE to be allowlisted, got finding: %+v", f)
		}
	}
}

func TestScanFile_PrivateKeyBlock(t *testing.T) {
	content := `
name: deploy
jobs:
  deploy:
    steps:
      - run: |
          echo "-----BEGIN RSA PRIVATE KEY-----"
`
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "private_key_block", "error")
}

func TestScanFile_StripeKeys(t *testing.T) {
	liveContent := "\nenv:\n  STRIPE: " + fakeStripeLive + "\n"
	testContent := "\nenv:\n  STRIPE: " + fakeStripeTest + "\n"
	liveFindings, err := scanFile(writeTempWorkflow(t, liveContent), false)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, liveFindings, "stripe_live", "error")

	testFindings, err := scanFile(writeTempWorkflow(t, testContent), false)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, testFindings, "stripe_test", "warning")
}

func TestScanFile_SlackToken(t *testing.T) {
	content := "\nenv:\n  SLACK_TOKEN: " + fakeSlackBotLong + "\n"
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "slack_token", "error")
}

func TestScanFile_SlackWebhook(t *testing.T) {
	content := `
env:
  WEBHOOK: https://hooks.slack.com/services/TABCDE123/BABCDE123/ABCDEFGHIJKLMNOPQRSTUVWxy
`
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "slack_webhook", "error")
}

func TestScanFile_OpenAIKey(t *testing.T) {
	content := `
env:
  OPENAI_KEY: sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv
`
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "openai_key", "error")
}

func TestScanFile_AnthropicKey(t *testing.T) {
	content := `
env:
  ANTHROPIC_KEY: sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq
`
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "anthropic_key", "error")
}

func TestScanFile_GoogleAPIKey(t *testing.T) {
	content := "\nenv:\n  GOOG: " + fakeGoogleAPIKey + "\n"
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "google_api_key", "error")
}

func TestScanFile_JWT(t *testing.T) {
	content := `
env:
  AUTH: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
`
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "jwt", "warning")
}

func TestScanFile_EntropyOptIn(t *testing.T) {
	// A 32-char high-entropy token that matches no named pattern.
	content := `
env:
  RANDOM_TOKEN: xK9mQ2vL8nP4rT6sW1yU7bJ3eH5oI0cA
`
	withoutEntropy, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range withoutEntropy {
		if f.Rule == "generic_high_entropy" {
			t.Error("generic_high_entropy should not fire without --entropy flag")
		}
	}

	withEntropy, err := scanFile(writeTempWorkflow(t, content), true)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range withEntropy {
		if f.Rule == "generic_high_entropy" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected generic_high_entropy finding with --entropy enabled")
	}
}

func TestScanFile_NoFindings(t *testing.T) {
	content := `
name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: go test ./...
        env:
          GOFLAGS: "-v"
`
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings; got %d: %+v", len(findings), findings)
	}
}

func TestScan_DirectoryWalk(t *testing.T) {
	dir := t.TempDir()
	// Write two workflow files.
	content1 := "env:\n  KEY: " + fakeGitHubPAT + "\n"
	content2 := "env:\n  NOPE: safe-value\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yml"), []byte(content1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(content2), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := Scan(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Error("expected at least one finding from directory scan")
	}
	// Confirm the finding is from the first file.
	found := false
	for _, f := range findings {
		if f.Rule == "github_pat" {
			found = true
		}
	}
	if !found {
		t.Error("expected github_pat finding from directory scan")
	}
}

func TestScan_NonExistentDir(t *testing.T) {
	_, err := Scan(Options{Dir: "/tmp/ghactor-nonexistent-dir-xyz"})
	if err == nil {
		t.Error("expected error for non-existent directory")
	}
}

func TestScanFile_LineNumbers(t *testing.T) {
	content := "name: ci\non: push\nenv:\n  KEY: " + fakeGitHubPAT + "\n"
	findings, err := scanFile(writeTempWorkflow(t, content), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Rule == "github_pat" {
			if f.Line != 4 {
				t.Errorf("expected finding on line 4, got line %d", f.Line)
			}
			return
		}
	}
	t.Error("github_pat finding not found")
}

func TestScanFile_RedactionNeverLeaksSecret(t *testing.T) {
	secrets := []struct {
		content string
		secret  string
	}{
		{
			"env:\n  K: " + fakeGitHubPAT + "\n",
			fakeGitHubPAT,
		},
		{
			"env:\n  K: " + fakeStripeLive + "\n",
			fakeStripeLive,
		},
	}
	for _, s := range secrets {
		findings, err := scanFile(writeTempWorkflow(t, s.content), false)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.Redacted == s.secret {
				t.Errorf("finding for rule %q leaked raw secret in Redacted field", f.Rule)
			}
		}
	}
}

func TestShouldFailOn(t *testing.T) {
	errFindings := []Finding{{Severity: "error"}}
	warnFindings := []Finding{{Severity: "warning"}}

	tests := []struct {
		level    string
		findings []Finding
		want     bool
	}{
		{"error", errFindings, true},
		{"error", warnFindings, false},
		{"warning", errFindings, true},
		{"warning", warnFindings, true},
		{"none", errFindings, false},
		{"never", errFindings, false},
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			got := shouldFailOn(tt.findings, tt.level)
			if got != tt.want {
				t.Errorf("shouldFailOn(%q) with %v findings = %v; want %v",
					tt.level, tt.findings, got, tt.want)
			}
		})
	}
}

// ---- helpers ----

func assertFinding(t *testing.T, findings []Finding, rule, severity string) {
	t.Helper()
	for _, f := range findings {
		if f.Rule == rule {
			if f.Severity != severity {
				t.Errorf("finding rule=%q: severity=%q; want %q", rule, f.Severity, severity)
			}
			return
		}
	}
	t.Errorf("expected finding with rule=%q; got findings: %+v", rule, findings)
}

func assertNoRawSecret(t *testing.T, findings []Finding, secret string) {
	t.Helper()
	for _, f := range findings {
		if strings.Contains(f.Redacted, secret) {
			t.Errorf("finding for rule %q contains raw secret in Redacted field", f.Rule)
		}
	}
}

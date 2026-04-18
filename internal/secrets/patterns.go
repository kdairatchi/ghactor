package secrets

import "regexp"

// Pattern describes a single secret-detection rule.
type Pattern struct {
	ID        string
	Name      string
	Regex     *regexp.Regexp
	Severity  string // "error" | "warning"
	RedactTo  int    // number of leading chars to keep before "****"; trailing 2 always kept
}

// Patterns is the registry of all active secret-detection patterns.
// GenericHighEntropy is handled separately in the scanner and is opt-in via --entropy.
var Patterns = []Pattern{
	{
		ID:       "aws_access_key",
		Name:     "AWS Access Key ID",
		Regex:    regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: "error",
		RedactTo: 4,
	},
	{
		ID:   "aws_secret_key",
		Name: "AWS Secret Access Key",
		// 40-char base64url blob that appears near aws/secret/key context.
		// Conservative: require the token to be 40 chars from the base64 alphabet and
		// appear after common key-name patterns on the same line.
		Regex:    regexp.MustCompile(`(?i)(?:aws.{0,20}secret|secret.{0,20}key|AWS_SECRET)[^A-Za-z0-9+/=]*([A-Za-z0-9+/]{40})`),
		Severity: "error",
		RedactTo: 4,
	},
	{
		ID:       "github_pat",
		Name:     "GitHub Personal Access Token",
		Regex:    regexp.MustCompile(`(?:ghp_[0-9A-Za-z]{36}|ghs_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82})`),
		Severity: "error",
		RedactTo: 4,
	},
	{
		ID:       "github_oauth",
		Name:     "GitHub OAuth Token",
		Regex:    regexp.MustCompile(`gho_[0-9A-Za-z]{36}`),
		Severity: "error",
		RedactTo: 4,
	},
	{
		ID:       "slack_token",
		Name:     "Slack API Token",
		Regex:    regexp.MustCompile(`xox[abp]-[0-9A-Za-z-]{10,}`),
		Severity: "error",
		RedactTo: 4,
	},
	{
		ID:       "slack_webhook",
		Name:     "Slack Webhook URL",
		Regex:    regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]{24}`),
		Severity: "error",
		RedactTo: 8,
	},
	{
		ID:       "stripe_live",
		Name:     "Stripe Live Secret Key",
		Regex:    regexp.MustCompile(`sk_live_[0-9A-Za-z]{24,}`),
		Severity: "error",
		RedactTo: 4,
	},
	{
		ID:       "stripe_test",
		Name:     "Stripe Test Secret Key",
		Regex:    regexp.MustCompile(`sk_test_[0-9A-Za-z]{24,}`),
		Severity: "warning",
		RedactTo: 4,
	},
	{
		ID:       "openai_key",
		Name:     "OpenAI API Key",
		Regex:    regexp.MustCompile(`(?:sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9_-]{40,})`),
		Severity: "error",
		RedactTo: 4,
	},
	{
		ID:       "anthropic_key",
		Name:     "Anthropic API Key",
		Regex:    regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{40,}`),
		Severity: "error",
		RedactTo: 6,
	},
	{
		ID:       "google_api_key",
		Name:     "Google API Key",
		Regex:    regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		Severity: "error",
		RedactTo: 4,
	},
	{
		ID:       "private_key_block",
		Name:     "PEM Private Key Block",
		Regex:    regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`),
		Severity: "error",
		RedactTo: 11, // keep "-----BEGIN "
	},
	{
		ID:       "jwt",
		Name:     "JSON Web Token",
		Regex:    regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
		Severity: "warning",
		RedactTo: 4,
	},
}

// allowlistSubstrings are case-insensitive substrings that indicate a value is
// intentionally fake and should not be reported.
var allowlistSubstrings = []string{
	"example",
	"fake",
	"dummy",
	"test-key",
	"YOUR_KEY_HERE",
}

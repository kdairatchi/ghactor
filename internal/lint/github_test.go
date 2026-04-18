package lint

import (
	"bytes"
	"strings"
	"testing"
)

var githubFixture = []Issue{
	{
		File:     ".github/workflows/ci.yml",
		Line:     10,
		Col:      5,
		Kind:     "GHA001",
		Severity: SevError,
		Message:  "unpinned action: uses mutable tag",
		Source:   "ghactor",
	},
	{
		File:     ".github/workflows/ci.yml",
		Line:     22,
		Col:      1,
		Kind:     "GHA004",
		Severity: SevWarning,
		Message:  "expression injection risk",
		Source:   "ghactor",
	},
	{
		File:     ".github/workflows/deploy.yml",
		Line:     5,
		Col:      3,
		Kind:     "GHA007",
		Severity: SevInfo,
		Message:  "consider restricting permissions",
		Source:   "ghactor",
	},
}

func TestWriteGitHubAnnotations_Levels(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGitHubAnnotations(&buf, githubFixture); err != nil {
		t.Fatalf("WriteGitHubAnnotations error: %v", err)
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("line count = %d, want 3\noutput:\n%s", len(lines), buf.String())
	}

	cases := []struct {
		line   string
		prefix string
	}{
		{lines[0], "::error "},
		{lines[1], "::warning "},
		{lines[2], "::notice "},
	}
	for _, tc := range cases {
		if !strings.HasPrefix(tc.line, tc.prefix) {
			t.Errorf("line %q does not start with %q", tc.line, tc.prefix)
		}
	}
}

func TestWriteGitHubAnnotations_Fields(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGitHubAnnotations(&buf, githubFixture[:1]); err != nil {
		t.Fatalf("WriteGitHubAnnotations error: %v", err)
	}

	line := strings.TrimRight(buf.String(), "\n")

	checks := []string{
		"file=.github/workflows/ci.yml",
		"line=10",
		"col=5",
		"title=GHA001",
	}
	for _, want := range checks {
		if !strings.Contains(line, want) {
			t.Errorf("annotation line %q missing %q", line, want)
		}
	}
}

func TestWriteGitHubAnnotations_ColonEscape(t *testing.T) {
	issues := []Issue{
		{
			File:     "a.yml",
			Line:     1,
			Col:      1,
			Kind:     "GHA004",
			Severity: SevError,
			Message:  "bad: value here",
			Source:   "ghactor",
		},
	}
	var buf bytes.Buffer
	if err := WriteGitHubAnnotations(&buf, issues); err != nil {
		t.Fatalf("error: %v", err)
	}

	line := strings.TrimRight(buf.String(), "\n")
	// The :: separator ends after the properties block; the message body
	// follows.  The colon in "bad: value" must be encoded as %3A.
	// Split on :: to isolate message portion.
	parts := strings.SplitN(line, "::", 3)
	if len(parts) < 3 {
		t.Fatalf("unexpected annotation format: %q", line)
	}
	msgBody := parts[2]
	if strings.Contains(msgBody, "bad: value") {
		t.Errorf("raw colon still present in message body: %q", msgBody)
	}
	if !strings.Contains(msgBody, "bad%3A value") {
		t.Errorf("expected %%3A-escaped colon in message body: %q", msgBody)
	}
}

func TestWriteGitHubAnnotations_NewlineEscape(t *testing.T) {
	issues := []Issue{
		{
			File:     "a.yml",
			Line:     1,
			Col:      1,
			Kind:     "GHA004",
			Severity: SevWarning,
			Message:  "line one\nline two\r\nline three",
			Source:   "ghactor",
		},
	}
	var buf bytes.Buffer
	if err := WriteGitHubAnnotations(&buf, issues); err != nil {
		t.Fatalf("error: %v", err)
	}

	output := buf.String()
	// Raw newlines in the message body would break the annotation protocol.
	// After escaping we should have exactly one output line (plus trailing \n).
	outputLines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(outputLines) != 1 {
		t.Errorf("multiline message produced %d output lines, want 1\noutput:\n%s",
			len(outputLines), output)
	}
	if !strings.Contains(output, "%0A") {
		t.Errorf("expected %%0A escape for newline in: %q", output)
	}
	if !strings.Contains(output, "%0D") {
		t.Errorf("expected %%0D escape for carriage return in: %q", output)
	}
}

func TestWriteGitHubAnnotations_PercentEscape(t *testing.T) {
	issues := []Issue{
		{
			File:     "a.yml",
			Line:     1,
			Col:      1,
			Kind:     "GHA001",
			Severity: SevError,
			Message:  "100% complete",
			Source:   "ghactor",
		},
	}
	var buf bytes.Buffer
	if err := WriteGitHubAnnotations(&buf, issues); err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(buf.String(), "%25") {
		t.Errorf("expected %%25 encoding for literal %% in: %q", buf.String())
	}
}

func TestWriteGitHubAnnotations_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteGitHubAnnotations(&buf, nil); err != nil {
		t.Fatalf("WriteGitHubAnnotations(nil) error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output for nil issues, got %q", buf.String())
	}
}

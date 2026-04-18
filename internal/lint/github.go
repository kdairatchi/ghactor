package lint

import (
	"fmt"
	"io"
	"strings"
)

// WriteGitHubAnnotations emits GitHub Actions workflow-command annotation lines
// to w, one line per issue. Severity mapping:
//
//	error   → ::error
//	warning → ::warning
//	info    → ::notice
//
// Message values are escaped per the GH workflow-command spec:
// % → %25, \r → %0D, \n → %0A, : → %3A (in the message body only).
func WriteGitHubAnnotations(w io.Writer, issues []Issue) error {
	for _, iss := range issues {
		level := ghLevel(iss.Severity)
		msg := ghEscapeMessage(iss.Message)
		line := fmt.Sprintf("::%s file=%s,line=%d,col=%d,title=%s::%s\n",
			level,
			iss.File,
			iss.Line,
			iss.Col,
			iss.Kind,
			msg,
		)
		if _, err := io.WriteString(w, line); err != nil {
			return fmt.Errorf("github annotations: %w", err)
		}
	}
	return nil
}

// ghLevel maps a Severity to the GitHub Actions command level token.
func ghLevel(s Severity) string {
	switch s {
	case SevError:
		return "error"
	case SevWarning:
		return "warning"
	default:
		return "notice"
	}
}

// ghEscapeMessage escapes special characters in the message body of a
// GitHub Actions workflow command.  Order matters: % must be escaped first
// so subsequent replacements don't double-escape.
func ghEscapeMessage(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	s = strings.ReplaceAll(s, ":", "%3A")
	return s
}

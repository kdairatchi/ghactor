# Contributing

Thank you for your interest in contributing to ghactor. This document outlines the process.

## Getting Started

### Build

```sh
go build -o ghactor ./cmd/ghactor
```

### Test

```sh
go test ./... -race
```

The `-race` flag enables the race detector to catch concurrency bugs. All tests must pass.

## Commit Conventions

We use conventional commits for clarity and changelog generation. Format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`, `security`

Example:

```
security(lint): add GHA011 rule for unencrypted secrets

Add detection for workflows that log or expose GITHUB_TOKEN
or custom secrets in stdout/stderr without masking.

Closes: #42
```

## Code Review Expectations

We review for:

- **Security first**: Every change gets a mental security audit. Ask: "How could this be exploited?" and "What's the attack surface?"
- **Tests**: New logic needs tests. Run `-race` locally.
- **Clarity**: Code should be self-documenting. Comments explain *why*, not *what*.
- **Backwards compatibility**: Don't break existing rule IDs or command-line flags without major version bump.

## Rule Structure

Rules are defined in `internal/lint/rules.go`. Each rule is a `Rule` struct:

```go
type Rule struct {
	ID           string                          // e.g., "GHA001"
	Title        string                          // short title
	Severity     Severity                        // SevError, SevWarning, SevInfo
	Description  string                          // detailed explanation
	Remediation  string                          // how to fix it
	References   []string                        // links to standards/docs
	Check        func(*workflow.File) []Issue    // the actual check function
}
```

When adding a new rule:

1. Choose an ID (GHA001–GHA010 are reserved; use GHA011+)
2. Implement the `Check` function to scan a `workflow.File` and return `Issue` slices
3. Add human-readable metadata (description, remediation, references)
4. Write tests in `internal/lint/rules_test.go`
5. Document in the [README.md](README.md) rules table

Example check function:

```go
func ruleMyCheck(wf *workflow.File) []Issue {
	var issues []Issue
	for _, job := range wf.Jobs {
		if job.Timeout == "" {
			issues = append(issues, Issue{
				File: wf.Path,
				Line: job.Line,
				Col: 1,
				Kind: "GHA999",
				Severity: SevWarning,
				Message: "job missing timeout",
			})
		}
	}
	return issues
}
```

## Sign-Off

By committing to this repository, you confirm that:

1. Your contribution is your original work or properly attributed
2. You grant kdairatchi and collaborators the right to use your contribution
3. You understand that ghactor is released under the MIT License

Optionally add a sign-off trailer to your commits:

```
Signed-off-by: Your Name <your.email@example.com>
```

Or use git's built-in `-s` flag:

```sh
git commit -s
```

## Questions?

Open an issue or reach out to the maintainer at prowlr@proton.me.

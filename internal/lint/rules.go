package lint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/kdairatchi/ghactor/internal/pin"
	"github.com/kdairatchi/ghactor/internal/workflow"
)

// Rule defines a single ghactor security lint rule, including human-readable
// metadata used by the `rules --verbose` command.
type Rule struct {
	ID          string
	Title       string
	Severity    Severity
	Description string
	Remediation string
	References  []string
	Check       func(*workflow.File) []Issue
}

var Rules = []Rule{
	{
		ID:       "GHA001",
		Title:    "unpinned-action",
		Severity: SevWarning,
		Description: "Actions referenced by a mutable tag (e.g. @v4) rather than a 40-character " +
			"commit SHA are vulnerable to supply-chain attacks. A maintainer — or an attacker who " +
			"has compromised the upstream repository — can silently change what code runs in your " +
			"pipeline by force-pushing the tag to a malicious commit.",
		Remediation: "Pin every third-party action to a full 40-character SHA that matches the " +
			"tag you intend to use, and leave a trailing comment with the human-readable tag so " +
			"reviewers can follow updates: `uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af68 # v4`. " +
			"Run `ghactor pin` to automate this across all workflow files.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
			"https://cwe.mitre.org/data/definitions/829.html",
		},
		Check: ruleUnpinnedAction,
	},
	{
		ID:       "GHA002",
		Title:    "missing-permissions",
		Severity: SevWarning,
		Description: "When no `permissions:` block is present at the workflow or job level, " +
			"GitHub defaults to `write-all` for every scope the GITHUB_TOKEN is granted. " +
			"This violates the principle of least privilege and means a compromised step can " +
			"write to the repository, packages, deployments, and other sensitive resources.",
		Remediation: "Add a top-level `permissions:` block that grants only the scopes your " +
			"workflow actually needs, ideally `permissions: contents: read`. Override at the " +
			"job level for any job that requires broader access. Use `permissions: {}` as the " +
			"default to deny all scopes and grant selectively.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene",
			"https://cwe.mitre.org/data/definitions/250.html",
		},
		Check: ruleMissingPermissions,
	},
	{
		ID:       "GHA003",
		Title:    "pull-request-target-checkout",
		Severity: SevError,
		Description: "The `pull_request_target` event runs in the context of the base repository " +
			"with full access to repository secrets. When a workflow using this trigger checks out " +
			"the PR head ref (`github.event.pull_request.head.sha` or `github.head_ref`), " +
			"untrusted code from a fork is executed with privileged credentials — a critical " +
			"supply-chain attack pattern known as a pwn-request.",
		Remediation: "Never check out the PR head ref in a `pull_request_target` workflow that " +
			"has access to secrets. Split the workflow into two: a `pull_request` workflow that " +
			"builds/tests the untrusted code (no secrets), and a `workflow_run` or separate " +
			"`pull_request_target` workflow that consumes artifacts and has secret access. " +
			"If you must check out the head, ensure the job has `permissions: {}` and no " +
			"secret access before doing so.",
		References: []string{
			"https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
			"https://cwe.mitre.org/data/definitions/829.html",
		},
		Check: rulePRTargetCheckout,
	},
	{
		ID:       "GHA004",
		Title:    "script-injection",
		Severity: SevError,
		Description: "Directly interpolating GitHub context values such as " +
			"`${{ github.event.issue.title }}` or `${{ inputs.* }}` inside a `run:` step " +
			"allows an attacker to inject arbitrary shell commands by crafting a malicious " +
			"issue title, PR description, commit message, or input value. This is the most " +
			"common critical vulnerability class in GitHub Actions workflows.",
		Remediation: "Pass untrusted context values through an environment variable instead of " +
			"inline expression expansion. Set `env: TITLE: ${{ github.event.issue.title }}` at " +
			"the step level and then reference `$TITLE` in the shell script. This ensures the " +
			"value is treated as data, not code, regardless of its content.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
			"https://cwe.mitre.org/data/definitions/78.html",
		},
		Check: ruleScriptInjection,
	},
	{
		ID:       "GHA005",
		Title:    "missing-timeout",
		Severity: SevInfo,
		Description: "Jobs without an explicit `timeout-minutes` value inherit GitHub's default " +
			"of 360 minutes (6 hours). A hung test suite, stuck network call, or runaway build " +
			"will consume Actions minutes for the full duration before being killed, which can " +
			"significantly inflate billing and block concurrent workflow runs.",
		Remediation: "Set `timeout-minutes` at the job level to a value appropriate for your " +
			"workload — typical CI jobs should complete in under 30 minutes. Use a conservative " +
			"upper bound (e.g. 2× the p99 runtime) to allow for flakiness without burning " +
			"excessive minutes on true hangs.",
		References: []string{
			"https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-and-Visibility",
		},
		Check: ruleMissingTimeout,
	},
	{
		ID:       "GHA006",
		Title:    "floating-latest",
		Severity: SevWarning,
		Description: "Actions pinned to mutable branch names such as `@main`, `@master`, " +
			"`@latest`, `@HEAD`, or `@develop` offer no supply-chain guarantees. Any commit " +
			"pushed to that branch — including a compromised one — immediately runs in all " +
			"workflows that reference the action. This is a weaker variant of the unpinned " +
			"action problem (GHA001) and is treated separately because floating symbolic " +
			"refs are typically intentional and therefore easy to overlook.",
		Remediation: "Replace the floating ref with the specific tag or 40-character SHA that " +
			"represents the version you want. Prefer a SHA with a `# tag` comment: " +
			"`uses: owner/action@<sha> # v2.3.1`. Use `ghactor pin` to resolve tags to " +
			"SHAs automatically.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
			"https://cwe.mitre.org/data/definitions/1357.html",
		},
		Check: ruleFloatingLatest,
	},
	{
		ID:       "GHA007",
		Title:    "unversioned-action",
		Severity: SevWarning,
		Description: "A `uses:` value with no `@ref` component (e.g. `uses: actions/checkout` " +
			"without any `@`) is completely unversioned. GitHub resolves this to the default " +
			"branch of the action repository at the time the workflow runs, making the " +
			"behavior non-deterministic and the supply chain entirely uncontrolled.",
		Remediation: "Always include an `@ref` in every `uses:` value. Pin to a SHA for " +
			"maximum supply-chain safety: `uses: actions/checkout@<40-char-sha> # v4`. " +
			"At minimum, pin to a specific tag. Run `ghactor pin` to automate SHA pinning.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
			"https://cwe.mitre.org/data/definitions/829.html",
		},
		Check: ruleUnversioned,
	},
	{
		ID:       "GHA009",
		Title:    "reusable-workflow-unpinned",
		Severity: SevError,
		Description: "Reusable workflows referenced via `uses:` in a `jobs.<id>.uses` field " +
			"are subject to the same supply-chain risks as action references. A floating ref " +
			"(`@main`, `@master`, `@HEAD`, `@develop`) or missing ref means an attacker who " +
			"controls the referenced repository can inject malicious workflow code that runs " +
			"with your repository's secrets and permissions. A semver tag is better but still " +
			"mutable; a 40-character SHA is the only immutable guarantee.",
		Remediation: "Pin reusable workflow references to a 40-character commit SHA: " +
			"`uses: org/repo/.github/workflows/deploy.yml@<sha> # v1.2.3`. " +
			"For internal organization workflows, at minimum pin to a specific tag and " +
			"enforce branch protection on the referenced repository. Upgrade to SHA pinning " +
			"when the workflow is stabilized.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#reusing-workflows",
			"https://docs.github.com/en/actions/using-workflows/reusing-workflows",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
		},
		Check: ruleReusableUnpinned,
	},
}

// GHA001: action referenced by tag (v4) rather than 40-char SHA.
func ruleUnpinnedAction(f *workflow.File) []Issue {
	var out []Issue
	sha40 := regexp.MustCompile(`^[0-9a-f]{40}$`)
	visitSteps(f, func(jobName string, idx int, s *workflow.Step) {
		if s.Uses == "" || strings.HasPrefix(s.Uses, "./") || strings.HasPrefix(s.Uses, "docker://") {
			return
		}
		ref := refOf(s.Uses)
		if ref == "" {
			out = append(out, mkIssue(f, s, "GHA001", SevWarning,
				fmt.Sprintf("action %q missing version/SHA", s.Uses)))
			return
		}
		if !sha40.MatchString(ref) {
			out = append(out, mkIssue(f, s, "GHA001", SevWarning,
				fmt.Sprintf("action %q is pinned by tag %q; prefer 40-char SHA (run: ghactor pin)", s.Uses, ref)))
		}
	})
	return out
}

// GHA002: no workflow-level or job-level `permissions:` block.
func ruleMissingPermissions(f *workflow.File) []Issue {
	if f.WF.HasPermissions() {
		return nil
	}
	for _, j := range f.WF.Jobs {
		if j.Permissions.Kind != 0 {
			return nil
		}
	}
	return []Issue{{
		File: f.Path, Line: 1, Col: 1, Kind: "GHA002", Severity: SevWarning,
		Source:  "ghactor",
		Message: "no `permissions:` block — defaults to write-all when GITHUB_TOKEN is used; set `permissions: contents: read`",
	}}
}

// GHA003: pull_request_target + actions/checkout of PR head is the classic pwn-request pattern.
func rulePRTargetCheckout(f *workflow.File) []Issue {
	hasPRT := false
	for _, t := range f.WF.Triggers() {
		if t == "pull_request_target" {
			hasPRT = true
			break
		}
	}
	if !hasPRT {
		return nil
	}
	var out []Issue
	visitSteps(f, func(jobName string, idx int, s *workflow.Step) {
		if !strings.HasPrefix(s.Uses, "actions/checkout@") {
			return
		}
		ref := s.With["ref"]
		if ref == "" {
			return
		}
		if strings.Contains(ref, "github.event.pull_request") || strings.Contains(ref, "github.head_ref") {
			out = append(out, mkIssue(f, s, "GHA003", SevError,
				"pull_request_target with checkout of PR head ref exposes secrets to untrusted code"))
		}
	})
	return out
}

// GHA004: ${{ github.* }} interpolation inside `run:` — classic command injection vector.
var injectionExpr = regexp.MustCompile(`\$\{\{\s*(github\.(event\.issue\.title|event\.issue\.body|event\.pull_request\.title|event\.pull_request\.body|event\.comment\.body|event\.review\.body|event\.review_comment\.body|event\.pages\.\*\.page_name|event\.head_commit\.message|event\.head_commit\.author\.email|event\.head_commit\.author\.name|event\.commits\.\*\.message|event\.commits\.\*\.author\.email|event\.commits\.\*\.author\.name|head_ref)|inputs\.[A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

func ruleScriptInjection(f *workflow.File) []Issue {
	var out []Issue
	visitSteps(f, func(jobName string, idx int, s *workflow.Step) {
		if s.Run == "" {
			return
		}
		if m := injectionExpr.FindString(s.Run); m != "" {
			out = append(out, mkIssue(f, s, "GHA004", SevError,
				fmt.Sprintf("untrusted expression %s in `run:` — pipe via env var instead", m)))
		}
	})
	return out
}

// GHA005: job has no timeout-minutes (default 360 burns Actions budget on hangs).
func ruleMissingTimeout(f *workflow.File) []Issue {
	var out []Issue
	for name, j := range f.WF.Jobs {
		if j.TimeoutMin != nil {
			continue
		}
		line := 1
		if j.RunsOn.Line > 0 {
			line = j.RunsOn.Line
		}
		out = append(out, Issue{
			File: f.Path, Line: line, Col: 1, Kind: "GHA005", Severity: SevInfo,
			Source:  "ghactor",
			Message: fmt.Sprintf("job %q has no timeout-minutes (default 360) — set an explicit cap", name),
		})
	}
	return out
}

// GHA006: action pinned to @main / @master / @latest / @HEAD is worst-case unstable + supply-chain risk.
func ruleFloatingLatest(f *workflow.File) []Issue {
	bad := map[string]bool{"main": true, "master": true, "latest": true, "HEAD": true, "develop": true}
	var out []Issue
	visitSteps(f, func(jobName string, idx int, s *workflow.Step) {
		ref := refOf(s.Uses)
		if bad[ref] {
			out = append(out, mkIssue(f, s, "GHA006", SevWarning,
				fmt.Sprintf("action pinned to floating ref @%s — use tag or SHA", ref)))
		}
	})
	return out
}

// GHA007: `uses:` with no @ref at all.
func ruleUnversioned(f *workflow.File) []Issue {
	var out []Issue
	visitSteps(f, func(jobName string, idx int, s *workflow.Step) {
		if s.Uses == "" || strings.HasPrefix(s.Uses, "./") || strings.HasPrefix(s.Uses, "docker://") {
			return
		}
		if !strings.Contains(s.Uses, "@") {
			out = append(out, mkIssue(f, s, "GHA007", SevWarning,
				fmt.Sprintf("action %q has no @ref", s.Uses)))
		}
	})
	return out
}

// optRules returns rules that require runtime options (resolver, config deny list).
// Called by RunWithOptions; returned rules are appended to the static Rules slice for that run.
func optRules(resolver *pin.Resolver, denyPatterns []string) []Rule {
	var extra []Rule
	if resolver != nil {
		extra = append(extra, Rule{
			ID:       "GHA008",
			Title:    "tag-drift",
			Severity: SevWarning,
			Description: "A SHA-pinned action carries a trailing `# <tag>` comment to aid " +
				"human review. When the tag has been updated upstream (e.g. a patch release " +
				"pushed under the same tag name) but the pinned SHA has not been refreshed, " +
				"the workflow is running stale code without realizing it. Tag-drift detection " +
				"resolves the current SHA for the annotated tag and flags any mismatch, " +
				"catching silent supply-chain updates before they accumulate.",
			Remediation: "Run `ghactor pin` to refresh all pinned SHAs to the current " +
				"commit that each annotated tag resolves to. Review the diff to confirm the " +
				"tag bump is expected and that the upstream changelog contains no breaking or " +
				"suspicious changes before merging.",
			References: []string{
				"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
				"https://cwe.mitre.org/data/definitions/1357.html",
			},
			Check: ruleTagDrift(resolver),
		})
	}
	if len(denyPatterns) > 0 {
		extra = append(extra, Rule{
			ID:       "GHA010",
			Title:    "denied-action",
			Severity: SevError,
			Description: "Your ghactor configuration defines a `deny_actions` list of glob " +
				"patterns for actions that must not be used in this repository — for example, " +
				"abandoned actions, actions with known vulnerabilities, or actions that have " +
				"not passed your organization's security review. A workflow step matched this " +
				"policy and must be removed or replaced.",
			Remediation: "Remove or replace the denied action with an approved alternative. " +
				"If the action is required, have it reviewed and approved by your security " +
				"team, then remove it from the `deny_actions` list in `.ghactor.yml`. " +
				"Document the rationale for any exception in the configuration file.",
			References: []string{
				"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
				"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-07-Insecure-System-Configuration",
				"https://cwe.mitre.org/data/definitions/1357.html",
			},
			Check: ruleDeniedAction(denyPatterns),
		})
	}
	return extra
}

// tagAnnotation matches a trailing `# <tag>` comment on a uses: line and captures the tag.
// Example:  uses: actions/checkout@abc123def456... # v4
var tagAnnotation = regexp.MustCompile(`#\s*(\S+)\s*$`)

// usesLineRaw matches the raw `uses:` line from workflow source to extract the tag comment.
// We need the raw source line because the parsed AST doesn't preserve comments.
var usesLineForDrift = regexp.MustCompile(`^\s*-?\s*uses:\s*([^\s#]+)(.*)$`)

// GHA008: pinned SHA is stale relative to the tag comment.
func ruleTagDrift(resolver *pin.Resolver) func(*workflow.File) []Issue {
	sha40re := regexp.MustCompile(`^[0-9a-f]{40}$`)
	return func(f *workflow.File) []Issue {
		var out []Issue
		lines := strings.Split(string(f.Source), "\n")
		for lineIdx, raw := range lines {
			m := usesLineForDrift.FindStringSubmatch(raw)
			if m == nil {
				continue
			}
			uses := m[1] // e.g. actions/checkout@abc123...
			comment := m[2]
			if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
				continue
			}
			owner, repo, ref, ok := splitUses(uses)
			if !ok || !sha40re.MatchString(ref) {
				// Only check lines already pinned to a SHA.
				continue
			}
			cm := tagAnnotation.FindStringSubmatch(comment)
			if cm == nil {
				// No tag annotation — nothing to drift-check.
				continue
			}
			tag := cm[1]
			currentSHA, err := resolver.Resolve(owner, repo, tag)
			if err != nil {
				// Resolve failure: skip silently (network unavailable, rate-limited, etc.).
				continue
			}
			if !strings.EqualFold(currentSHA, ref) {
				out = append(out, Issue{
					File:     f.Path,
					Line:     lineIdx + 1,
					Col:      1,
					Kind:     "GHA008",
					Severity: SevWarning,
					Source:   "ghactor",
					Message: fmt.Sprintf(
						"action %s/%s pinned to SHA %s but tag %s now resolves to %s — run: ghactor pin",
						owner, repo, ref[:8], tag, currentSHA[:8],
					),
				})
			}
		}
		return out
	}
}

// GHA010: action matches a deny_actions glob pattern from config.
func ruleDeniedAction(patterns []string) func(*workflow.File) []Issue {
	return func(f *workflow.File) []Issue {
		var out []Issue
		visitSteps(f, func(jobName string, idx int, s *workflow.Step) {
			if s.Uses == "" || strings.HasPrefix(s.Uses, "./") || strings.HasPrefix(s.Uses, "docker://") {
				return
			}
			// Build the match target: "owner/repo" portion + optional "@ref".
			at := strings.LastIndex(s.Uses, "@")
			var ownerRepo, ref string
			if at >= 0 {
				ownerRepo = s.Uses[:at]
				ref = s.Uses[at+1:]
			} else {
				ownerRepo = s.Uses
			}
			for _, pat := range patterns {
				patName, patRef, hasRef := strings.Cut(pat, "@")
				matchName, _ := doublestar.Match(patName, ownerRepo)
				if !matchName {
					continue
				}
				if hasRef && patRef != ref {
					continue
				}
				out = append(out, mkIssue(f, s, "GHA010", SevError,
					fmt.Sprintf("action %q is denied by policy pattern %q", s.Uses, pat)))
				return // one finding per step is enough
			}
		})
		return out
	}
}

// sha40 matches a full 40-character lowercase hex SHA.
var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

// floatingRefs are symbolic refs that provide no supply-chain guarantees.
var floatingRefs = map[string]bool{
	"main":    true,
	"master":  true,
	"HEAD":    true,
	"develop": true,
}

// GHA009: reusable workflow referenced by a floating ref or non-SHA ref.
//
// Error   — ref is absent or is a floating branch name (main/master/HEAD/develop).
// Warning — ref is present but is not a 40-char SHA (e.g. a semver tag like v1.2.3).
func ruleReusableUnpinned(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}
	var out []Issue
	for _, ru := range f.WF.Reusables {
		line, col := ru.Line, ru.Col
		if line == 0 {
			line = 1
		}
		if col == 0 {
			col = 1
		}
		uses := ru.Owner + "/" + ru.Repo + "/" + ru.Path + "@" + ru.Ref
		if ru.Ref == "" {
			out = append(out, Issue{
				File: f.Path, Line: line, Col: col,
				Kind: "GHA009", Severity: SevError, Source: "ghactor",
				Message: fmt.Sprintf("reusable workflow %q has no @ref — pin to a 40-char SHA", uses),
			})
			continue
		}
		if floatingRefs[ru.Ref] {
			out = append(out, Issue{
				File: f.Path, Line: line, Col: col,
				Kind: "GHA009", Severity: SevError, Source: "ghactor",
				Message: fmt.Sprintf("reusable workflow %q is pinned to floating ref @%s — use a 40-char SHA", uses, ru.Ref),
			})
			continue
		}
		if !sha40.MatchString(ru.Ref) {
			out = append(out, Issue{
				File: f.Path, Line: line, Col: col,
				Kind: "GHA009", Severity: SevWarning, Source: "ghactor",
				Message: fmt.Sprintf("reusable workflow %q is pinned by tag @%s — prefer a 40-char SHA for supply-chain safety", uses, ru.Ref),
			})
		}
	}
	return out
}

func refOf(uses string) string {
	if uses == "" {
		return ""
	}
	i := strings.LastIndex(uses, "@")
	if i < 0 {
		return ""
	}
	return uses[i+1:]
}

func visitSteps(f *workflow.File, fn func(job string, idx int, s *workflow.Step)) {
	if f == nil || f.WF == nil {
		return
	}
	for jobName, j := range f.WF.Jobs {
		for idx, s := range j.Steps {
			if s == nil {
				continue
			}
			fn(jobName, idx, s)
		}
	}
}

// splitUses parses "owner/repo[@ref]" and returns the components.
// Returns ok=false when the string has fewer than two slash-separated segments
// before the @ or has no @ at all.
func splitUses(uses string) (owner, repo, ref string, ok bool) {
	at := strings.LastIndex(uses, "@")
	if at < 0 {
		return "", "", "", false
	}
	ref = uses[at+1:]
	full := uses[:at]
	parts := strings.SplitN(full, "/", 3)
	if len(parts) < 2 {
		return "", "", "", false
	}
	return parts[0], parts[1], ref, true
}

func mkIssue(f *workflow.File, s *workflow.Step, kind string, sev Severity, msg string) Issue {
	line, col := s.Line, s.Col
	if line == 0 {
		line = 1
	}
	if col == 0 {
		col = 1
	}
	return Issue{File: f.Path, Line: line, Col: col, Kind: kind, Severity: sev, Source: "ghactor", Message: msg}
}

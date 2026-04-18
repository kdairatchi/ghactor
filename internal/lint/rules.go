package lint

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"

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
		ID:       "GHA011",
		Title:    "persist-credentials-on-prt",
		Severity: SevError,
		Description: "When `actions/checkout` runs under a `pull_request_target` workflow with " +
			"`persist-credentials: true` (the default when the key is omitted), the GITHUB_TOKEN " +
			"is written to the local git config and remains accessible to every subsequent step. " +
			"Any step in the job — including one that inadvertently executes attacker-controlled " +
			"code — can read the token and push to the base repository.",
		Remediation: "Set `persist-credentials: false` on every `actions/checkout` step inside " +
			"a `pull_request_target` workflow. Pass credentials explicitly only to the specific " +
			"step that requires push access, and scope that step's `permissions:` to the minimum " +
			"required. Prefer splitting privileged and unprivileged work across separate jobs.",
		References: []string{
			"https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
			"https://cwe.mitre.org/data/definitions/522.html",
		},
		Check: rulePersistCredentialsPRT,
	},
	{
		ID:       "GHA012",
		Title:    "curl-pipe-shell",
		Severity: SevWarning,
		Description: "Piping the output of `curl` or `wget` directly into `sh` or `bash` executes " +
			"arbitrary remote code without any integrity verification. If the remote server is " +
			"compromised, the CDN is poisoned, or the connection is intercepted, the attacker " +
			"controls everything the shell process can do — including reading secrets from the " +
			"runner environment.",
		Remediation: "Download the script to a file first, verify its checksum against a known-good " +
			"value (e.g., `sha256sum -c`), and then execute it. Alternatively, use a dedicated " +
			"action with a pinned SHA for common installers, or vendor the script into your " +
			"repository and reference it directly.",
		References: []string{
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
			"https://cwe.mitre.org/data/definitions/494.html",
		},
		Check: ruleCurlPipeShell,
	},
	{
		ID:       "GHA013",
		Title:    "cache-key-untrusted",
		Severity: SevWarning,
		Description: "`actions/cache` (and setup actions with a `cache-key:` input) whose `key:` " +
			"field contains `${{ github.event.* }}` or `${{ inputs.* }}` expressions are " +
			"vulnerable to cache poisoning. An attacker who controls the key value can craft a " +
			"pull request that writes a malicious entry into the cache under a predictable key, " +
			"then trigger a privileged workflow that restores it.",
		Remediation: "Build cache keys exclusively from trusted, content-addressed values: " +
			"`runner.os`, `hashFiles(...)`, `github.sha`, or other immutable context properties. " +
			"Never interpolate user-controlled event fields or workflow inputs directly into a " +
			"cache key.",
		References: []string{
			"https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
			"https://cwe.mitre.org/data/definitions/349.html",
		},
		Check: ruleCacheKeyUntrusted,
	},
	{
		ID:       "GHA014",
		Title:    "legacy-set-env",
		Severity: SevError,
		Description: "The `::set-env` and `::add-path` workflow commands were disabled by GitHub " +
			"in November 2020 (GHSA-mfwh-5m23-j46w) due to environment injection vulnerabilities. " +
			"Re-enabling them by setting `ACTIONS_ALLOW_UNSECURE_COMMANDS=true` restores the " +
			"original attack surface. Any workflow still using these commands either relies on " +
			"legacy behaviour that no longer works or has explicitly re-enabled an unsafe feature.",
		Remediation: "Replace `::set-env name=VAR::value` with `echo \"VAR=value\" >> $GITHUB_ENV` " +
			"and replace `::add-path` with `echo \"/path\" >> $GITHUB_PATH`. Never set " +
			"`ACTIONS_ALLOW_UNSECURE_COMMANDS=true`; there is no legitimate use case for it.",
		References: []string{
			"https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/",
			"https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#environment-files",
			"https://cwe.mitre.org/data/definitions/78.html",
		},
		Check: ruleLegacySetEnv,
	},
	{
		ID:       "GHA015",
		Title:    "prt-artifact-upload",
		Severity: SevError,
		Description: "`actions/upload-artifact` in a `pull_request_target` workflow runs with " +
			"access to repository secrets and the privileged GITHUB_TOKEN. Artifacts uploaded " +
			"here are stored in the base repository's artifact storage and can be downloaded by " +
			"any authenticated user, potentially exfiltrating sensitive data built or generated " +
			"during the privileged run.",
		Remediation: "Avoid uploading artifacts in `pull_request_target` workflows. If artifact " +
			"sharing between a `pull_request` build and a privileged deployment step is needed, " +
			"use the `workflow_run` trigger pattern: build in `pull_request` (no secrets), " +
			"upload the artifact there, then download and deploy it in a separate `workflow_run` " +
			"job after appropriate validation.",
		References: []string{
			"https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
			"https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target",
			"https://cwe.mitre.org/data/definitions/200.html",
		},
		Check: rulePRTArtifactUpload,
	},
	{
		ID:       "GHA016",
		Title:    "self-hosted-public",
		Severity: SevWarning,
		Description: "Self-hosted runners with no restrictive org-scoped label (only `self-hosted` " +
			"or `self-hosted` + a bare OS label such as `linux` or `windows`) can be targeted by " +
			"pull requests from public forks. GitHub routes `pull_request` jobs to any runner " +
			"that matches the label set; without a unique org-scoped label, a fork contributor " +
			"can land code on your infrastructure.",
		Remediation: "Add at least one org-specific label to your self-hosted runners " +
			"(e.g., `org-runner-prod`, `internal`) and require that label in the `runs-on:` " +
			"array. This prevents external PRs from routing to internal infrastructure. " +
			"Additionally, enable `Actions > Runner groups` restrictions in your org settings " +
			"to limit which repositories can use each runner group.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#hardening-for-self-hosted-runners",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-07-Insecure-System-Configuration",
			"https://cwe.mitre.org/data/definitions/284.html",
		},
		Check: ruleSelfHostedPublic,
	},
	{
		ID:       "GHA017",
		Title:    "missing-concurrency-deploy",
		Severity: SevInfo,
		Description: "Deploy and release workflows triggered by pushes to main/master/release " +
			"branches, `release` events, or `workflow_dispatch` without a top-level `concurrency:` " +
			"block are vulnerable to race conditions when two runs start close together. A " +
			"double-deploy can cause partially-applied configuration, duplicated release artifacts, " +
			"or conflicting infrastructure state.",
		Remediation: "Add a `concurrency:` block at the workflow level with a group key that " +
			"serialises runs for the same ref and `cancel-in-progress: false` for deployments " +
			"(to avoid cancelling an in-flight deploy): " +
			"`concurrency: { group: deploy-${{ github.ref }}, cancel-in-progress: false }`.",
		References: []string{
			"https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#concurrency",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation",
		},
		Check: ruleMissingConcurrencyDeploy,
	},
	{
		ID:       "GHA018",
		Title:    "github-env-smuggling",
		Severity: SevError,
		Description: "Writing an untrusted expression directly into `$GITHUB_ENV` or " +
			"`$GITHUB_OUTPUT` via `echo \"VAR=${{ github.event.* }}\" >> $GITHUB_ENV` allows " +
			"an attacker to inject environment variables or output values that are then trusted " +
			"by later steps. This is an environment variable smuggling attack: the injected " +
			"value can override PATH, proxy settings, or any variable a subsequent step reads.",
		Remediation: "Never expand untrusted expressions directly into `$GITHUB_ENV` or " +
			"`$GITHUB_OUTPUT`. Instead, set the value as a step-level `env:` variable and " +
			"reference that safe variable: `env: { VAL: ${{ github.event.issue.title }} }` " +
			"then `echo \"SAFE_VAL=$VAL\" >> $GITHUB_ENV`. This ensures the shell treats " +
			"the value as data, not a key=value pair to be parsed.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
			"https://cwe.mitre.org/data/definitions/78.html",
		},
		Check: ruleGitHubEnvSmuggling,
	},
	{
		ID:       "GHA019",
		Title:    "oidc-no-subject",
		Severity: SevWarning,
		Description: "A job with `permissions: id-token: write` can request an OIDC token from " +
			"GitHub's token endpoint. If the cloud role's trust policy does not constrain the " +
			"`sub` (subject) claim to a specific repository, branch, or environment, any " +
			"repository or fork that can trigger the workflow can obtain a token and assume the " +
			"cloud role. This is a common misconfiguration in AWS, GCP, and Azure OIDC setups.",
		Remediation: "Constrain the OIDC trust policy at the cloud provider to require a " +
			"specific `sub` claim (e.g., " +
			"`repo:myorg/myrepo:ref:refs/heads/main`). For AWS, set a condition on " +
			"`token.actions.githubusercontent.com:sub`. For GCP, use `attribute.repository`. " +
			"Additionally, consider using `actions/configure-aws-credentials` or equivalent " +
			"with explicit `audience:` and `role-to-assume:` inputs.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-openid-connect-to-access-cloud-resources",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene",
			"https://cwe.mitre.org/data/definitions/284.html",
		},
		Check: ruleOIDCNoSubject,
	},
	{
		ID:       "GHA020",
		Title:    "overprivileged-token",
		Severity: SevWarning,
		Description: "Granting write scopes the workflow doesn't use violates least-privilege and " +
			"expands blast radius if a single step is compromised. When the workflow has no " +
			"release/upload/push/PR actions and the `permissions:` block at the workflow level " +
			"grants `contents: write`, `packages: write`, or `pull-requests: write`, the write " +
			"scope is unnecessary.",
		Remediation: "Remove unused write scopes, or move them to the specific job that requires " +
			"them with a job-level `permissions:` override. Use `contents: read` as the default " +
			"and escalate only where needed.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene",
		},
		Check: ruleOverprivilegedToken,
	},
	{
		ID:       "GHA021",
		Title:    "workflow-call-untyped-input",
		Severity: SevWarning,
		Description: "Without an explicit `type:`, GitHub accepts any scalar and coerces; callers " +
			"can unintentionally pass booleans or numbers that are silently cast, and downstream " +
			"shell interpolation may behave inconsistently. A reusable workflow " +
			"(`on.workflow_call.inputs.<name>`) that omits `type:` relies on implicit string " +
			"coercion, which disables GitHub's input validation.",
		Remediation: "Set `type: string | boolean | number | choice` on every " +
			"`on.workflow_call.inputs.<name>` declaration.",
		References: []string{
			"https://docs.github.com/en/actions/using-workflows/reusing-workflows#using-inputs-and-secrets-in-a-reusable-workflow",
		},
		Check: ruleWorkflowCallUntypedInput,
	},
	{
		ID:       "GHA022",
		Title:    "step-shell-unspecified",
		Severity: SevInfo,
		Description: "Implicit shell selection makes cross-platform workflows non-deterministic; " +
			"the same `run:` block runs under different interpreters depending on the runner. " +
			"When a job targets multiple OSes via `strategy.matrix.os` or " +
			"`runs-on: ${{ matrix.os }}` and a step uses `run:` without a `shell:` key (and no " +
			"`defaults.run.shell:` is set at the workflow or job level), the shell used on " +
			"Windows (pwsh) differs from Linux/macOS (bash).",
		Remediation: "Set `shell: bash` at the step, job, or `defaults.run.shell:` level to " +
			"guarantee consistent interpreter selection across platforms.",
		References: []string{
			"https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsshell",
		},
		Check: ruleStepShellUnspecified,
	},
	{
		ID:       "GHA023",
		Title:    "container-unpinned",
		Severity: SevWarning,
		Description: "Container images referenced by tag can be re-tagged by the registry owner " +
			"or a registry compromise to point to malicious layers; only digest-pinned images " +
			"guarantee reproducibility and supply-chain integrity. A `container:` or " +
			"`services.<name>.image:` that lacks an `@sha256:<64-hex-chars>` digest suffix is " +
			"mutable and vulnerable to supply-chain compromise.",
		Remediation: "Pin by digest: `image: node:20@sha256:abc...`. Use `crane digest node:20` " +
			"or `docker manifest inspect node:20` to resolve a tag to its current digest.",
		References: []string{
			"https://docs.docker.com/engine/reference/commandline/pull/#pull-an-image-by-digest-immutable-identifier",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
		},
		Check: ruleContainerUnpinned,
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
	{
		ID:       "GHA024",
		Title:    "deprecated-action-version",
		Severity: SevWarning,
		Description: "Certain action versions are deprecated or hard-disabled by GitHub. Using them " +
			"causes workflow failures (for hard-fail versions) or runs on unsupported Node runtimes " +
			"(EOL Node 12/16), exposing the runner to unpatched runtime vulnerabilities. Common " +
			"examples: actions/upload-artifact v1–v3 hard-fail since 2025-01-30; actions/checkout " +
			"v1–v3 run on deprecated Node 16.",
		Remediation: "Upgrade to the latest major version of the action. For the artifact actions, " +
			"migrate to v4. For setup-* and checkout actions, migrate to v4 or v5 as appropriate. " +
			"Run `ghactor pin` after upgrading to pin the new version to a SHA.",
		References: []string{
			"https://github.blog/changelog/2024-04-16-deprecation-notice-v1-and-v2-of-the-artifact-actions/",
			"https://github.blog/changelog/2023-09-22-github-actions-transitioning-from-node-16-to-node-20/",
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions",
		},
		Check: ruleDeprecatedActionVersion,
	},
	{
		ID:       "GHA025",
		Title:    "deprecated-runner-image",
		Severity: SevError,
		Description: "GitHub-hosted runner images are periodically retired. Using a removed image " +
			"causes an immediate workflow failure with a confusing error message. Using a deprecated " +
			"image that is not yet removed gives a diminishing window before workflows begin to fail " +
			"without any code change on your part. Removed images: ubuntu-20.04 (2025-04), " +
			"macos-12 (2024-12). Deprecated: macos-13 (EOL 2025-12), windows-2019.",
		Remediation: "Update runs-on to a supported image: ubuntu-22.04 or ubuntu-24.04 for Ubuntu; " +
			"macos-14 or macos-15 for macOS; windows-2022 or windows-2025 for Windows. " +
			"Test the workflow after migration — package and tool versions may differ between images.",
		References: []string{
			"https://github.blog/changelog/2025-01-22-github-hosted-runners-ubuntu-20-04-image-brownout-schedule/",
			"https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners/about-github-hosted-runners",
		},
		Check: ruleDeprecatedRunnerImage,
	},
	{
		ID:       "GHA027",
		Title:    "publish-cache-restore",
		Severity: SevWarning,
		Description: "Restoring a build cache in a publish or release workflow creates a cache " +
			"poisoning vector. An attacker with write access to a feature branch can populate the " +
			"cache with a malicious build artifact; when the release workflow runs, it restores the " +
			"poisoned cache and publishes the attacker's artifact rather than one built from the " +
			"release commit. This is a variant of the poisoned-pipeline-execution attack class.",
		Remediation: "Remove cache restoration from publish/release workflows. Accept the longer " +
			"build time on release — this is a one-time cost per release that protects artifact " +
			"integrity. If build time is critical, use a separate build job with artifact upload/download " +
			"(not cache) to transfer outputs between jobs within the same workflow run.",
		References: []string{
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
			"https://woodruffw.github.io/zizmor/audits/cache-poisoning/",
			"https://cwe.mitre.org/data/definitions/349.html",
		},
		Check: rulePublishCacheRestore,
	},
	{
		ID:       "GHA028",
		Title:    "no-build-provenance",
		Severity: SevInfo,
		Description: "Publish and release workflows that do not attest build provenance make it " +
			"impossible for consumers to verify that a published artifact was produced from the " +
			"expected source commit by the expected workflow. Build provenance attestation (via " +
			"actions/attest-build-provenance) generates a signed SLSA provenance statement that " +
			"package registries and downstream consumers can verify.",
		Remediation: "Add `actions/attest-build-provenance` to your publish workflow after the " +
			"build step and before the publish/upload step. Requires `permissions: id-token: write` " +
			"and `permissions: attestations: write`. " +
			"This is an opt-in advisory — disable with `--disable GHA028` or in `.ghactor.yml`.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds",
			"https://slsa.dev/spec/v1.0/",
			"https://github.com/actions/attest-build-provenance",
		},
		Check: ruleNoBuildProvenance,
	},
	{
		ID:       "GHA029",
		Title:    "cross-org-secrets-inherit",
		Severity: SevWarning,
		Description: "`secrets: inherit` on a reusable workflow call passes ALL repository secrets " +
			"to the called workflow. When the callee is in a different GitHub organization, every " +
			"secret the repository holds — tokens, API keys, deploy keys — is forwarded to " +
			"third-party infrastructure. A compromised or malicious workflow in the external org " +
			"can exfiltrate all secrets with no indication in the calling workflow.",
		Remediation: "Replace `secrets: inherit` with an explicit `secrets:` block that forwards " +
			"only the specific secrets the external workflow requires. Review whether a cross-org " +
			"reusable workflow call is necessary, or whether the logic can be moved in-org. " +
			"If secrets: inherit is unavoidable, restrict the secret scope with fine-grained " +
			"environment protection rules.",
		References: []string{
			"https://docs.github.com/en/actions/using-workflows/reusing-workflows#passing-secrets-to-nested-workflows",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-06-Insufficient-Credential-Hygiene",
			"https://cwe.mitre.org/data/definitions/200.html",
		},
		Check: ruleCrossOrgSecretsInherit,
	},
	{
		ID:       "GHA031",
		Title:    "obfuscated-run",
		Severity: SevWarning,
		Description: "Shell obfuscation patterns — base64-decoded payloads piped to a shell, " +
			"`eval` on `curl` output, pipe-to-interpreter patterns, or suspiciously long base64 " +
			"literals — are common indicators of malicious workflow injection or supply-chain " +
			"compromise. Legitimate workflows have no reason to obfuscate their execution. " +
			"These patterns also defeat static analysis and code review.",
		Remediation: "Replace obfuscated patterns with transparent equivalents: download scripts to " +
			"a file, verify their checksum with sha256sum, then execute. Never use eval on remote " +
			"content. Replace base64-encoded payloads with vendored scripts or dedicated actions " +
			"with pinned SHAs.",
		References: []string{
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
			"https://cwe.mitre.org/data/definitions/506.html",
		},
		Check: ruleObfuscatedRun,
	},
	{
		ID:       "GHA032",
		Title:    "spoofable-actor-check",
		Severity: SevWarning,
		Description: "Comparing `github.actor` or `github.triggering_actor` to a bot identity " +
			"string (e.g. `'dependabot[bot]'`) is unreliable for security decisions. The actor " +
			"field reflects whoever initiated the workflow, not necessarily the entity whose code " +
			"is running. A user can create a GitHub account named `dependabot[bot]` and trigger " +
			"workflows that pass this check while bypassing bot-specific restrictions.",
		Remediation: "Gate on `github.event.pull_request.user.login` combined with " +
			"`github.event_name == 'pull_request'` to verify the PR author. For dependabot " +
			"specifically, check `github.actor == 'dependabot[bot]' && github.event_name == 'pull_request_review'` " +
			"or use the official `dependabot/fetch-metadata` action which includes verified checks.",
		References: []string{
			"https://docs.github.com/en/code-security/dependabot/working-with-dependabot/automating-dependabot-with-github-actions",
			"https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
			"https://cwe.mitre.org/data/definitions/290.html",
		},
		Check: ruleSpoofableActorCheck,
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

// GHA004: ${{ github.* }} / ${{ inputs.* }} interpolation inside `run:` — classic command injection vector.
// Also flags ${{ steps.<id>.outputs.* }}, ${{ needs.<id>.outputs.* }}, and ${{ matrix.* }} at SevWarning
// (these are tainted when they derive from untrusted upstream data).
var injectionExpr = regexp.MustCompile(`\$\{\{\s*(github\.(event\.issue\.title|event\.issue\.body|event\.pull_request\.title|event\.pull_request\.body|event\.comment\.body|event\.review\.body|event\.review_comment\.body|event\.pages\.\*\.page_name|event\.head_commit\.message|event\.head_commit\.author\.email|event\.head_commit\.author\.name|event\.commits\.\*\.message|event\.commits\.\*\.author\.email|event\.commits\.\*\.author\.name|head_ref)|inputs\.[A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// injectionExprWarn matches derived/tainted expressions that are a lower-confidence injection risk.
var injectionExprWarn = regexp.MustCompile(`\$\{\{\s*(steps\.[A-Za-z0-9_-]+\.outputs\.[A-Za-z0-9_.*-]+|needs\.[A-Za-z0-9_-]+\.outputs\.[A-Za-z0-9_.*-]+|matrix\.[A-Za-z0-9_.*-]+)\s*\}\}`)

// injectionStepIDRe extracts the step ID from a steps.<id>.outputs.* match.
var injectionStepIDRe = regexp.MustCompile(`\$\{\{\s*steps\.([A-Za-z0-9_-]+)\.outputs\.`)

// taintingActions are action prefixes whose outputs are untrusted user-controlled data
// (e.g. PR changed-file lists). A step.outputs reference from these escalates to SevError.
var taintingActions = []string{
	"tj-actions/changed-files",
	"dorny/paths-filter",
	"jitterbit/get-changed-files",
	"trilom/file-changes-action",
	"tj-actions/verify-changed-files",
}

func ruleScriptInjection(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}
	var out []Issue

	// GHA026 pre-pass: build stepID→uses map per job.
	// We iterate jobs explicitly so we can build a per-job map.
	for jobName, j := range f.WF.Jobs {
		// Build stepID→uses for this job.
		stepIDToUses := make(map[string]string, len(j.Steps))
		for _, s := range j.Steps {
			if s == nil || s.Uses == "" {
				continue
			}
			// Strip @ref for prefix matching.
			at := strings.LastIndex(s.Uses, "@")
			actionName := s.Uses
			if at >= 0 {
				actionName = s.Uses[:at]
			}
			// Use the step name as the id if no explicit id (yaml doesn't expose id through struct,
			// but we can check all steps to find those used earlier in the chain).
			// The YAML `id:` field is not in the Step struct, so we read it from RawNode.
			if s.RawNode != nil && s.RawNode.Kind == yaml.MappingNode {
				for k := 0; k+1 < len(s.RawNode.Content); k += 2 {
					if s.RawNode.Content[k].Value == "id" {
						stepIDToUses[s.RawNode.Content[k+1].Value] = actionName
						break
					}
				}
			}
		}

		for _, s := range j.Steps {
			if s == nil || s.Run == "" {
				continue
			}
			_ = jobName // used implicitly via mkIssue

			if m := injectionExpr.FindString(s.Run); m != "" {
				out = append(out, mkIssue(f, s, "GHA004", SevError,
					fmt.Sprintf("untrusted expression %s in `run:` — pipe via env var instead", m)))
				continue
			}
			if m := injectionExprWarn.FindString(s.Run); m != "" {
				// GHA026 promotion: check if the step ID maps to a tainting action.
				promoted := false
				if idm := injectionStepIDRe.FindStringSubmatch(m); idm != nil {
					stepID := idm[1]
					actionName := stepIDToUses[stepID]
					for _, prefix := range taintingActions {
						if strings.HasPrefix(actionName, prefix) {
							out = append(out, mkIssue(f, s, "GHA004", SevError,
								fmt.Sprintf("expression %s in `run:` derives from %s (known tainted source — see CVE-2023-27529); treat as untrusted user input and pipe via env var", m, actionName)))
							promoted = true
							break
						}
					}
				}
				if !promoted {
					out = append(out, mkIssue(f, s, "GHA004", SevWarning,
						fmt.Sprintf("potentially tainted expression %s in `run:` — pipe via env var instead", m)))
				}
			}
		}
	}
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

// GHA011: actions/checkout with persist-credentials: true (or omitted) under pull_request_target.
func rulePersistCredentialsPRT(f *workflow.File) []Issue {
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
		val, explicitly := s.With["persist-credentials"]
		// Flag when the key is absent (default true) or explicitly set to true.
		if !explicitly || strings.EqualFold(strings.TrimSpace(val), "true") {
			out = append(out, mkIssue(f, s, "GHA011", SevError,
				"actions/checkout with persist-credentials: true under pull_request_target — token remains accessible to subsequent steps; set persist-credentials: false"))
		}
	})
	return out
}

// curlPipeShellRe matches curl/wget piped directly to sh or bash (including -O-/-qO- variants).
var curlPipeShellRe = regexp.MustCompile(`(?i)(curl\s[^|#\n]*\|[^|#\n]*(sh|bash)|wget\s[^|#\n]*\|[^|#\n]*(sh|bash))`)

// GHA012: run: contains curl|bash, wget|sh, or -O-/-qO- piped variants.
func ruleCurlPipeShell(f *workflow.File) []Issue {
	var out []Issue
	visitSteps(f, func(jobName string, idx int, s *workflow.Step) {
		if s.Run == "" {
			return
		}
		if curlPipeShellRe.MatchString(s.Run) {
			out = append(out, mkIssue(f, s, "GHA012", SevWarning,
				"curl/wget piped to shell — download to a file, verify checksum, then execute"))
		}
	})
	return out
}

// untrustedExprRe matches any github.event.* or inputs.* expression (used for key inspection).
var untrustedExprRe = regexp.MustCompile(`\$\{\{\s*(github\.event\.[A-Za-z0-9_.[\]*]+|inputs\.[A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)

// GHA013: actions/cache key: contains github.event.* or inputs.* — cache poisoning vector.
func ruleCacheKeyUntrusted(f *workflow.File) []Issue {
	var out []Issue
	visitSteps(f, func(jobName string, idx int, s *workflow.Step) {
		if s.Uses == "" {
			return
		}
		// Match actions/cache@* or setup-* actions that accept a cache-key input.
		isCache := strings.HasPrefix(s.Uses, "actions/cache@") ||
			strings.HasPrefix(s.Uses, "actions/cache/restore@") ||
			strings.HasPrefix(s.Uses, "actions/cache/save@") ||
			strings.Contains(s.Uses, "setup-")
		if !isCache {
			return
		}
		for _, inputKey := range []string{"key", "cache-key"} {
			val, ok := s.With[inputKey]
			if !ok {
				continue
			}
			if untrustedExprRe.MatchString(val) {
				out = append(out, mkIssue(f, s, "GHA013", SevWarning,
					fmt.Sprintf("cache key %q contains untrusted expression — use content-addressed keys (hashFiles, github.sha, runner.os)", val)))
				return
			}
		}
	})
	return out
}

// legacySetEnvRe matches ::set-env, ::add-path, or enabling unsecure commands.
var legacySetEnvRe = regexp.MustCompile(`(::set-env\s+name=|::add-path::|ACTIONS_ALLOW_UNSECURE_COMMANDS)`)

// GHA014: run: uses disabled ::set-env / ::add-path workflow commands.
func ruleLegacySetEnv(f *workflow.File) []Issue {
	var out []Issue
	visitSteps(f, func(jobName string, idx int, s *workflow.Step) {
		if s.Run == "" {
			return
		}
		if m := legacySetEnvRe.FindString(s.Run); m != "" {
			out = append(out, mkIssue(f, s, "GHA014", SevError,
				fmt.Sprintf("legacy workflow command %q detected — disabled by GitHub since Nov 2020; use $GITHUB_ENV / $GITHUB_PATH instead", m)))
		}
	})
	return out
}

// GHA015: actions/upload-artifact used in a pull_request_target workflow.
func rulePRTArtifactUpload(f *workflow.File) []Issue {
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
		if strings.HasPrefix(s.Uses, "actions/upload-artifact@") {
			out = append(out, mkIssue(f, s, "GHA015", SevError,
				"actions/upload-artifact in a pull_request_target workflow can exfiltrate secrets — use the workflow_run pattern instead"))
		}
	})
	return out
}

// osLabels contains bare OS labels that provide no org-scoped restriction.
var osLabels = map[string]bool{
	"linux":   true,
	"windows": true,
	"macos":   true,
	"x64":     true,
	"arm64":   true,
	"arm":     true,
}

// GHA016: runs-on: with only self-hosted and/or bare OS labels — no org-scoped restriction.
func ruleSelfHostedPublic(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}
	var out []Issue
	for jobName, j := range f.WF.Jobs {
		labels := runsOnLabels(&j.RunsOn)
		if !containsLabel(labels, "self-hosted") {
			continue
		}
		// Check whether there is any label beyond "self-hosted" and the bare OS/arch set.
		hasOrgLabel := false
		for _, l := range labels {
			if l == "self-hosted" {
				continue
			}
			if osLabels[strings.ToLower(l)] {
				continue
			}
			hasOrgLabel = true
			break
		}
		if !hasOrgLabel {
			line := 1
			if j.RunsOn.Line > 0 {
				line = j.RunsOn.Line
			}
			out = append(out, Issue{
				File: f.Path, Line: line, Col: 1,
				Kind: "GHA016", Severity: SevWarning, Source: "ghactor",
				Message: fmt.Sprintf("job %q uses self-hosted runner with no org-scoped label (%v) — fork PRs can target unprotected self-hosted runners",
					jobName, labels),
			})
		}
	}
	return out
}

// runsOnLabels extracts the string labels from a runs-on yaml.Node.
// Handles scalar ("ubuntu-latest"), sequence (["self-hosted","linux"]), and
// mapping ({group: ..., labels: [...]}) forms.
func runsOnLabels(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value != "" {
			return []string{n.Value}
		}
	case yaml.SequenceNode:
		var labels []string
		for _, c := range n.Content {
			if c.Kind == yaml.ScalarNode {
				labels = append(labels, c.Value)
			}
		}
		return labels
	case yaml.MappingNode:
		// runs-on: {group: ..., labels: [...]}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "labels" {
				return runsOnLabels(n.Content[i+1])
			}
		}
	}
	return nil
}

func containsLabel(labels []string, target string) bool {
	for _, l := range labels {
		if strings.EqualFold(l, target) {
			return true
		}
	}
	return false
}

// deployBranches are canonical deploy-related branch names.
var deployBranches = map[string]bool{
	"main":    true,
	"master":  true,
	"release": true,
}

// GHA017: deploy/release workflow without a top-level concurrency: block.
func ruleMissingConcurrencyDeploy(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}
	if !isDeployWorkflow(f) {
		return nil
	}
	// Check for a top-level concurrency: key in the raw YAML node tree.
	if hasConcurrencyBlock(f) {
		return nil
	}
	return []Issue{{
		File: f.Path, Line: 1, Col: 1,
		Kind: "GHA017", Severity: SevInfo, Source: "ghactor",
		Message: "deploy/release workflow has no top-level `concurrency:` block — parallel runs can race; add concurrency: { group: deploy-${{ github.ref }}, cancel-in-progress: false }",
	}}
}

// isDeployWorkflow returns true when the workflow looks like a deploy/release pipeline.
func isDeployWorkflow(f *workflow.File) bool {
	triggers := f.WF.Triggers()
	for _, t := range triggers {
		switch t {
		case "release":
			return true
		case "workflow_dispatch":
			// Flag if the workflow name or filename contains deploy/release.
			name := strings.ToLower(f.WF.Name)
			fname := strings.ToLower(filepath.Base(f.Path))
			if strings.Contains(name, "deploy") || strings.Contains(name, "release") ||
				strings.Contains(fname, "deploy") || strings.Contains(fname, "release") {
				return true
			}
		case "push":
			// Check if branches include main/master/release/* in the On mapping.
			if pushTargetsDeployBranch(f) {
				return true
			}
		}
	}
	return false
}

// pushTargetsDeployBranch checks whether on.push.branches contains a deploy branch name.
func pushTargetsDeployBranch(f *workflow.File) bool {
	on := &f.WF.On
	if on.Kind != yaml.MappingNode {
		return false
	}
	// Find the "push" key in the on: mapping.
	var pushNode *yaml.Node
	for i := 0; i+1 < len(on.Content); i += 2 {
		if on.Content[i].Value == "push" {
			pushNode = on.Content[i+1]
			break
		}
	}
	if pushNode == nil || pushNode.Kind != yaml.MappingNode {
		return false
	}
	// Find the "branches" key inside push.
	var branchesNode *yaml.Node
	for i := 0; i+1 < len(pushNode.Content); i += 2 {
		if pushNode.Content[i].Value == "branches" {
			branchesNode = pushNode.Content[i+1]
			break
		}
	}
	if branchesNode == nil {
		return false
	}
	switch branchesNode.Kind {
	case yaml.ScalarNode:
		return deployBranches[branchesNode.Value] || strings.HasPrefix(branchesNode.Value, "release")
	case yaml.SequenceNode:
		for _, c := range branchesNode.Content {
			if c.Kind == yaml.ScalarNode {
				if deployBranches[c.Value] || strings.HasPrefix(c.Value, "release") {
					return true
				}
			}
		}
	}
	return false
}

// hasConcurrencyBlock inspects the raw yaml.Node tree for a top-level "concurrency" key.
func hasConcurrencyBlock(f *workflow.File) bool {
	if f.Root == nil || len(f.Root.Content) == 0 {
		return false
	}
	top := f.Root.Content[0]
	if top.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(top.Content); i += 2 {
		if top.Content[i].Value == "concurrency" {
			return true
		}
	}
	return false
}

// envSmugglingRe matches echo "VAR=${{ github.event.* or inputs.* }}" >> $GITHUB_ENV (or OUTPUT).
var envSmugglingRe = regexp.MustCompile(
	`\$\{\{\s*(github\.event\.[A-Za-z0-9_.[\]*]+|inputs\.[A-Za-z_][A-Za-z0-9_]*)\s*\}\}` +
		`[^|&\n]*>>\s*\$?(GITHUB_ENV|GITHUB_OUTPUT|\{GITHUB_ENV\}|\{GITHUB_OUTPUT\})`)

// GHA018: untrusted expression written directly into $GITHUB_ENV or $GITHUB_OUTPUT.
func ruleGitHubEnvSmuggling(f *workflow.File) []Issue {
	var out []Issue
	visitSteps(f, func(jobName string, idx int, s *workflow.Step) {
		if s.Run == "" {
			return
		}
		for _, line := range strings.Split(s.Run, "\n") {
			if envSmugglingRe.MatchString(line) {
				out = append(out, mkIssue(f, s, "GHA018", SevError,
					"untrusted expression written directly into $GITHUB_ENV/$GITHUB_OUTPUT — use a step-level env: variable to prevent env-var smuggling"))
				return
			}
		}
	})
	return out
}

// GHA019: job with permissions: id-token: write — flag as reminder to constrain OIDC subject.
func ruleOIDCNoSubject(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}
	var out []Issue
	for jobName, j := range f.WF.Jobs {
		if !jobHasIDTokenWrite(&j.Permissions) {
			continue
		}
		line := 1
		if j.Permissions.Line > 0 {
			line = j.Permissions.Line
		}
		out = append(out, Issue{
			File: f.Path, Line: line, Col: 1,
			Kind: "GHA019", Severity: SevWarning, Source: "ghactor",
			Message: fmt.Sprintf("job %q has permissions: id-token: write — ensure the cloud role trust policy constrains the sub claim (repo/branch/environment) to prevent token misuse by forks",
				jobName),
		})
	}
	return out
}

// jobHasIDTokenWrite returns true when the yaml.Node permissions block contains id-token: write.
func jobHasIDTokenWrite(n *yaml.Node) bool {
	if n == nil || n.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == "id-token" && strings.EqualFold(n.Content[i+1].Value, "write") {
			return true
		}
	}
	return false
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

// writeScopes are the permission scopes whose `write` value triggers GHA020.
var writeScopes = map[string]bool{
	"contents":      true,
	"packages":      true,
	"pull-requests": true,
}

// ruleGHA020WriteJustifyActions are uses: prefixes / run: patterns that justify a write scope
// at the workflow level. If any step matches, we suppress the finding.
var ruleGHA020WriteJustifyActions = []string{
	"actions/upload-release-asset",
	"actions/create-release",
	"softprops/action-gh-release",
	"stefanzweifel/git-auto-commit-action",
	"EndBug/add-and-commit",
	"peter-evans/create-pull-request",
	"docker/build-push-action",
}

// ruleGHA020WriteJustifyRunRe matches git push/commit in a run: block.
var ruleGHA020WriteJustifyRunRe = regexp.MustCompile(`\bgit\s+(push|commit)\b`)

// ruleGHA020DeployTriggers are workflow-level triggers that justify write scopes.
var ruleGHA020DeployTriggers = map[string]bool{
	"release":           true,
	"workflow_dispatch": true,
}

// GHA020: workflow-level write scopes with no apparent usage.
func ruleOverprivilegedToken(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}

	// Only check when there is a workflow-level permissions block.
	wfPerms := &f.WF.Permissions
	if wfPerms.Kind != yaml.MappingNode {
		return nil
	}

	// Collect which write scopes are set at the workflow level.
	var writeFound []string
	var permLine int
	for i := 0; i+1 < len(wfPerms.Content); i += 2 {
		k := wfPerms.Content[i]
		v := wfPerms.Content[i+1]
		if permLine == 0 {
			permLine = k.Line
		}
		if writeScopes[k.Value] && strings.EqualFold(v.Value, "write") {
			writeFound = append(writeFound, k.Value)
		}
	}
	if len(writeFound) == 0 {
		return nil
	}

	// If any job has a job-level permissions block that overrides the scope to read, skip.
	for _, j := range f.WF.Jobs {
		if j.Permissions.Kind == yaml.MappingNode {
			// Job explicitly sets permissions — it may be narrowing. Skip the workflow-level flag
			// only if ALL jobs have an override. For simplicity: any job override suppresses.
			return nil
		}
	}

	// Check deploy-adjacent triggers.
	for _, t := range f.WF.Triggers() {
		if ruleGHA020DeployTriggers[t] {
			return nil
		}
		if t == "push" && pushTargetsDeployBranch(f) {
			return nil
		}
	}

	// Check for actions/run patterns that justify the write scope.
	justified := false
	visitSteps(f, func(_ string, _ int, s *workflow.Step) {
		if justified {
			return
		}
		for _, prefix := range ruleGHA020WriteJustifyActions {
			if strings.HasPrefix(s.Uses, prefix) {
				justified = true
				return
			}
		}
		if ruleGHA020WriteJustifyRunRe.MatchString(s.Run) {
			justified = true
		}
	})
	if justified {
		return nil
	}

	if permLine == 0 {
		permLine = 1
	}
	return []Issue{{
		File: f.Path, Line: permLine, Col: 1,
		Kind: "GHA020", Severity: SevWarning, Source: "ghactor",
		Message: fmt.Sprintf("workflow-level permissions grants write scopes %v with no apparent usage — remove unused write scopes or move them to the job that requires them",
			writeFound),
	}}
}

// GHA021: on.workflow_call.inputs.<name> missing type: key.
func ruleWorkflowCallUntypedInput(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}
	// Walk on: → workflow_call: → inputs: mapping.
	on := &f.WF.On
	if on.Kind != yaml.MappingNode {
		return nil
	}
	wcNode := mapNodePublic(on, "workflow_call")
	if wcNode == nil || wcNode.Kind != yaml.MappingNode {
		return nil
	}
	inputsNode := mapNodePublic(wcNode, "inputs")
	if inputsNode == nil || inputsNode.Kind != yaml.MappingNode {
		return nil
	}

	var out []Issue
	// Each pair in inputsNode.Content is <name-node, input-mapping-node>.
	for i := 0; i+1 < len(inputsNode.Content); i += 2 {
		nameNode := inputsNode.Content[i]
		inputNode := inputsNode.Content[i+1]
		if inputNode.Kind != yaml.MappingNode {
			continue
		}
		hasType := false
		for j := 0; j+1 < len(inputNode.Content); j += 2 {
			if inputNode.Content[j].Value == "type" {
				hasType = true
				break
			}
		}
		if !hasType {
			line := nameNode.Line
			if line == 0 {
				line = 1
			}
			out = append(out, Issue{
				File: f.Path, Line: line, Col: nameNode.Column,
				Kind: "GHA021", Severity: SevWarning, Source: "ghactor",
				Message: fmt.Sprintf("workflow_call input %q has no `type:` — set type: string|boolean|number|choice to enable GitHub input validation",
					nameNode.Value),
			})
		}
	}
	return out
}

// mapNodePublic is a package-visible alias for the private mapNode helper from workflow package.
// Since mapNode is defined in the workflow package (internal), we replicate the logic here.
func mapNodePublic(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// ruleGHA022MatrixOSRe matches runs-on matrix OS expressions.
var ruleGHA022MatrixOSRe = regexp.MustCompile(`\$\{\{\s*matrix\.os\s*\}\}`)

// GHA022: step with run: and no shell: in a multi-OS matrix job with no defaults.run.shell.
func ruleStepShellUnspecified(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}

	// Check workflow-level defaults.run.shell.
	wfDefaultShell := ruleGHA022WorkflowDefaultShell(f)

	var out []Issue
	// Need to walk the raw yaml.Node for strategy.matrix.os and job defaults.
	if f.Root == nil || len(f.Root.Content) == 0 {
		return nil
	}
	top := f.Root.Content[0]
	jobsNode := mapNodePublic(top, "jobs")
	if jobsNode == nil {
		return nil
	}

	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		jobName := jobsNode.Content[i].Value
		jobNode := jobsNode.Content[i+1]
		if jobNode.Kind != yaml.MappingNode {
			continue
		}

		job, ok := f.WF.Jobs[jobName]
		if !ok {
			continue
		}

		// Check if this job is a multi-OS matrix job.
		if !ruleGHA022IsMultiOSJob(job, jobNode) {
			continue
		}

		// Check job-level defaults.run.shell.
		if wfDefaultShell || ruleGHA022JobDefaultShell(jobNode) {
			continue
		}

		// Flag each run: step without shell:.
		for _, s := range job.Steps {
			if s == nil || s.Run == "" {
				continue
			}
			if s.Shell != "" {
				continue
			}
			line := s.Line
			if line == 0 {
				line = 1
			}
			out = append(out, Issue{
				File: f.Path, Line: line, Col: s.Col,
				Kind: "GHA022", Severity: SevInfo, Source: "ghactor",
				Message: fmt.Sprintf("step %q in multi-OS matrix job %q has `run:` with no `shell:` — default shell differs per OS (bash/pwsh); set shell: bash explicitly",
					s.Name, jobName),
			})
		}
	}
	return out
}

// ruleGHA022IsMultiOSJob returns true when the job's runs-on uses matrix.os or the strategy
// matrix contains an os key with multiple values.
func ruleGHA022IsMultiOSJob(job *workflow.Job, jobNode *yaml.Node) bool {
	// Check runs-on for ${{ matrix.os }}.
	runsOn := &job.RunsOn
	switch runsOn.Kind {
	case yaml.ScalarNode:
		if ruleGHA022MatrixOSRe.MatchString(runsOn.Value) {
			return true
		}
	}

	// Check strategy.matrix.os in the job yaml.Node.
	stratNode := mapNodePublic(jobNode, "strategy")
	if stratNode == nil {
		return false
	}
	matrixNode := mapNodePublic(stratNode, "matrix")
	if matrixNode == nil {
		return false
	}
	osNode := mapNodePublic(matrixNode, "os")
	if osNode == nil {
		return false
	}
	// os: must be a sequence with more than one entry to be truly multi-OS.
	if osNode.Kind == yaml.SequenceNode && len(osNode.Content) > 1 {
		return true
	}
	return false
}

// ruleGHA022WorkflowDefaultShell returns true when defaults.run.shell is set at workflow level.
func ruleGHA022WorkflowDefaultShell(f *workflow.File) bool {
	defaults, ok := f.WF.Defaults["run"]
	if !ok {
		return false
	}
	runMap, ok := defaults.(map[string]interface{})
	if !ok {
		return false
	}
	shell, ok := runMap["shell"]
	return ok && shell != ""
}

// ruleGHA022JobDefaultShell returns true when defaults.run.shell is set at the job node level.
func ruleGHA022JobDefaultShell(jobNode *yaml.Node) bool {
	defaultsNode := mapNodePublic(jobNode, "defaults")
	if defaultsNode == nil {
		return false
	}
	runNode := mapNodePublic(defaultsNode, "run")
	if runNode == nil {
		return false
	}
	return mapNodePublic(runNode, "shell") != nil
}

// sha256DigestRe matches an image reference that ends with @sha256:<64-hex-chars>.
var sha256DigestRe = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// GHA023: container: or services.<name>.image: without @sha256: digest pin.
func ruleContainerUnpinned(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}
	if f.Root == nil || len(f.Root.Content) == 0 {
		return nil
	}
	top := f.Root.Content[0]
	jobsNode := mapNodePublic(top, "jobs")
	if jobsNode == nil {
		return nil
	}

	var out []Issue
	for i := 0; i+1 < len(jobsNode.Content); i += 2 {
		jobName := jobsNode.Content[i].Value
		jobNode := jobsNode.Content[i+1]
		if jobNode.Kind != yaml.MappingNode {
			continue
		}

		// Check container: image.
		containerNode := mapNodePublic(jobNode, "container")
		if containerNode != nil {
			out = append(out, ruleGHA023CheckContainer(f, jobName, containerNode)...)
		}

		// Check services: <name>.image.
		servicesNode := mapNodePublic(jobNode, "services")
		if servicesNode != nil && servicesNode.Kind == yaml.MappingNode {
			for j := 0; j+1 < len(servicesNode.Content); j += 2 {
				svcName := servicesNode.Content[j].Value
				svcNode := servicesNode.Content[j+1]
				out = append(out, ruleGHA023CheckService(f, jobName, svcName, svcNode)...)
			}
		}
	}
	return out
}

// ruleGHA023CheckContainer inspects a container: node (scalar or mapping) for an unpinned image.
func ruleGHA023CheckContainer(f *workflow.File, jobName string, n *yaml.Node) []Issue {
	switch n.Kind {
	case yaml.ScalarNode:
		// container: image-name (bare scalar)
		return ruleGHA023CheckImage(f, n, "container", jobName)
	case yaml.MappingNode:
		// container: { image: ..., ... }
		imgNode := mapNodePublic(n, "image")
		if imgNode != nil {
			return ruleGHA023CheckImage(f, imgNode, "container", jobName)
		}
	}
	return nil
}

// ruleGHA023CheckService inspects a services.<name>: node for an unpinned image.
func ruleGHA023CheckService(f *workflow.File, jobName, svcName string, n *yaml.Node) []Issue {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	imgNode := mapNodePublic(n, "image")
	if imgNode == nil {
		return nil
	}
	return ruleGHA023CheckImage(f, imgNode, fmt.Sprintf("services.%s", svcName), jobName)
}

// ruleGHA023CheckImage emits a GHA023 finding when an image node value is not digest-pinned.
func ruleGHA023CheckImage(f *workflow.File, n *yaml.Node, context, jobName string) []Issue {
	img := strings.TrimSpace(n.Value)
	if img == "" {
		return nil
	}
	if sha256DigestRe.MatchString(img) {
		return nil
	}
	line := n.Line
	if line == 0 {
		line = 1
	}
	return []Issue{{
		File: f.Path, Line: line, Col: n.Column,
		Kind: "GHA023", Severity: SevWarning, Source: "ghactor",
		Message: fmt.Sprintf("job %q %s image %q is not pinned by digest — use image@sha256:<digest> for supply-chain integrity",
			jobName, context, img),
	}}
}

// ---------------------------------------------------------------------------
// GHA024 — deprecated-action-version
// ---------------------------------------------------------------------------

// deprecatedVersions maps action names to version-prefix → severity.
// A key of "*" means the entire action is deprecated regardless of version.
var deprecatedVersions = map[string]map[string]Severity{
	"actions/upload-artifact":   {"v1": SevError, "v2": SevError, "v3": SevError},
	"actions/download-artifact": {"v1": SevError, "v2": SevError, "v3": SevError},
	"actions/cache":             {"v1": SevWarning, "v2": SevWarning},
	"actions/checkout":          {"v1": SevWarning, "v2": SevWarning, "v3": SevWarning},
	"actions/setup-node":        {"v1": SevWarning, "v2": SevWarning, "v3": SevWarning},
	"actions/setup-python":      {"v1": SevWarning, "v2": SevWarning, "v3": SevWarning, "v4": SevWarning},
	"actions/setup-go":          {"v1": SevWarning, "v2": SevWarning, "v3": SevWarning, "v4": SevWarning},
	"actions/setup-java":        {"v1": SevWarning, "v2": SevWarning, "v3": SevWarning},
	"actions/github-script":     {"v1": SevWarning, "v2": SevWarning, "v3": SevWarning, "v4": SevWarning, "v5": SevWarning, "v6": SevWarning},
	"actions/create-release":    {"*": SevError},
}

// deprecatedVersionReasons carries human-readable reasons per action name.
var deprecatedVersionReasons = map[string]string{
	"actions/upload-artifact":   "v1/v2/v3 hard-fail since 2025-01-30; upgrade to v4",
	"actions/download-artifact": "v1/v2/v3 hard-fail since 2025-01-30; upgrade to v4",
	"actions/cache":             "v1/v2 use Node 12/16 (EOL); upgrade to v3+",
	"actions/checkout":          "v1/v2/v3 use Node 16 (EOL); upgrade to v4",
	"actions/setup-node":        "v1/v2/v3 use Node 16 (EOL); upgrade to v4",
	"actions/setup-python":      "v1–v4 use deprecated Node runtimes; upgrade to v5",
	"actions/setup-go":          "v1–v4 use deprecated Node runtimes; upgrade to v5",
	"actions/setup-java":        "v1/v2/v3 use deprecated Node runtimes; upgrade to v4",
	"actions/github-script":     "v1–v6 use deprecated Node runtimes; upgrade to v7",
	"actions/create-release":    "action is archived and no longer maintained; use softprops/action-gh-release",
}

// deprecatedVersionLinks carries reference URLs per action name.
var deprecatedVersionLinks = map[string]string{
	"actions/upload-artifact":   "https://github.blog/changelog/2024-04-16-deprecation-notice-v1-and-v2-of-the-artifact-actions/",
	"actions/download-artifact": "https://github.blog/changelog/2024-04-16-deprecation-notice-v1-and-v2-of-the-artifact-actions/",
	"actions/cache":             "https://github.blog/changelog/2022-10-11-github-actions-deprecating-save-state-and-set-output-commands/",
	"actions/checkout":          "https://github.blog/changelog/2023-09-22-github-actions-transitioning-from-node-16-to-node-20/",
	"actions/setup-node":        "https://github.blog/changelog/2023-09-22-github-actions-transitioning-from-node-16-to-node-20/",
	"actions/setup-python":      "https://github.blog/changelog/2023-09-22-github-actions-transitioning-from-node-16-to-node-20/",
	"actions/setup-go":          "https://github.blog/changelog/2023-09-22-github-actions-transitioning-from-node-16-to-node-20/",
	"actions/setup-java":        "https://github.blog/changelog/2023-09-22-github-actions-transitioning-from-node-16-to-node-20/",
	"actions/github-script":     "https://github.blog/changelog/2023-09-22-github-actions-transitioning-from-node-16-to-node-20/",
	"actions/create-release":    "https://github.com/actions/create-release",
}

// majorVersionRe extracts the major version prefix (e.g. "v3") from a tag like "v3.1.2" or "v3".
var majorVersionRe = regexp.MustCompile(`^(v\d+)`)

// GHA024: step uses a known-deprecated version of an action.
func ruleDeprecatedActionVersion(f *workflow.File) []Issue {
	var out []Issue
	lines := strings.Split(string(f.Source), "\n")

	visitSteps(f, func(jobName string, idx int, s *workflow.Step) {
		if s.Uses == "" {
			return
		}
		at := strings.LastIndex(s.Uses, "@")
		if at < 0 {
			return
		}
		actionName := s.Uses[:at]
		ref := s.Uses[at+1:]

		versions, ok := deprecatedVersions[actionName]
		if !ok {
			return
		}

		// Determine the version tag to check.
		// For SHA-pinned refs, extract the tag from the trailing comment.
		versionTag := ref
		if sha40.MatchString(ref) {
			// Look at the raw source line for a comment annotation.
			stepLine := s.Line
			if stepLine > 0 && stepLine <= len(lines) {
				raw := lines[stepLine-1]
				cm := tagAnnotation.FindStringSubmatch(raw)
				if cm == nil {
					// No comment annotation — can't determine version, skip.
					return
				}
				versionTag = cm[1]
			} else {
				return
			}
		}

		// Check for wildcard deprecation first (whole action deprecated).
		if sev, hasWild := versions["*"]; hasWild {
			reason := deprecatedVersionReasons[actionName]
			link := deprecatedVersionLinks[actionName]
			out = append(out, mkIssue(f, s, "GHA024", sev,
				fmt.Sprintf("action %s@%s — %s (see %s)", actionName, versionTag, reason, link)))
			return
		}

		// Extract major version and check.
		m := majorVersionRe.FindStringSubmatch(versionTag)
		if m == nil {
			return
		}
		major := m[1]
		sev, deprecated := versions[major]
		if !deprecated {
			return
		}
		reason := deprecatedVersionReasons[actionName]
		link := deprecatedVersionLinks[actionName]
		out = append(out, mkIssue(f, s, "GHA024", sev,
			fmt.Sprintf("action %s@%s — %s (see %s)", actionName, versionTag, reason, link)))
	})
	return out
}

// ---------------------------------------------------------------------------
// GHA025 — deprecated-runner-image
// ---------------------------------------------------------------------------

// deprecatedRunners maps runner image names to their severity and reason.
var deprecatedRunners = map[string]struct {
	Sev    Severity
	Reason string
}{
	"ubuntu-20.04": {SevError, "removed 2025-04; migrate to ubuntu-22.04 or ubuntu-24.04"},
	"macos-12":     {SevError, "removed 2024-12; migrate to macos-14 or macos-15"},
	"macos-13":     {SevWarning, "deprecation announced 2025-09, unsupported 2025-12; migrate to macos-14"},
	"windows-2019": {SevWarning, "deprecated; migrate to windows-2022 or windows-2025"},
}

// GHA025: runs-on uses a removed or deprecated runner image.
func ruleDeprecatedRunnerImage(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}
	var out []Issue
	for jobName, j := range f.WF.Jobs {
		labels := runsOnLabels(&j.RunsOn)
		for _, label := range labels {
			// Self-hosted runners: skip.
			if strings.EqualFold(label, "self-hosted") || strings.HasPrefix(strings.ToLower(label), "self-hosted") {
				break
			}
			info, bad := deprecatedRunners[strings.ToLower(label)]
			if !bad {
				continue
			}
			line := j.RunsOn.Line
			if line == 0 {
				line = 1
			}
			out = append(out, Issue{
				File: f.Path, Line: line, Col: 1,
				Kind: "GHA025", Severity: info.Sev, Source: "ghactor",
				Message: fmt.Sprintf("job %q uses deprecated runner %q — %s", jobName, label, info.Reason),
			})
			break // one finding per job
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// GHA027 — publish-cache-restore
// GHA028 — no-build-provenance
// (shared isPublishWorkflow helper)
// ---------------------------------------------------------------------------

// publishActions are action prefixes that indicate a publish/release workflow.
var publishActions = []string{
	"softprops/action-gh-release",
	"pypa/gh-action-pypi-publish",
	"actions/create-release",
	"docker/build-push-action",
	"goreleaser/goreleaser-action",
	"actions/attest-build-provenance",
	"sigstore/cosign-installer",
	"aws-actions/amazon-ecr-login",
	"google-github-actions/auth",
}

// isPublishWorkflow returns true if the workflow looks like a release/publish pipeline.
// It checks for: release trigger, push with tag filter, or a step using a known publish action.
func isPublishWorkflow(f *workflow.File) bool {
	if f == nil || f.WF == nil {
		return false
	}
	triggers := f.WF.Triggers()
	for _, t := range triggers {
		if t == "release" {
			return true
		}
		if t == "workflow_dispatch" {
			// workflow_dispatch with a tag-like input name hints at publish.
			name := strings.ToLower(f.WF.Name)
			fname := strings.ToLower(filepath.Base(f.Path))
			if strings.Contains(name, "release") || strings.Contains(name, "publish") ||
				strings.Contains(fname, "release") || strings.Contains(fname, "publish") {
				return true
			}
		}
	}
	// Check for push with tag filter in the on: mapping.
	on := &f.WF.On
	if on.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(on.Content); i += 2 {
			if on.Content[i].Value == "push" {
				pushNode := on.Content[i+1]
				if pushNode.Kind == yaml.MappingNode {
					tagsNode := mapNodePublic(pushNode, "tags")
					if tagsNode != nil {
						return true
					}
				}
				break
			}
		}
	}
	// Check whether any step uses a known publish action.
	found := false
	visitSteps(f, func(_ string, _ int, s *workflow.Step) {
		if found {
			return
		}
		for _, prefix := range publishActions {
			if strings.HasPrefix(s.Uses, prefix) {
				found = true
				return
			}
		}
	})
	return found
}

// GHA027: publish workflow that restores a build cache via actions/cache.
// This flags only explicit actions/cache steps (not setup-* implicit caching,
// which uses content-addressed keys and is a lower-risk profile).
func rulePublishCacheRestore(f *workflow.File) []Issue {
	if !isPublishWorkflow(f) {
		return nil
	}
	var out []Issue
	visitSteps(f, func(_ string, _ int, s *workflow.Step) {
		if s.Uses == "" {
			return
		}
		if strings.HasPrefix(s.Uses, "actions/cache@") {
			out = append(out, mkIssue(f, s, "GHA027", SevWarning,
				"publish/release workflow restores a build cache — an attacker with cache-write from a feature branch can poison the restore; build from source without cache on release"))
		}
	})
	return out
}

// provenanceActions are action prefixes that satisfy GHA028 (attestation/signing present).
// goreleaser-action is included because GoReleaser with COSIGN_EXPERIMENTAL performs
// keyless artifact signing, which is an equivalent form of supply-chain attestation.
var provenanceActions = []string{
	"actions/attest-build-provenance",
	"sigstore/cosign-installer",
	"sigstore/cosign-action",
	"anchore/sbom-action",
	"github/codeql-action/upload-sarif",
	"goreleaser/goreleaser-action",
}

// GHA028: publish workflow without actions/attest-build-provenance or equivalent signing.
func ruleNoBuildProvenance(f *workflow.File) []Issue {
	if !isPublishWorkflow(f) {
		return nil
	}
	hasAttest := false
	visitSteps(f, func(_ string, _ int, s *workflow.Step) {
		for _, prefix := range provenanceActions {
			if strings.HasPrefix(s.Uses, prefix) {
				hasAttest = true
				return
			}
		}
	})
	if hasAttest {
		return nil
	}
	// Emit on line 1 (the on: block position is a reasonable anchor).
	line := 1
	if f.WF.On.Line > 0 {
		line = f.WF.On.Line
	}
	return []Issue{{
		File: f.Path, Line: line, Col: 1,
		Kind: "GHA028", Severity: SevInfo, Source: "ghactor",
		Message: "publish/release workflow has no actions/attest-build-provenance step — consider attesting build provenance for supply-chain transparency (opt-in: disable with `--disable GHA028`)",
	}}
}

// ---------------------------------------------------------------------------
// GHA029 — cross-org-secrets-inherit
// ---------------------------------------------------------------------------

// currentRepoOwner attempts to determine the repository owner from the environment
// or from the git remote URL. Returns "" if it cannot be determined.
func currentRepoOwner() string {
	// GITHUB_REPOSITORY is set by GitHub Actions: "owner/repo".
	if v := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY")); v != "" {
		if idx := strings.Index(v, "/"); idx > 0 {
			return v[:idx]
		}
	}
	return ""
}

// GHA029: reusable workflow call with secrets: inherit where the callee owner
// differs from the current repo owner.
func ruleCrossOrgSecretsInherit(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}
	owner := currentRepoOwner()
	if owner == "" {
		// Can't determine owner — skip gracefully.
		return nil
	}
	var out []Issue
	for _, ru := range f.WF.Reusables {
		if !ru.SecretsInherit {
			continue
		}
		if strings.EqualFold(ru.Owner, owner) {
			continue
		}
		line := ru.Line
		if line == 0 {
			line = 1
		}
		uses := ru.Owner + "/" + ru.Repo + "/" + ru.Path + "@" + ru.Ref
		out = append(out, Issue{
			File: f.Path, Line: line, Col: ru.Col,
			Kind: "GHA029", Severity: SevWarning, Source: "ghactor",
			Message: fmt.Sprintf("reusable workflow %q from external org %q uses `secrets: inherit` — all repository secrets are forwarded to a third-party workflow; pass only required secrets explicitly",
				uses, ru.Owner),
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// GHA030 — action-not-in-allowlist
// optAllowRules returns a GHA030 rule when an allowlist is configured.
// ---------------------------------------------------------------------------

// ruleActionNotInAllowlist returns a check function that flags actions not matching
// any glob in the provided allowlist. When allowPatterns is empty, returns nil.
func ruleActionNotInAllowlist(allowPatterns []string) func(*workflow.File) []Issue {
	if len(allowPatterns) == 0 {
		return nil
	}
	return func(f *workflow.File) []Issue {
		var out []Issue
		visitSteps(f, func(_ string, _ int, s *workflow.Step) {
			if s.Uses == "" || strings.HasPrefix(s.Uses, "./") || strings.HasPrefix(s.Uses, "docker://") {
				return
			}
			at := strings.LastIndex(s.Uses, "@")
			var ownerRepo string
			if at >= 0 {
				ownerRepo = s.Uses[:at]
			} else {
				ownerRepo = s.Uses
			}
			for _, pat := range allowPatterns {
				patName, _, _ := strings.Cut(pat, "@")
				if ok, _ := doublestar.Match(patName, ownerRepo); ok {
					return // allowed
				}
			}
			out = append(out, mkIssue(f, s, "GHA030", SevError,
				fmt.Sprintf("action %q is not in the allow_actions allowlist — add it to .ghactor.yml allow_actions or use an approved alternative", s.Uses)))
		})
		return out
	}
}

// ---------------------------------------------------------------------------
// GHA031 — obfuscated-run
// ---------------------------------------------------------------------------

var (
	obfuscatedBase64PipeRe  = regexp.MustCompile(`\bbase64\s+(-d|--decode)\b[^|]*\|\s*(sh|bash|zsh)\b`)
	obfuscatedLongBase64Re  = regexp.MustCompile(`[A-Za-z0-9+/=]{200,}`)
	obfuscatedEvalCurlRe    = regexp.MustCompile(`\beval\s+.*\$\(?\s*curl\b`)
	obfuscatedCurlInterpRe  = regexp.MustCompile(`\bcurl\s+[^|;]+\|\s*(python3?|perl|ruby|node)\b`)
)

// GHA031: run: step contains obfuscated shell patterns.
func ruleObfuscatedRun(f *workflow.File) []Issue {
	var out []Issue
	visitSteps(f, func(_ string, _ int, s *workflow.Step) {
		if s.Run == "" {
			return
		}
		if obfuscatedBase64PipeRe.MatchString(s.Run) {
			out = append(out, mkIssue(f, s, "GHA031", SevWarning,
				"base64 decode piped to shell — potentially obfuscated code execution"))
		}
		if obfuscatedEvalCurlRe.MatchString(s.Run) {
			out = append(out, mkIssue(f, s, "GHA031", SevWarning,
				"eval on curl output — remote code execution without integrity check"))
		}
		if obfuscatedCurlInterpRe.MatchString(s.Run) {
			out = append(out, mkIssue(f, s, "GHA031", SevWarning,
				"pipe-to-interpreter — curl output piped directly to python/perl/ruby/node"))
		}
		if obfuscatedLongBase64Re.MatchString(s.Run) {
			out = append(out, mkIssue(f, s, "GHA031", SevWarning,
				"long base64-like literal (≥200 chars) in run: — possible obfuscated payload"))
		}
	})
	return out
}

// ---------------------------------------------------------------------------
// GHA032 — spoofable-actor-check
// ---------------------------------------------------------------------------

// spoofableActorRe matches github.actor or github.triggering_actor compared to a [bot] string.
var spoofableActorRe = regexp.MustCompile(`github\.(actor|triggering_actor)\s*==\s*['"][^'"]*\[bot\]['"]`)

// GHA032: if: condition compares github.actor to a [bot] string — spoofable.
func ruleSpoofableActorCheck(f *workflow.File) []Issue {
	if f == nil || f.WF == nil {
		return nil
	}
	var out []Issue
	for _, j := range f.WF.Jobs {
		if spoofableActorRe.MatchString(j.If) {
			line := j.RunsOn.Line
			if line == 0 {
				line = 1
			}
			out = append(out, Issue{
				File: f.Path, Line: line, Col: 1,
				Kind: "GHA032", Severity: SevWarning, Source: "ghactor",
				Message: "job `if:` checks github.actor/triggering_actor against a [bot] identity — spoofable by any user naming their account identically; use github.event.pull_request.user.login + github.event_name gating instead",
			})
		}
		for _, s := range j.Steps {
			if s == nil {
				continue
			}
			if spoofableActorRe.MatchString(s.If) {
				out = append(out, mkIssue(f, s, "GHA032", SevWarning,
					"step `if:` checks github.actor/triggering_actor against a [bot] identity — spoofable; use github.event.pull_request.user.login + github.event_name gating instead"))
			}
		}
	}
	return out
}

// optAllowlistRule returns a GHA030 Rule entry when allow_actions is configured.
// This mirrors the same pattern as optRules for deny_actions.
func optAllowlistRule(allowPatterns []string) *Rule {
	if len(allowPatterns) == 0 {
		return nil
	}
	return &Rule{
		ID:       "GHA030",
		Title:    "action-not-in-allowlist",
		Severity: SevError,
		Description: "Your ghactor configuration defines an `allow_actions` allowlist. When this " +
			"list is non-empty, every `uses:` reference must match at least one glob pattern in the " +
			"list. Actions not in the allowlist have not been reviewed and approved for use in this " +
			"repository. This is the inverse of `deny_actions` — rather than blocking known-bad " +
			"actions, it blocks everything not explicitly approved.",
		Remediation: "Add the action to the `allow_actions` list in `.ghactor.yml` after your " +
			"security team reviews it, or replace it with an approved alternative. Use glob patterns " +
			"like `actions/*` to approve an entire org's actions. Empty list disables enforcement.",
		References: []string{
			"https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions",
			"https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-07-Insecure-System-Configuration",
		},
		Check: ruleActionNotInAllowlist(allowPatterns),
	}
}

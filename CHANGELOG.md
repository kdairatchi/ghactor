# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-04-18

### Added — new commands
- **`explain <RULE_ID>`** — detailed rule card with description, remediation, references, and before/after YAML fix example. `--json` for machine-readable output.
- **`gen [template]`** — scaffold hardened workflow YAML with pinned SHAs, least-privilege permissions, and job-level timeouts baked in. Eight templates: `ci-go`, `ci-node`, `ci-python`, `codeql`, `release-goreleaser`, `attest-release`, `dependabot`, `ghactor-self`. Supports `-o FILE`, `--force`, and `--var key=value` overrides.
- **`watch`** — fsnotify-based auto re-lint on YAML change with debounced rename-over-write handling. `--clear` clears the terminal between runs, `--debounce DURATION` tunes responsiveness.
- **`baseline {create,status,prune}`** — snapshot current findings so CI fails only on *new* issues. Line-independent SHA-256 fingerprints with ±2-line shift tolerance (ideal for legacy-repo adoption).
- **`audit`** — cross-check pinned actions against the GitHub Advisory Database (GHSA). `--offline` runs against a static deny list only. `--no-archival` / `--no-missing` disable archived-repo and 404/deleted-repo checks.
- **`secrets`** — Gitleaks-style scan of workflow YAML for leaked API keys, tokens, and private keys. `--entropy` adds high-entropy string detection.
- **`sarifdiff`** — diff two SARIF reports to surface new findings between baseline and head.

### Added — new rules (GHA011–GHA032)
- **GHA011** (error) — `actions/checkout` with `persist-credentials: true` under `pull_request_target` (token theft).
- **GHA012** (warn) — `run:` contains `curl | sh` / `wget | bash` pattern (remote code execution).
- **GHA013** (warn) — `actions/cache` key derived from untrusted `github.event.*` / `inputs.*` (cache poisoning).
- **GHA014** (error) — Legacy `::set-env` / `::add-path` / `ACTIONS_ALLOW_UNSECURE_COMMANDS=true` (disabled since Nov 2020).
- **GHA015** (error) — `actions/upload-artifact` under `pull_request_target` (artifact exfil of secrets).
- **GHA016** (warn) — `self-hosted` runner with no restrictive labels — fork PRs can target it.
- **GHA017** (info) — Deploy/release workflow has no `concurrency:` block (double-deploy race).
- **GHA018** (error) — Untrusted expression written to `$GITHUB_ENV` / `$GITHUB_OUTPUT` (env smuggling).
- **GHA019** (warn) — Job requests `id-token: write` — verify OIDC trust policy constrains `sub`/`aud`.
- **GHA020** (warn) — `permissions:` grants `write-all` / broad `write` — narrow to least-privilege.
- **GHA021** (warn) — Reusable workflow `workflow_call` input is untyped — pin `type:` to prevent coercion.
- **GHA022** (info) — Step `run:` block with no `shell:` — default drifts across runners (bash vs. pwsh).
- **GHA023** (warn) — `container:` / `services.*.image:` pinned by tag, not digest.
- **GHA024** (warn/error) — Action pinned to deprecated major (e.g. `actions/upload-artifact@v3` — hard-fail since 2025-01-30).
- **GHA025** (warn/error) — Job uses deprecated/removed runner image (`ubuntu-20.04`, `macos-12`, `windows-2019`, …).
- **GHA026** — `GHA004` promotion for untrusted `steps.<id>.outputs.*` from known-tainted actions (`tj-actions/changed-files`, CVE-2023-27529).
- **GHA027** (warn) — Publish/release workflow restores a build cache — feature-branch cache poisoning into release.
- **GHA028** (info) — Publish/release workflow has no `actions/attest-build-provenance` step.
- **GHA029** (warn) — Reusable workflow from external org with `secrets: inherit` — forwards all repo secrets.
- **GHA030** (error) — Action not in `.ghactor.yml` `allow_actions:` allowlist (opt-in — only fires when configured).
- **GHA031** (warn) — `run:` obfuscation — base64 decode piped to shell, `eval` of `${{ }}`, `curl | bash` chains.
- **GHA032** (warn) — Job `if:` gating on spoofable `github.actor` / `[bot]` identity match.

### Added — output formats
- **JUnit XML** (`--junit FILE`) — Jenkins/GitLab CI integration.
- **GitHub workflow annotations** (`--github`) — `::error file=…` / `::warning file=…` / `::notice file=…` on stdout.
- **SARIF 2.1.0** rule catalog with `shortDescription`, `fullDescription`, `help.markdown`, `helpUri`, `defaultConfiguration.level`, and `ruleIndex` on results.
- **Composite action linting** (`--actions DIR`) — lint `action.yml` files alongside workflow YAML.

### Added — filtering and CI adoption
- `--since REF` — lint only files changed relative to a git ref (`origin/main`, `v0.2.0`, `HEAD~10`).
- `--baseline FILE` — suppress known findings listed in a baseline file; report only *new* findings.
- `--resolve-drift` — GHA008 online check: compare pinned SHA to the current SHA for the commented tag.
- `.ghactor.yml` rule severity overrides with canonical aliases (`off` / `disable` / `disabled` / `none` / `ignore`).
- `.ghactor.yml` `allow_actions` allowlist (GHA030).

### Added — fix engine
- `--fix-perms` — add minimal `permissions:` blocks where missing.
- `--fix-shell` — add `shell: bash` to steps without explicit shell.
- `--fix-containers` — rewrite `container:` / `services.*.image:` from tag to digest (requires Docker).
- `--default-shell SHELL` — tune the default shell injected by `--fix-shell`.
- `--all` — apply all safe autofixers.

### Changed
- **Pin cache** schema v2 with per-entry 30-day TTL; auto-migrates v1 flat map.
- **Trail** now uses GitHub REST directly by default (reads `GITHUB_TOKEN` / `GHACTOR_GITHUB_TOKEN`), with transparent `gh` CLI fallback when no token is set. Supports GHES via `GITHUB_API_URL`.
- **Doctor** JSON output now includes `config_path` and canonical `score` from a single source.
- **Workflow AST** — `ReusableUse.SecretsInherit` field added (zero-value safe).

### Security (self-hardening)
- Release workflow permissions moved workflow → job level (workflow-level is now `contents: read`).
- Self-lint passes clean under `--only-ghactor` except for the expected `id-token: write` advisory on the release job (required for Sigstore keyless signing).

## [0.2.0] - 2026-04-15

### Added
- Initial release of ghactor security-first CLI for GitHub Actions workflows
- **Lint command**: Run rhysd/actionlint + ghactor's 10 security rules (GHA001–GHA010)
  - GHA001: Unpinned actions (supply-chain attack risk)
  - GHA002: Missing permissions block (least-privilege enforcement)
  - GHA003: pull_request_target + untrusted checkout (pwn-request pattern)
  - GHA004: Script injection via untrusted context interpolation
  - GHA005: Missing timeout-minutes
  - GHA006: Floating action references (@main, @master, @latest, @HEAD)
  - GHA007: Actions with no @ref specified
  - GHA008: Pinned SHA stale relative to comment tag
  - GHA009: Reusable workflow ref is floating or tag-based
  - GHA010: Action matches deny_actions glob from config
- **Pin command**: Rewrite `uses: owner/repo@tag` to `@<40-char SHA> # tag` via gh API
- **Fix command**: Apply safe autofixes (permissions blocks, timeout-minutes injection, optionally pin)
- **Update command**: Compare actions to latest releases and optionally rewrite to latest (pinned by SHA)
- **Trial command**: Shell to nektos/act for local workflow testing
- **Trail command**: Inspect recent workflow runs with success/fail/avg duration metrics and failure-rate gating
- **Doctor command**: Repo-wide workflow health report with 0–100 score and per-rule breakdowns
- **Rules command**: List all ghactor rules with optional verbose mode showing descriptions and remediation
- **SARIF output**: Export linting results as SARIF 2.1.0 for GitHub code scanning integration
- **Config file support**: `.ghactor.yml` for controlling linting behavior (ignore-actionlint, fail-on level, deny-actions patterns)

### Technical Details
- Written in Go 1.23, single binary distribution
- Exposes ghactor as GitHub Action composite action (installs and runs via go install)
- Pre-commit hook support for inline workflow validation

---

For installation and usage instructions, see [README.md](README.md).

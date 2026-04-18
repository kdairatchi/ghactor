# ghactor

Security-first CLI for GitHub Actions workflows. Lint, fix, pin to SHA, trial-run, and inspect recent runs — all from one binary.

```
 ┓
┓┓┣┓┏┓┏╋┏┓┏┓
┗┫┛┗┗┻┗┗┗┛┛   lint · fix · pin · trial · trail
```

## Install

```sh
go install github.com/kdairatchi/ghactor/cmd/ghactor@latest
```

Requires `gh` (GitHub CLI) for `pin`, `update`, and `trail`. Requires `act` (nektos/act) for `trial`.

## Commands

| Command   | What it does                                                                      |
|-----------|-----------------------------------------------------------------------------------|
| `lint`    | Run rhysd/actionlint **and** ghactor's security rules (GHA001–GHA010)             |
| `pin`     | Rewrite `uses: owner/repo@tag` to `@<40-char SHA> # tag` via `gh api`             |
| `fix`     | Add missing `permissions:`, inject `timeout-minutes:`, optionally pin             |
| `update`  | Show which actions have newer releases (via `gh api .../releases/latest`)         |
| `trial`   | Shell to `act` to run a workflow locally                                          |
| `trail`   | Pretty-print recent runs with success/fail/avg duration (via `gh run list`)       |
| `doctor`  | Repo-wide health report with 0–100 score                                          |
| `rules`   | List all ghactor rules                                                            |

## Rules

| ID      | Severity   | What                                                                                                 |
|---------|------------|------------------------------------------------------------------------------------------------------|
| GHA001  | warn       | Action pinned by tag, not 40-char SHA                                                                |
| GHA002  | warn       | No `permissions:` block — defaults to write-all                                                      |
| GHA003  | error      | `pull_request_target` + checkout of PR head ref (pwn-request pattern)                               |
| GHA004  | error      | Untrusted `${{ github.event.* }}` interpolated into `run:` (injection)                              |
| GHA005  | info       | Job has no `timeout-minutes:` (default 360)                                                          |
| GHA006  | warn       | Action pinned to floating ref (`@main`, `@master`, `@latest`, `@HEAD`)                              |
| GHA007  | warn       | `uses:` with no `@ref` at all                                                                        |
| GHA008  | warn       | Pinned SHA is stale — the `# tag` comment resolves to a different SHA; requires `Resolver` in opts  |
| GHA009  | error/warn | Reusable workflow ref is a floating branch (error) or a semver tag rather than a SHA (warning)      |
| GHA010  | error      | Action matches a `deny_actions` glob pattern from `.ghactor.yml`                                     |

## Examples

```sh
ghactor lint                                  # actionlint + ghactor rules
ghactor lint --only-ghactor --disable GHA005  # only our rules, skip timeouts
ghactor lint --json | jq '.[] | select(.severity=="error")'

ghactor pin --dry-run                         # preview SHA pinning
ghactor pin                                   # rewrite files in place (cache at .ghactor/cache.json)

ghactor fix --timeout 15 --pin                # add perms, 15-min timeouts, pin all

ghactor doctor                                # scored health report
ghactor trail -n 50                           # last 50 runs
ghactor trial -e pull_request                 # run locally via act
```

## Exit codes

`lint` exits 1 on findings at or above `--fail-on` (default `warning`). Use `--fail-on error` for CI that only blocks on real security issues.

## Using in CI

**As a composite action** — findings land in the Security tab via SARIF upload:

```yaml
name: ghactor
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4
      - uses: kdairatchi/ghactor@v1
        with:
          fail-on: error
          disable: GHA005
```

**Or call the CLI directly:**

```yaml
- uses: actions/setup-go@11bd71901bbe5b1630ceea73d27597364c9af683 # v5
  with: { go-version: stable }
- run: go install github.com/kdairatchi/ghactor/cmd/ghactor@latest
- run: ghactor lint --sarif ghactor.sarif --fail-on error
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ghactor.sarif
    category: ghactor
```

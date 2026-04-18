<div align="center">

<img src=".github/banner.png" alt="ghactor" width="720">

# ghactor

**Security-first CLI for GitHub Actions.** Lint, fix, SHA-pin, trial-run, and audit recent runs — from one binary.

<p>
  <a href="https://github.com/kdairatchi/ghactor/releases"><img src="https://img.shields.io/github/v/release/kdairatchi/ghactor?style=flat-square&labelColor=0d0d15&color=f0c040" alt="Release"></a>
  <a href="https://pkg.go.dev/github.com/kdairatchi/ghactor"><img src="https://img.shields.io/badge/go-1.22%2B-06b6d4?style=flat-square&labelColor=0d0d15" alt="Go"></a>
  <a href="https://github.com/kdairatchi/ghactor/blob/main/LICENSE"><img src="https://img.shields.io/github/license/kdairatchi/ghactor?style=flat-square&labelColor=0d0d15&color=06b6d4" alt="License"></a>
  <a href="https://github.com/kdairatchi/ghactor/actions"><img src="https://img.shields.io/github/actions/workflow/status/kdairatchi/ghactor/ci.yml?style=flat-square&labelColor=0d0d15&color=f0c040" alt="CI"></a>
</p>

</div>

---

## Why ghactor

GitHub Actions is a supply-chain minefield. Floating `@main` tags drift under you. Missing `permissions:` blocks default to *write-all*. A careless `pull_request_target` plus a PR-head checkout is full repo takeover. Most teams catch this in review — if at all.

ghactor catches it before the workflow ships:

- **`lint`** wraps `actionlint` with ten security rules focused on the things that actually get exploited (pwn-request, injection, floating refs, stale pins).
- **`pin`** rewrites every `uses:` to a 40-char SHA with the original tag preserved as a comment, so upgrades still diff cleanly.
- **`fix`** auto-adds `permissions:`, job timeouts, and optional SHA pinning in a single pass.
- **`trial`** shells to `act` so you run the workflow locally before you merge.
- **`doctor`** gives you a 0–100 posture score for the whole repo.

One binary, zero Node runtime, ships as a composite Action or a CLI.

## Install

```sh
go install github.com/kdairatchi/ghactor/cmd/ghactor@latest
```

Requires `gh` (GitHub CLI) for `pin`, `update`, and `trail`. Requires [`act`](https://github.com/nektos/act) for `trial`.

## How it fits together

```mermaid
flowchart LR
    W["workflows/*.yml"] --> L["lint"]
    W --> F["fix"]
    W --> P["pin"]
    W --> T["trial"]
    L --> S{"SARIF?"}
    S -->|yes| GH["GitHub Security tab"]
    S -->|no| C["CLI output"]
    F -->|--pin| P
    P --> W
    T --> ACT["act local runner"]

    classDef cmd fill:#0d0d15,stroke:#f0c040,color:#f0c040
    classDef sink fill:#0d0d15,stroke:#06b6d4,color:#06b6d4
    classDef src fill:#111119,stroke:#9ca3af,color:#fff
    class L,F,P,T cmd
    class GH,C,ACT sink
    class W,S src
```

## Commands

| Command   | What it does                                                                      |
|-----------|-----------------------------------------------------------------------------------|
| `lint`    | Runs `actionlint` **plus** ghactor's security rules (GHA001–GHA010)               |
| `pin`     | Rewrites `uses: owner/repo@tag` to `@<40-char SHA> # tag` via `gh api`            |
| `fix`     | Adds missing `permissions:`, injects `timeout-minutes:`, optionally pins          |
| `update`  | Shows which actions have newer releases (via `gh api .../releases/latest`)        |
| `trial`   | Shells to `act` to run a workflow locally                                         |
| `trail`   | Pretty-prints recent runs with success/fail/avg duration (via `gh run list`)      |
| `doctor`  | Repo-wide health report with a 0–100 score                                        |
| `rules`   | Lists all ghactor rules                                                           |

## Rules

The ten rules group into three lanes — **injection**, **drift**, and **least-privilege**. `lint` runs all of them by default.

```mermaid
flowchart TB
    subgraph INJ["injection"]
        direction LR
        GHA003["GHA003<br/>pwn-request<br/>error"]
        GHA004["GHA004<br/>expression injection<br/>error"]
    end
    subgraph PIN["drift / supply-chain"]
        direction LR
        GHA001["GHA001<br/>tag not SHA<br/>warn"]
        GHA006["GHA006<br/>floating ref<br/>warn"]
        GHA007["GHA007<br/>no ref<br/>warn"]
        GHA008["GHA008<br/>stale SHA<br/>warn"]
        GHA009["GHA009<br/>reusable wf ref<br/>error / warn"]
        GHA010["GHA010<br/>deny-listed action<br/>error"]
    end
    subgraph LP["least-privilege"]
        direction LR
        GHA002["GHA002<br/>no permissions<br/>warn"]
        GHA005["GHA005<br/>no timeout-minutes<br/>info"]
    end

    classDef err fill:#1a0d0d,stroke:#ef4444,color:#ef4444
    classDef warn fill:#14110a,stroke:#f0c040,color:#f0c040
    classDef info fill:#0a1419,stroke:#06b6d4,color:#06b6d4
    class GHA003,GHA004,GHA009,GHA010 err
    class GHA001,GHA002,GHA006,GHA007,GHA008 warn
    class GHA005 info
```

Full detail: `ghactor rules --verbose`.

| ID      | Severity     | What                                                                                           |
|---------|--------------|------------------------------------------------------------------------------------------------|
| GHA001  | warn         | Action pinned by tag, not 40-char SHA                                                          |
| GHA002  | warn         | No `permissions:` block — defaults to write-all                                                |
| GHA003  | error        | `pull_request_target` + checkout of PR head ref (pwn-request pattern)                          |
| GHA004  | error        | Untrusted `${{ github.event.* }}` interpolated into `run:` (shell injection)                   |
| GHA005  | info         | Job has no `timeout-minutes:` (default 360)                                                    |
| GHA006  | warn         | Action pinned to floating ref (`@main`, `@master`, `@latest`, `@HEAD`)                         |
| GHA007  | warn         | `uses:` with no `@ref` at all                                                                  |
| GHA008  | warn         | Pinned SHA is stale — `# tag` comment resolves to a different SHA (requires `Resolver` opt)    |
| GHA009  | error / warn | Reusable-workflow ref is a floating branch (error) or a semver tag rather than a SHA (warn)    |
| GHA010  | error        | Action matches a `deny_actions` glob in `.ghactor.yml`                                         |

## Examples

```sh
# Lint everything
ghactor lint

# Just the ghactor rules, skip timeouts noise
ghactor lint --only-ghactor --disable GHA005

# Pipe to jq for CI dashboards
ghactor lint --json | jq '.[] | select(.severity=="error")'

# Preview SHA pinning without writing
ghactor pin --dry-run

# Rewrite in place (cache lands in .ghactor/cache.json)
ghactor pin

# One-shot hardening: perms + 15-min timeouts + pin every action
ghactor fix --timeout 15 --pin

# Scored posture report
ghactor doctor

# Last 50 runs, color-coded
ghactor trail -n 50

# Local trial run via act
ghactor trial -e pull_request
```

## Exit codes

`lint` exits `1` on findings at or above `--fail-on` (default `warning`). Use `--fail-on error` in CI when you only want to block on real security issues — everything else stays a signal, not a blocker.

## Using in CI

```mermaid
flowchart LR
    PR["Pull request"] --> CK["actions/checkout"]
    CK --> GA["kdairatchi/ghactor@v1"]
    GA --> SARIF["ghactor.sarif"]
    SARIF --> UP["upload-sarif"]
    UP --> TAB["Security tab"]
    GA -->|"fail-on: error"| FAIL{"Blocking finding?"}
    FAIL -->|yes| BLK["PR blocked"]
    FAIL -->|no| OK["Check passes"]

    classDef cmd fill:#0d0d15,stroke:#f0c040,color:#f0c040
    classDef sink fill:#0d0d15,stroke:#06b6d4,color:#06b6d4
    classDef node fill:#111119,stroke:#9ca3af,color:#fff
    classDef bad fill:#1a0d0d,stroke:#ef4444,color:#ef4444
    classDef good fill:#0d1a10,stroke:#22c55e,color:#22c55e
    class GA cmd
    class TAB,UP,SARIF sink
    class PR,CK,FAIL node
    class BLK bad
    class OK good
```

**As a composite action** — findings land in the Security tab via SARIF:

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

## Config

Optional `.ghactor.yml` at the repo root:

```yaml
fail_on: warning          # error | warning | info
disable:                  # skip specific rules
  - GHA005
deny_actions:             # glob patterns → GHA010 error
  - "some-untrusted-org/*"
  - "*/shady-action"
```

---

<div align="center">

Built by [@kdairatchi](https://github.com/kdairatchi) · part of the [ProwlrBot](https://github.com/ProwlrBot) ecosystem · Licensed MIT

</div>

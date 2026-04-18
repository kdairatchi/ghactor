package fix

import (
	"strings"
	"testing"
)

func TestMovePermsToJob_SingleJobWriteScopes(t *testing.T) {
	// Single job with mixed read+write perms: write scopes move to job, reads stay at top.
	src := `name: release
on: [push]
permissions:
  contents: write
  packages: write
  pull-requests: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	out, changes, note := movePermsToJob("w.yml", []byte(src))
	if note != "" {
		t.Errorf("unexpected note: %s", note)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	s := string(out)

	// Read-only scope stays at top level.
	if !strings.Contains(s, "permissions:\n  pull-requests: read") {
		t.Errorf("read scope missing from top level:\n%s", s)
	}
	// Write scopes should be absent from top-level permissions block
	// (only pull-requests: read should remain).
	topPermsIdx := strings.Index(s, "permissions:")
	jobsIdx := strings.Index(s, "jobs:")
	topPermsSection := s[topPermsIdx:jobsIdx]
	if strings.Contains(topPermsSection, "contents: write") {
		t.Errorf("contents: write should not remain at top level:\n%s", topPermsSection)
	}
	if strings.Contains(topPermsSection, "packages: write") {
		t.Errorf("packages: write should not remain at top level:\n%s", topPermsSection)
	}

	// Write scopes appear under the job.
	buildIdx := strings.Index(s, "  build:")
	if buildIdx < 0 {
		t.Fatalf("build job not found")
	}
	jobSection := s[buildIdx:]
	if !strings.Contains(jobSection, "contents: write") {
		t.Errorf("contents: write not found in job section:\n%s", jobSection)
	}
	if !strings.Contains(jobSection, "packages: write") {
		t.Errorf("packages: write not found in job section:\n%s", jobSection)
	}

	// Rule field correct.
	if changes[0].Rule != "GHA020" {
		t.Errorf("want Rule GHA020, got %q", changes[0].Rule)
	}
}

func TestMovePermsToJob_MultipleJobs_Skip(t *testing.T) {
	src := `name: release
on: [push]
permissions:
  contents: write
  packages: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo deploy
`
	out, changes, note := movePermsToJob("w.yml", []byte(src))
	if note != "" {
		t.Errorf("unexpected note: %s", note)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for multi-job workflow, got %d", len(changes))
	}
	if string(out) != src {
		t.Errorf("source should be unchanged for multi-job workflow")
	}
}

func TestMovePermsToJob_JobPermsAlreadyPresent_MergesMissing(t *testing.T) {
	// Job already has permissions block: missing write scopes are appended.
	src := `name: release
on: [push]
permissions:
  contents: write
  packages: write
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
`
	out, changes, note := movePermsToJob("w.yml", []byte(src))
	if note != "" {
		t.Errorf("unexpected note: %s", note)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	s := string(out)

	// packages: write should be injected into the job's permissions.
	buildIdx := strings.Index(s, "  build:")
	if buildIdx < 0 {
		t.Fatalf("build job not found")
	}
	jobSection := s[buildIdx:]
	if !strings.Contains(jobSection, "packages: write") {
		t.Errorf("packages: write not found in job section:\n%s", jobSection)
	}
	// contents: write should NOT override the existing contents: read.
	if strings.Contains(jobSection, "contents: write") {
		t.Errorf("contents: write should not have been injected (job already has contents: read):\n%s", jobSection)
	}
}

func TestMovePermsToJob_WriteAll_ReturnsNote(t *testing.T) {
	// permissions: write-all scalar → no-op with note explaining why.
	src := `name: release
on: [push]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
`
	out, changes, note := movePermsToJob("w.yml", []byte(src))
	if note == "" {
		t.Error("expected a note for permissions: write-all")
	}
	if !strings.Contains(note, "write-all") {
		t.Errorf("note should mention write-all: %s", note)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes, got %d", len(changes))
	}
	if string(out) != src {
		t.Error("source should be unchanged for write-all")
	}
}

func TestMovePermsToJob_NoWriteScopes_NoChange(t *testing.T) {
	src := `name: ci
on: [push]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`
	out, changes, note := movePermsToJob("w.yml", []byte(src))
	if note != "" {
		t.Errorf("unexpected note: %s", note)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for read-only perms, got %d", len(changes))
	}
	if string(out) != src {
		t.Error("source should be unchanged")
	}
}

func TestMovePermsToJob_Idempotent(t *testing.T) {
	// After one application the result should not change on second application.
	src := `name: release
on: [push]
permissions:
  contents: write
  packages: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	out1, changes1, _ := movePermsToJob("w.yml", []byte(src))
	if len(changes1) == 0 {
		t.Fatal("first pass should produce changes")
	}
	_, changes2, _ := movePermsToJob("w.yml", out1)
	if len(changes2) != 0 {
		t.Errorf("second pass should produce no changes (idempotent), got %d", len(changes2))
	}
}

package fix

import (
	"bytes"
	"strings"
	"testing"
)

func TestAddTopPermissions(t *testing.T) {
	src := []byte("name: ci\non: [push]\n# guard comment\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps: []\n")
	out, ok := addTopPermissions(src)
	if !ok {
		t.Fatal("expected change")
	}
	s := string(out)
	if !strings.Contains(s, "permissions:\n  contents: read") {
		t.Errorf("permissions block missing:\n%s", s)
	}
	if !strings.Contains(s, "# guard comment") {
		t.Errorf("comment was eaten:\n%s", s)
	}
	idxOn := strings.Index(s, "on:")
	idxPerm := strings.Index(s, "permissions:")
	idxJobs := strings.Index(s, "jobs:")
	if !(idxOn < idxPerm && idxPerm < idxJobs) {
		t.Errorf("ordering wrong:\n%s", s)
	}
}

func TestAddTopPermissionsIdempotent(t *testing.T) {
	src := []byte("on: [push]\npermissions:\n  contents: read\njobs: {}\n")
	out, ok := addTopPermissions(src)
	if ok || string(out) != string(src) {
		t.Errorf("should not modify when permissions already present")
	}
}

// crlfSrc converts a LF-only source string to CRLF by replacing every \n.
func crlfSrc(s string) []byte {
	return []byte(strings.ReplaceAll(s, "\n", "\r\n"))
}

func TestCRLFPreservedAddTopPermissions(t *testing.T) {
	lf := "name: ci\non: [push]\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps: []\n"
	src := crlfSrc(lf)

	out, ok := addTopPermissions(src)
	if !ok {
		t.Fatal("expected change")
	}
	if !bytes.Contains(out, []byte("\r\n")) {
		t.Error("CRLF line endings were not preserved after addTopPermissions")
	}
	if bytes.Contains(out, []byte("\r\r\n")) {
		t.Error("double carriage return detected — insert was double-converted")
	}
	if !bytes.Contains(out, []byte("permissions:\r\n  contents: read\r\n")) {
		t.Errorf("permissions block not present with CRLF endings:\n%q", out)
	}
}

func TestCRLFPreservedAddJobTimeouts(t *testing.T) {
	lf := "jobs:\n  one:\n    runs-on: ubuntu-latest\n    steps: []\n"
	src := crlfSrc(lf)

	out, changes := addJobTimeouts("w.yml", src, 20)
	if len(changes) != 1 {
		t.Fatalf("want 1 change, got %d", len(changes))
	}
	if !bytes.Contains(out, []byte("\r\n")) {
		t.Error("CRLF line endings were not preserved after addJobTimeouts")
	}
	if bytes.Contains(out, []byte("\r\r\n")) {
		t.Error("double carriage return detected — insert was double-converted")
	}
	if !bytes.Contains(out, []byte("    timeout-minutes: 20\r\n")) {
		t.Errorf("timeout not present with CRLF endings:\n%q", out)
	}
}

func TestAddJobTimeoutsRespectsIndent(t *testing.T) {
	src := []byte("jobs:\n  one:\n    runs-on: ubuntu-latest\n    steps: []\n  two:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps: []\n  three:\n    runs-on: ubuntu-latest\n    steps: []\n")
	out, changes := addJobTimeouts("w.yml", src, 15)
	if len(changes) != 2 {
		t.Fatalf("want 2 changes (one + three), got %d", len(changes))
	}
	s := string(out)
	if strings.Count(s, "timeout-minutes: 15") != 2 {
		t.Errorf("expected exactly 2 inserted timeouts:\n%s", s)
	}
	if !strings.Contains(s, "    timeout-minutes: 15\n") {
		t.Errorf("indent not preserved:\n%s", s)
	}
}

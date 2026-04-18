package fix

import (
	"errors"
	"strings"
	"testing"
)

// fakeResolver is a test stub for DigestResolver.
type fakeResolver struct {
	digests map[string]string
	err     error
}

func (f *fakeResolver) Digest(ref string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if d, ok := f.digests[ref]; ok {
		return d, nil
	}
	return "", errors.New("no digest configured for " + ref)
}

const fakeDigestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const fakeDigestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func newFakeResolver(pairs ...string) *fakeResolver {
	m := make(map[string]string)
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return &fakeResolver{digests: m}
}

func TestDigestPinContainers_TagOnlyImage(t *testing.T) {
	src := `name: test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node:20
    services:
      postgres:
        image: postgres:15
    steps:
      - run: node --version
`
	resolver := newFakeResolver("node:20", fakeDigestA, "postgres:15", fakeDigestB)
	out, changes, warns := digestPinContainers("w.yml", []byte(src), resolver)
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes, got %d: %v", len(changes), changes)
	}
	s := string(out)

	// Pin convention mirrors pin.go: strip tag from ref, keep as comment.
	// node:20 → node@sha256:aaa... # node:20
	if !strings.Contains(s, "node@"+fakeDigestA) {
		t.Errorf("node:20 not pinned in output:\n%s", s)
	}
	if !strings.Contains(s, "# node:20") {
		t.Errorf("original node:20 tag not preserved as comment:\n%s", s)
	}
	if !strings.Contains(s, "postgres@"+fakeDigestB) {
		t.Errorf("postgres:15 not pinned in output:\n%s", s)
	}
	if !strings.Contains(s, "# postgres:15") {
		t.Errorf("original postgres:15 tag not preserved as comment:\n%s", s)
	}

	for _, c := range changes {
		if c.Rule != "GHA023" {
			t.Errorf("want Rule GHA023, got %q", c.Rule)
		}
	}
}

func TestDigestPinContainers_AlreadyPinned_NoOp(t *testing.T) {
	src := `name: test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node:20@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    steps:
      - run: node --version
`
	resolver := newFakeResolver()
	out, changes, warns := digestPinContainers("w.yml", []byte(src), resolver)
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes for already-pinned image, got %d", len(changes))
	}
	if string(out) != src {
		t.Error("source should be unchanged")
	}
}

func TestDigestPinContainers_DockerUnavailable_ReturnsWarning(t *testing.T) {
	src := `name: test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node:20
    steps:
      - run: node --version
`
	resolver := &fakeResolver{err: ErrDockerUnavailable}
	out, changes, warns := digestPinContainers("w.yml", []byte(src), resolver)
	if len(changes) != 0 {
		t.Errorf("expected 0 changes when docker unavailable, got %d", len(changes))
	}
	if len(warns) == 0 {
		t.Error("expected a warning when docker is unavailable")
	}
	if !strings.Contains(warns[0], "docker CLI not available") {
		t.Errorf("warning should mention docker CLI: %v", warns)
	}
	if string(out) != src {
		t.Error("source should be unchanged")
	}
}

func TestDigestPinContainers_PerImageError_SkipsWithWarning(t *testing.T) {
	// Resolver returns an error for the specific image (auth failure etc.)
	// but does not return ErrDockerUnavailable — should skip with per-image warning.
	src := `name: test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: private.registry/img:v1
    services:
      pg:
        image: postgres:15
    steps:
      - run: echo hi
`
	resolver := newFakeResolver("postgres:15", fakeDigestB)
	// private.registry/img:v1 has no entry → error but not ErrDockerUnavailable.
	out, changes, warns := digestPinContainers("w.yml", []byte(src), resolver)

	// postgres:15 should be pinned.
	if len(changes) != 1 {
		t.Fatalf("expected 1 change (postgres only), got %d: %v", len(changes), changes)
	}
	// private.registry/img:v1 should be warned about.
	if len(warns) != 1 {
		t.Errorf("expected 1 warning for skipped private image, got %d: %v", len(warns), warns)
	}
	s := string(out)
	if !strings.Contains(s, "postgres@"+fakeDigestB) {
		t.Errorf("postgres:15 not pinned:\n%s", s)
	}
	if strings.Contains(s, "private.registry/img:v1@sha256:") || strings.Contains(s, "private.registry/img@sha256:") {
		// Should NOT be pinned.
		t.Errorf("private image should not be pinned:\n%s", s)
	}
}

func TestDigestPinContainers_ScalarContainer(t *testing.T) {
	// container: node:20  (bare scalar, no image: key)
	src := `name: test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    container: node:20
    steps:
      - run: node --version
`
	resolver := newFakeResolver("node:20", fakeDigestA)
	out, changes, warns := digestPinContainers("w.yml", []byte(src), resolver)
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	s := string(out)
	if !strings.Contains(s, "node@"+fakeDigestA) {
		t.Errorf("node:20 not pinned in scalar container:\n%s", s)
	}
}

func TestDigestPinContainers_Idempotent(t *testing.T) {
	src := `name: test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    container:
      image: node:20
    steps:
      - run: node --version
`
	resolver := newFakeResolver("node:20", fakeDigestA)
	out1, changes1, _ := digestPinContainers("w.yml", []byte(src), resolver)
	if len(changes1) == 0 {
		t.Fatal("first pass should produce changes")
	}
	_, changes2, _ := digestPinContainers("w.yml", out1, resolver)
	if len(changes2) != 0 {
		t.Errorf("second pass should produce no changes (idempotent), got %d", len(changes2))
	}
}

func TestImageBase(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"node:20", "node"},
		{"ghcr.io/owner/img:v1", "ghcr.io/owner/img"},
		{"postgres", "postgres"},
		{"registry:5000/img:tag", "registry:5000/img"},
		{"ubuntu:22.04", "ubuntu"},
	}
	for _, tc := range cases {
		got := imageBase(tc.in)
		if got != tc.want {
			t.Errorf("imageBase(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestExtractDockerDigest(t *testing.T) {
	// Minimal representation of docker manifest inspect --verbose output.
	input := `[
  {
    "Ref": "docker.io/library/node:20",
    "Descriptor": {
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "Digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "Size": 1234
    }
  }
]`
	got := extractDockerDigest(input)
	want := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

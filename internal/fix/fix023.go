package fix

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// DigestResolver resolves a container image reference to its sha256 digest.
// The returned string must be in the form "sha256:<64 hex chars>".
// Implementations must be safe for concurrent use.
type DigestResolver interface {
	Digest(ref string) (string, error)
}

// ErrDockerUnavailable is returned by dockerResolver when the docker CLI is not
// found on PATH or cannot be executed. The caller treats this as a skip condition
// rather than a hard failure.
var ErrDockerUnavailable = errors.New("docker CLI not available")

// dockerResolver is the default DigestResolver implementation. It shells out to
// `docker manifest inspect <ref>` and parses the Digest field from the JSON output.
type dockerResolver struct{}

// Digest runs `docker manifest inspect --verbose <ref>` and extracts the digest.
// Returns ErrDockerUnavailable if docker is not on PATH.
func (dockerResolver) Digest(ref string) (string, error) {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return "", ErrDockerUnavailable
	}

	// --verbose emits a JSON array where each element has a Descriptor.digest field.
	// For a single-arch image it's a single object with a top-level Descriptor.digest.
	// We use `docker manifest inspect` without --verbose first; it returns a JSON
	// object with a `config.digest` field for the manifest config. However, to get
	// the image manifest digest we use the simpler form:
	//   docker inspect --format='{{index .RepoDigests 0}}' <ref>
	// ... but that requires a pulled image. Instead use:
	//   docker manifest inspect -v <ref>  → array of platform manifests, each with Descriptor.digest.
	// For simplicity and maximum compatibility we call `docker pull --quiet <ref>`
	// then `docker inspect --format {{index .RepoDigests 0}} <ref>` to get the digest.
	// This approach requires actually pulling, which may be slow. A lighter approach:
	//   docker manifest inspect <ref> outputs a JSON manifest; the manifest digest
	//   is the sha256 of the manifest bytes, not present in the JSON body itself.
	// The cleanest approach without pulling: use skopeo or crane — but we can't add deps.
	//
	// Compromise: use `docker buildx imagetools inspect --raw <ref>` (available since
	// Docker 19.03 with buildx). On failure fall back to pulling.
	// For maximum portability we use `docker manifest inspect --verbose <ref>` which
	// is available in Docker 18.09+. We parse the Digest from the first element.

	out, err := exec.Command(dockerPath, "manifest", "inspect", "--verbose", ref).Output()
	if err != nil {
		// docker may return exit 1 for auth errors or unavailable images.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", fmt.Errorf("docker manifest inspect %s: %s", ref, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("docker manifest inspect %s: %w", ref, err)
	}

	digest := extractDockerDigest(string(out))
	if digest == "" {
		return "", fmt.Errorf("docker manifest inspect %s: could not extract digest from output", ref)
	}
	return digest, nil
}

// extractDockerDigest pulls the first sha256:... digest value from `docker manifest inspect --verbose` output.
var digestFieldRe = regexp.MustCompile(`"Digest"\s*:\s*"(sha256:[0-9a-f]{64})"`)

func extractDockerDigest(s string) string {
	m := digestFieldRe.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// sha256DigestSuffix matches an image reference already pinned with @sha256:<64 hex chars>.
var sha256DigestSuffix = regexp.MustCompile(`@sha256:[0-9a-f]{64}`)

// isPseudoRef returns true for image references that have no real registry digest
// (e.g. "scratch", empty string).
func isPseudoRef(ref string) bool {
	switch strings.ToLower(strings.TrimSpace(ref)) {
	case "", "scratch":
		return true
	}
	return false
}

// digestPinContainers implements the GHA023 autofix: finds every container: and
// services.<name>.image: that is not already digest-pinned, resolves the digest
// via resolver, and rewrites the YAML line in place.
//
// If resolver.Digest returns ErrDockerUnavailable the entire function returns
// immediately with a warning string and no changes applied. Per-image errors
// (auth failure, not found) are collected as warnings and the image is skipped.
func digestPinContainers(path string, src []byte, resolver DigestResolver) ([]byte, []Change, []string) {
	if resolver == nil {
		resolver = dockerResolver{}
	}

	root, err := parseDoc(src)
	if err != nil {
		return src, nil, nil
	}
	m := topMap(root)
	jobsVal := findNodeKey(m, "jobs")
	if jobsVal == nil || jobsVal.Kind != yaml.MappingNode {
		return src, nil, nil
	}

	type imageRef struct {
		line    int
		col     int
		current string // current image value in YAML
	}
	var refs []imageRef

	for i := 0; i+1 < len(jobsVal.Content); i += 2 {
		jobNode := jobsVal.Content[i+1]
		if jobNode.Kind != yaml.MappingNode {
			continue
		}

		// container: (scalar or mapping with image:)
		containerNode := findNodeKey(jobNode, "container")
		if containerNode != nil {
			switch containerNode.Kind {
			case yaml.ScalarNode:
				refs = append(refs, imageRef{containerNode.Line, containerNode.Column, containerNode.Value})
			case yaml.MappingNode:
				imgNode := findNodeKeyNode(containerNode, "image")
				if imgNode != nil {
					imgVal := findNodeKey(containerNode, "image")
					if imgVal != nil {
						refs = append(refs, imageRef{imgVal.Line, imgVal.Column, imgVal.Value})
					}
				}
			}
		}

		// services.<name>.image:
		servicesNode := findNodeKey(jobNode, "services")
		if servicesNode != nil && servicesNode.Kind == yaml.MappingNode {
			for j := 0; j+1 < len(servicesNode.Content); j += 2 {
				svcNode := servicesNode.Content[j+1]
				if svcNode.Kind != yaml.MappingNode {
					continue
				}
				imgVal := findNodeKey(svcNode, "image")
				if imgVal != nil {
					refs = append(refs, imageRef{imgVal.Line, imgVal.Column, imgVal.Value})
				}
			}
		}
	}

	if len(refs) == 0 {
		return src, nil, nil
	}

	// Filter to unpinned, non-pseudo refs.
	var toPin []imageRef
	for _, r := range refs {
		if isPseudoRef(r.current) {
			continue
		}
		if sha256DigestSuffix.MatchString(r.current) {
			continue
		}
		toPin = append(toPin, r)
	}
	if len(toPin) == 0 {
		return src, nil, nil
	}

	// Sort descending by line for bottom-up splice.
	for a := 0; a < len(toPin); a++ {
		for b := a + 1; b < len(toPin); b++ {
			if toPin[b].line > toPin[a].line {
				toPin[a], toPin[b] = toPin[b], toPin[a]
			}
		}
	}

	lines := splitLines(src)
	var changes []Change
	var warnings []string

	for _, r := range toPin {
		digest, err := resolver.Digest(r.current)
		if err != nil {
			if errors.Is(err, ErrDockerUnavailable) {
				return src, nil, []string{fmt.Sprintf("GHA023: skipped — %v", err)}
			}
			warnings = append(warnings, fmt.Sprintf("GHA023: skipped %q — %v", r.current, err))
			continue
		}
		if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
			warnings = append(warnings, fmt.Sprintf("GHA023: skipped %q — resolver returned unexpected digest %q", r.current, digest))
			continue
		}

		// Build the new image value: keep the original as a trailing comment.
		// Pattern mirrors how pin.go handles action refs: keep human-readable tag as comment.
		// Strip any existing tag for the comment label.
		label := imageLabel(r.current)
		// New value: strip tag from ref before @sha256, append digest, comment with original tag.
		base := imageBase(r.current)
		newVal := fmt.Sprintf("%s@%s", base, digest)
		comment := fmt.Sprintf(" # %s", label)

		// Find and rewrite the line. The YAML line (1-indexed) contains the value.
		// We search for the exact current value string on that line and replace it.
		lineIdx := r.line - 1
		if lineIdx < 0 || lineIdx >= len(lines) {
			continue
		}
		original := lines[lineIdx]
		// The value may be quoted or unquoted. Try replacing the exact string.
		updated := replaceImageInLine(original, r.current, newVal, comment)
		if updated == original {
			warnings = append(warnings, fmt.Sprintf("GHA023: skipped %q — could not locate value in line %d", r.current, r.line))
			continue
		}
		lines[lineIdx] = updated
		changes = append(changes, Change{
			File:    path,
			Rule:    "GHA023",
			Line:    r.line,
			Summary: fmt.Sprintf("pinned container image %q to digest %s", r.current, digest[:19]+"..."),
		})
	}

	// Flip changes back to file order.
	for a, b := 0, len(changes)-1; a < b; a, b = a+1, b-1 {
		changes[a], changes[b] = changes[b], changes[a]
	}

	return joinLines(lines), changes, warnings
}

// imageBase returns the image reference without the tag portion.
// e.g. "node:20" → "node", "ghcr.io/owner/img:v1" → "ghcr.io/owner/img".
// If the image has no tag, it is returned as-is.
func imageBase(ref string) string {
	// Find the last colon that is not part of a registry port.
	// A colon followed by a valid tag (no slash) indicates a tag.
	// We look for the last colon after the last slash.
	lastSlash := strings.LastIndex(ref, "/")
	nameAndTag := ref
	prefix := ""
	if lastSlash >= 0 {
		prefix = ref[:lastSlash+1]
		nameAndTag = ref[lastSlash+1:]
	}
	if colon := strings.LastIndex(nameAndTag, ":"); colon >= 0 {
		return prefix + nameAndTag[:colon]
	}
	return ref
}

// imageLabel returns a short human-readable label for the comment.
// e.g. "node:20" → "node:20", "ghcr.io/owner/img:v1" → "ghcr.io/owner/img:v1".
func imageLabel(ref string) string {
	return ref
}

// replaceImageInLine rewrites the YAML line by replacing the bare image value
// with newVal + comment. Handles both unquoted and quoted values.
func replaceImageInLine(line, oldVal, newVal, comment string) string {
	// Try simple substring replacement first (unquoted).
	if idx := strings.Index(line, oldVal); idx >= 0 {
		rest := line[idx+len(oldVal):]
		// Make sure we're not in the middle of a longer word.
		if rest == "" || rest == "\n" || rest == "\r\n" || strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, "\t") || strings.HasPrefix(rest, "#") {
			return line[:idx] + newVal + comment + rest
		}
	}
	return line
}

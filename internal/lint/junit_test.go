package lint

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
)

// xmlSuites mirrors the JUnit structure for unmarshalling test output.
type xmlSuites struct {
	XMLName xml.Name   `xml:"testsuites"`
	Suites  []xmlSuite `xml:"testsuite"`
}

type xmlSuite struct {
	Name      string        `xml:"name,attr"`
	Tests     int           `xml:"tests,attr"`
	Failures  int           `xml:"failures,attr"`
	Errors    int           `xml:"errors,attr"`
	Testcases []xmlTestcase `xml:"testcase"`
}

type xmlTestcase struct {
	Classname string      `xml:"classname,attr"`
	Name      string      `xml:"name,attr"`
	Failure   *xmlFailure `xml:"failure"`
}

type xmlFailure struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

var junitFixture = []Issue{
	{
		File:     ".github/workflows/ci.yml",
		Line:     10,
		Col:      5,
		Kind:     "GHA001",
		Severity: SevWarning,
		Message:  "unpinned action uses a mutable tag",
		Source:   "ghactor",
	},
	{
		File:     ".github/workflows/ci.yml",
		Line:     22,
		Col:      1,
		Kind:     "GHA004",
		Severity: SevError,
		Message:  "expression injection via ${{ github.event.issue.title }}",
		Source:   "ghactor",
	},
	{
		File:     ".github/workflows/deploy.yml",
		Line:     5,
		Col:      3,
		Kind:     "GHA007",
		Severity: SevInfo,
		Message:  "consider restricting permissions",
		Source:   "ghactor",
	},
}

func TestWriteJUnit_ValidXML(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, junitFixture, "test"); err != nil {
		t.Fatalf("WriteJUnit returned error: %v", err)
	}

	out := buf.Bytes()
	if !bytes.HasPrefix(out, []byte("<?xml")) {
		t.Error("output does not start with XML declaration")
	}

	var doc xmlSuites
	if err := xml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("xml.Unmarshal failed: %v\noutput:\n%s", err, out)
	}

	if len(doc.Suites) != 1 {
		t.Fatalf("suites count = %d, want 1", len(doc.Suites))
	}
	suite := doc.Suites[0]

	if suite.Name != "ghactor" {
		t.Errorf("suite name = %q, want %q", suite.Name, "ghactor")
	}
	if suite.Tests != 3 {
		t.Errorf("tests = %d, want 3", suite.Tests)
	}
	if suite.Failures != 2 {
		t.Errorf("failures = %d, want 2 (error + warning)", suite.Failures)
	}
	if suite.Errors != 0 {
		t.Errorf("errors = %d, want 0", suite.Errors)
	}
	if len(suite.Testcases) != 3 {
		t.Fatalf("testcases count = %d, want 3", len(suite.Testcases))
	}
}

func TestWriteJUnit_FailureElements(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, junitFixture, "test"); err != nil {
		t.Fatalf("WriteJUnit error: %v", err)
	}

	var doc xmlSuites
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("xml.Unmarshal: %v", err)
	}
	cases := doc.Suites[0].Testcases

	// First testcase (warning) must have a <failure>.
	tc0 := cases[0]
	if tc0.Failure == nil {
		t.Fatal("testcase[0] (warning): expected <failure>, got none")
	}
	if tc0.Failure.Type != "GHA001" {
		t.Errorf("failure type = %q, want GHA001", tc0.Failure.Type)
	}
	if tc0.Classname != ".github/workflows/ci.yml" {
		t.Errorf("classname = %q, want .github/workflows/ci.yml", tc0.Classname)
	}
	if !strings.Contains(tc0.Name, "GHA001") {
		t.Errorf("name = %q, want it to contain GHA001", tc0.Name)
	}
	if !strings.Contains(tc0.Name, "line:10") {
		t.Errorf("name = %q, want it to contain line:10", tc0.Name)
	}

	// Second testcase (error) must have a <failure>.
	tc1 := cases[1]
	if tc1.Failure == nil {
		t.Fatal("testcase[1] (error): expected <failure>, got none")
	}
	if tc1.Failure.Type != "GHA004" {
		t.Errorf("failure type = %q, want GHA004", tc1.Failure.Type)
	}

	// Third testcase (info) must NOT have a <failure>.
	tc2 := cases[2]
	if tc2.Failure != nil {
		t.Errorf("testcase[2] (info): expected no <failure>, got one with type=%q", tc2.Failure.Type)
	}
}

func TestWriteJUnit_CDataPresent(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, junitFixture, "test"); err != nil {
		t.Fatalf("WriteJUnit error: %v", err)
	}
	raw := buf.String()
	if !strings.Contains(raw, "<![CDATA[") {
		t.Error("expected CDATA section in output")
	}
}

func TestWriteJUnit_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, nil, "test"); err != nil {
		t.Fatalf("WriteJUnit(nil) error: %v", err)
	}
	var doc xmlSuites
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("xml.Unmarshal: %v", err)
	}
	if doc.Suites[0].Tests != 0 {
		t.Errorf("tests = %d, want 0", doc.Suites[0].Tests)
	}
	if doc.Suites[0].Failures != 0 {
		t.Errorf("failures = %d, want 0", doc.Suites[0].Failures)
	}
}

func TestWriteJUnit_XMLEscaping(t *testing.T) {
	issues := []Issue{
		{
			File:     "a.yml",
			Line:     1,
			Col:      1,
			Kind:     "GHA004",
			Severity: SevError,
			Message:  `injection via <script> & "quotes" 'apos'`,
			Source:   "ghactor",
		},
	}
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, issues, "test"); err != nil {
		t.Fatalf("WriteJUnit error: %v", err)
	}
	// Must parse cleanly — invalid XML would break Unmarshal.
	var doc xmlSuites
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("xml.Unmarshal after escaping: %v\noutput:\n%s", err, buf.String())
	}
}

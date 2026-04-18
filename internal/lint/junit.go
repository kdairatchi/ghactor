package lint

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// junitTestsuites is the root element of a JUnit XML report.
type junitTestsuites struct {
	XMLName    xml.Name     `xml:"testsuites"`
	Testsuites []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Errors    int             `xml:"errors,attr"`
	Time      string          `xml:"time,attr"`
	Testcases []junitTestcase `xml:"testcase"`
}

type junitTestcase struct {
	Classname string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
}

// junitFailure uses ",innerxml" for the body so the encoder emits the
// CDATA section verbatim instead of escaping the delimiters.
type junitFailure struct {
	Type    string `xml:"type,attr"`
	Message string `xml:"message,attr"`
	// Body is emitted as pre-formed XML content (CDATA section).
	Body string `xml:",innerxml"`
}

// WriteJUnit writes a JUnit XML report to w for the given issues.
// Errors and Warnings produce a <failure> element; Info produces a passing testcase.
// The version string is available for future use in the suite metadata.
func WriteJUnit(w io.Writer, issues []Issue, _ string) error {
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return fmt.Errorf("junit: write header: %w", err)
	}

	failures := 0
	for _, iss := range issues {
		if iss.Severity == SevError || iss.Severity == SevWarning {
			failures++
		}
	}

	cases := make([]junitTestcase, 0, len(issues))
	for _, iss := range issues {
		tc := junitTestcase{
			Classname: iss.File,
			Name:      fmt.Sprintf("%s line:%d:%d", iss.Kind, iss.Line, iss.Col),
			Time:      "0",
		}
		if iss.Severity == SevError || iss.Severity == SevWarning {
			tc.Failure = &junitFailure{
				Type:    iss.Kind,
				Message: xmlAttrEscape(iss.Message),
				Body:    "<![CDATA[" + iss.Message + "]]>",
			}
		}
		cases = append(cases, tc)
	}

	suite := junitSuite{
		Name:      "ghactor",
		Tests:     len(issues),
		Failures:  failures,
		Errors:    0,
		Time:      "0",
		Testcases: cases,
	}

	doc := junitTestsuites{Testsuites: []junitSuite{suite}}

	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("junit: encode: %w", err)
	}
	return enc.Flush()
}

// xmlAttrEscape escapes characters that are invalid in XML attribute values.
func xmlAttrEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

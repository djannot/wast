package scanner

import (
	"io"

	"github.com/djannot/wast/pkg/httputil"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// maxResponseBodySize is the maximum number of bytes read from an HTTP response
// body. Defined here as an alias of the shared constant for convenient use
// within the scanner package.
const maxResponseBodySize = httputil.MaxResponseBodySize

// readResponseBody reads at most maxResponseBodySize bytes from r.
// It replaces bare io.ReadAll(resp.Body) calls to prevent memory exhaustion
// when scanning potentially malicious targets.
func readResponseBody(r io.Reader) ([]byte, error) {
	return httputil.ReadResponseBody(r)
}

// titleCase converts s to title case using Unicode-aware rules.
// It replaces the deprecated strings.Title function.
func titleCase(s string) string {
	return cases.Title(language.English).String(s)
}

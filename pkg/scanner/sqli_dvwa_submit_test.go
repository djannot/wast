package scanner

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestSQLiScanner_DVWA_MissingSubmitParameter tests the scenario where
// DVWA requires the Submit parameter to process the query.
// If the Submit parameter is missing, DVWA shows the form but no results.
func TestSQLiScanner_DVWA_MissingSubmitParameter(t *testing.T) {
	// When Submit parameter is missing, DVWA shows form but no query results
	noSubmitHTML := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA) v1.10</title>
</head>
<body>
<div id="wrapper">
<div id="main_body">
<h1>SQL Injection</h1>
<div class="body_padded">
<form action="#" method="GET">
User ID:
<input type="text" name="id" value="">
<input type="submit" name="Submit" value="Submit">
</form>
</div>
</div>
</div>
</body>
</html>`

	// With Submit parameter, normal result for id=1
	withSubmitHTML := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA) v1.10</title>
</head>
<body>
<div id="wrapper">
<div id="main_body">
<h1>SQL Injection</h1>
<div class="body_padded">
<form action="#" method="GET">
User ID:
<input type="text" name="id" value="1">
<input type="submit" name="Submit" value="Submit">
</form>
<br />
<table>
<tr><td>ID</td><td>First name</td><td>Surname</td></tr>
<tr><td>1</td><td>admin</td><td>admin</td></tr>
</table>
</div>
</div>
</div>
</body>
</html>`

	// True payload returns all users (WITH Submit parameter)
	truePayloadHTML := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA) v1.10</title>
</head>
<body>
<div id="wrapper">
<div id="main_body">
<h1>SQL Injection</h1>
<div class="body_padded">
<form action="#" method="GET">
User ID:
<input type="text" name="id" value="1' OR '1'='1">
<input type="submit" name="Submit" value="Submit">
</form>
<br />
<table>
<tr><td>ID</td><td>First name</td><td>Surname</td></tr>
<tr><td>1</td><td>admin</td><td>admin</td></tr>
<tr><td>2</td><td>Gordon</td><td>Brown</td></tr>
<tr><td>3</td><td>Hack</td><td>Me</td></tr>
<tr><td>4</td><td>Pablo</td><td>Picasso</td></tr>
<tr><td>5</td><td>Bob</td></tr></tr>
</table>
</div>
</div>
</div>
</body>
</html>`

	// False payload returns no users (WITH Submit parameter)
	falsePayloadHTML := `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Vulnerability: SQL Injection :: Damn Vulnerable Web Application (DVWA) v1.10</title>
</head>
<body>
<div id="wrapper">
<div id="main_body">
<h1>SQL Injection</h1>
<div class="body_padded">
<form action="#" method="GET">
User ID:
<input type="text" name="id" value="1' OR '1'='2">
<input type="submit" name="Submit" value="Submit">
</form>
<br />
<table>
<tr><td>ID</td><td>First name</td><td>Surname</td></tr>
</table>
</div>
</div>
</div>
</body>
</html>`

	// Mock a more realistic scenario:
	// - When accessing with just id=1 (no Submit), show form only
	// - When accessing with both id=1&Submit=Submit, show results
	customMock := &dvwaMockClient{
		requests:         make([]*http.Request, 0),
		noSubmitHTML:     noSubmitHTML,
		withSubmitHTML:   withSubmitHTML,
		truePayloadHTML:  truePayloadHTML,
		falsePayloadHTML: falsePayloadHTML,
	}

	scanner := NewSQLiScanner(WithSQLiHTTPClient(customMock))

	ctx := context.Background()
	// Scanner starts with just id=1 (discovered URL)
	result := scanner.Scan(ctx, "http://dvwa.local/vulnerabilities/sqli/?id=1")

	if result == nil {
		t.Fatal("Scan returned nil result")
	}

	t.Logf("Total tests performed: %d", result.Summary.TotalTests)
	t.Logf("Vulnerabilities found: %d", result.Summary.VulnerabilitiesFound)

	if len(result.Findings) > 0 {
		for i, finding := range result.Findings {
			t.Logf("Finding %d: param=%s, payload=%s, confidence=%s",
				i+1, finding.Parameter, finding.Payload, finding.Confidence)
		}
	}

	// This tests the actual problem: when the scanner doesn't include Submit parameter,
	// DVWA doesn't execute the query, so all responses look similar (just the form).
	// This causes the differential analysis to fail.
	if result.Summary.VulnerabilitiesFound == 0 {
		t.Log("No vulnerabilities detected - this reproduces issue #188")
		t.Log("Root cause: DVWA requires Submit parameter to execute queries")
		t.Log("Without Submit, all responses are identical (just the form), so differential analysis fails")
	} else {
		t.Logf("Detected %d vulnerabilities", result.Summary.VulnerabilitiesFound)
	}
}

// dvwaMockClient simulates DVWA's behavior where Submit parameter is required
type dvwaMockClient struct {
	requests         []*http.Request
	noSubmitHTML     string
	withSubmitHTML   string
	truePayloadHTML  string
	falsePayloadHTML string
}

func (m *dvwaMockClient) Do(req *http.Request) (*http.Response, error) {
	m.requests = append(m.requests, req)

	query := req.URL.Query()
	idValue := query.Get("id")
	hasSubmit := query.Get("Submit") != ""

	var bodyStr string

	// If no Submit parameter, just show the form
	if !hasSubmit {
		bodyStr = m.noSubmitHTML
	} else {
		// With Submit parameter, check for SQL injection payloads
		if strings.Contains(idValue, "1'='1") || strings.Contains(idValue, "2'='2") {
			bodyStr = m.truePayloadHTML
		} else if strings.Contains(idValue, "1'='2") {
			bodyStr = m.falsePayloadHTML
		} else if idValue == "1" || idValue == "" {
			bodyStr = m.withSubmitHTML
		} else {
			// Default case
			bodyStr = m.withSubmitHTML
		}
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(bodyStr)),
		Header:     make(http.Header),
	}, nil
}

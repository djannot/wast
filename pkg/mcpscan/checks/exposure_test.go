package checks

import (
	"context"
	"strings"
	"testing"
)

func TestExposureChecker_AWSKey(t *testing.T) {
	tools := []ToolInfo{
		{Name: "list_config", Description: "returns config"},
	}
	caller := newMockCaller()
	// AWS access key pattern: AKIA + 16 alphanumeric chars
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"Your key is AKIAIOSFODNN7EXAMPLE and secret is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure {
			found = true
			if f.Severity != SeverityCritical {
				t.Errorf("expected Critical severity for AWS key, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected exposure finding for AWS access key")
	}
}

func TestExposureChecker_NoSensitiveData(t *testing.T) {
	tools := []ToolInfo{
		{Name: "get_time", Description: "returns current time"},
	}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"2024-01-01T00:00:00Z"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)
	if len(findings) != 0 {
		t.Errorf("expected no findings for benign response, got %d", len(findings))
	}
}

func TestExposureChecker_PrivateKey(t *testing.T) {
	tools := []ToolInfo{
		{Name: "get_cert", Description: "returns certificate"},
	}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical finding for private key in response")
	}
}

func TestExposureChecker_ErrorResponse(t *testing.T) {
	tools := []ToolInfo{
		{Name: "risky_tool", Description: "can leak"},
	}
	caller := newMockCaller()
	// Error containing environment variable dump
	caller.errors["risky_tool:test"] = nil
	caller.defaultResp = nil
	// Override default to return an error with env vars
	errCaller := &errorCaller{msg: "HOME=/root PATH=/usr/bin USER=root SHELL=/bin/bash PWD=/root"}

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, errCaller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure {
			found = true
		}
	}
	if !found {
		t.Error("expected exposure finding from error response containing env vars")
	}
}

func TestExposureChecker_PostgreSQLConnectionString(t *testing.T) {
	tools := []ToolInfo{{Name: "get_config", Description: "returns config"}}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"db url: postgres://admin:s3cr3t@db.internal:5432/mydb"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical finding for PostgreSQL connection string")
	}
}

func TestExposureChecker_PostgreSQLConnectionString_NoMatch(t *testing.T) {
	tools := []ToolInfo{{Name: "get_config", Description: "returns config"}}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"connected to database successfully"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)
	for _, f := range findings {
		if f.Title == "Sensitive data exposure: PostgreSQL connection string" {
			t.Error("unexpected PostgreSQL finding for benign response")
		}
	}
}

func TestExposureChecker_MySQLConnectionString(t *testing.T) {
	tools := []ToolInfo{{Name: "get_dsn", Description: "returns DSN"}}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"mysql://user:pass@localhost:3306/shop"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical finding for MySQL connection string")
	}
}

func TestExposureChecker_MongoDBConnectionString(t *testing.T) {
	tools := []ToolInfo{{Name: "get_mongo", Description: "returns mongo URI"}}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"uri=mongodb+srv://admin:secret@cluster0.example.mongodb.net/prod"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical finding for MongoDB connection string")
	}
}

func TestExposureChecker_RedisConnectionString(t *testing.T) {
	tools := []ToolInfo{{Name: "get_cache", Description: "returns cache config"}}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"cache: rediss://:password@redis.internal:6380/0"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical finding for Redis connection string")
	}
}

func TestExposureChecker_JDBCConnectionString(t *testing.T) {
	tools := []ToolInfo{{Name: "get_jdbc", Description: "returns JDBC string"}}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"jdbc:postgresql://db.corp.internal:5432/production?user=svc&password=topsecret"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical finding for JDBC connection string")
	}
}

func TestExposureChecker_DatabaseURLAssignment(t *testing.T) {
	tools := []ToolInfo{{Name: "get_env", Description: "returns env"}}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"DATABASE_URL=postgres://user:pass@host/db"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)

	found := false
	for _, f := range findings {
		if f.Category == CategoryExposure && f.Severity == SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Error("expected critical finding for DATABASE_URL assignment")
	}
}

func TestExposureChecker_DatabaseURLAssignment_NoMatch(t *testing.T) {
	tools := []ToolInfo{{Name: "get_env", Description: "returns env"}}
	caller := newMockCaller()
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"DATABASE_URL=short"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), tools, caller)
	for _, f := range findings {
		if f.Title == "Sensitive data exposure: DATABASE_URL assignment" {
			t.Error("unexpected DATABASE_URL finding for short value")
		}
	}
}

// errorCaller always returns an error with the given message.
type errorCaller struct{ msg string }

func (e *errorCaller) CallTool(_ context.Context, _ string, _ map[string]interface{}) ([]byte, error) {
	return nil, &mockError{e.msg}
}

type mockError struct{ msg string }

func (m *mockError) Error() string { return m.msg }

// ---------------------------------------------------------------------------
// benignArgStrategy tests
// ---------------------------------------------------------------------------

// TestBenignArgStrategy_ListTool verifies that a "list"-named tool with no params
// still gets at least one (empty) arg set and that no more than 3 sets are returned.
func TestBenignArgStrategy_ListTool(t *testing.T) {
	tool := ToolInfo{
		Name:        "list_users",
		Description: "Returns a list of all users",
		Parameters:  []ParamInfo{},
	}
	sets := benignArgStrategy(tool)
	if len(sets) == 0 {
		t.Fatal("expected at least one arg set for list tool")
	}
	if len(sets) > 3 {
		t.Errorf("expected at most 3 arg sets, got %d", len(sets))
	}
	// The first set should be empty (no required params).
	if len(sets[0]) != 0 {
		t.Errorf("expected empty first arg set for parameterless tool, got %v", sets[0])
	}
}

// TestBenignArgStrategy_SearchTool verifies that a search tool with a "query" param
// generates a wildcard "*" variant in addition to the default "test" set.
func TestBenignArgStrategy_SearchTool(t *testing.T) {
	tool := ToolInfo{
		Name:        "search_records",
		Description: "Search for records",
		Parameters: []ParamInfo{
			{Name: "query", Type: "string", Required: true},
		},
	}
	sets := benignArgStrategy(tool)
	if len(sets) < 2 {
		t.Fatalf("expected at least 2 arg sets for search tool, got %d", len(sets))
	}
	if len(sets) > 3 {
		t.Errorf("expected at most 3 arg sets, got %d", len(sets))
	}
	// Set 1: semantic default for "query" should be "test".
	if sets[0]["query"] != "test" {
		t.Errorf("expected sets[0][query]=\"test\", got %v", sets[0]["query"])
	}
	// Set 2: wildcard variant.
	if sets[1]["query"] != "*" {
		t.Errorf("expected sets[1][query]=\"*\", got %v", sets[1]["query"])
	}
}

// TestBenignArgStrategy_ConfigTool verifies that a config tool with an "action" param
// generates a "list" default and a "get" variant.
func TestBenignArgStrategy_ConfigTool(t *testing.T) {
	tool := ToolInfo{
		Name:        "get_config",
		Description: "Retrieve configuration settings",
		Parameters: []ParamInfo{
			{Name: "action", Type: "string", Required: true},
		},
	}
	sets := benignArgStrategy(tool)
	if len(sets) == 0 {
		t.Fatal("expected at least one arg set for config tool")
	}
	if len(sets) > 3 {
		t.Errorf("expected at most 3 arg sets, got %d", len(sets))
	}
	// Semantic default for "action" should be "list".
	if sets[0]["action"] != "list" {
		t.Errorf("expected sets[0][action]=\"list\", got %v", sets[0]["action"])
	}
	// Second set should try "get".
	found := false
	for _, s := range sets[1:] {
		if s["action"] == "get" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a \"get\" variant for action param, sets=%v", sets)
	}
}

// TestBenignArgStrategy_StatusTool verifies that a status tool with a "status" string param
// gets the "active" semantic default.
func TestBenignArgStrategy_StatusTool(t *testing.T) {
	tool := ToolInfo{
		Name:        "check_status",
		Description: "Check the current status",
		Parameters: []ParamInfo{
			{Name: "status", Type: "string", Required: true},
		},
	}
	sets := benignArgStrategy(tool)
	if len(sets) == 0 {
		t.Fatal("expected at least one arg set for status tool")
	}
	if sets[0]["status"] != "active" {
		t.Errorf("expected sets[0][status]=\"active\", got %v", sets[0]["status"])
	}
}

// TestBenignArgStrategy_GenericTool verifies that a tool with generic string params
// gets the "test" fallback value.
func TestBenignArgStrategy_GenericTool(t *testing.T) {
	tool := ToolInfo{
		Name:        "do_something",
		Description: "Performs an unspecified action",
		Parameters: []ParamInfo{
			{Name: "input", Type: "string", Required: true},
			{Name: "count", Type: "integer", Required: true},
		},
	}
	sets := benignArgStrategy(tool)
	if len(sets) == 0 {
		t.Fatal("expected at least one arg set for generic tool")
	}
	if sets[0]["input"] != "test" {
		t.Errorf("expected sets[0][input]=\"test\", got %v", sets[0]["input"])
	}
	if sets[0]["count"] != 1 {
		t.Errorf("expected sets[0][count]=1, got %v", sets[0]["count"])
	}
}

// TestBenignArgStrategy_EnumParam verifies that enum hints in descriptions are honoured.
func TestBenignArgStrategy_EnumParam(t *testing.T) {
	tool := ToolInfo{
		Name:        "filter_records",
		Description: "Filter records by type",
		Parameters: []ParamInfo{
			{Name: "type", Type: "string", Required: true, Description: "one of: active, archived, deleted"},
		},
	}
	sets := benignArgStrategy(tool)
	if len(sets) == 0 {
		t.Fatal("expected at least one arg set")
	}
	if sets[0]["type"] != "active" {
		t.Errorf("expected enum-extracted value \"active\", got %v", sets[0]["type"])
	}
}

// TestBenignArgStrategy_MaxThreeSets verifies that at most 3 arg sets are returned
// even for tools that qualify for all heuristics.
func TestBenignArgStrategy_MaxThreeSets(t *testing.T) {
	tool := ToolInfo{
		Name:        "search_and_act",
		Description: "Search for records and perform actions",
		Parameters: []ParamInfo{
			{Name: "query", Type: "string", Required: true},
			{Name: "action", Type: "string", Required: true},
		},
	}
	sets := benignArgStrategy(tool)
	if len(sets) > 3 {
		t.Errorf("expected at most 3 arg sets, got %d", len(sets))
	}
}

// TestExposureChecker_MultipleArgSets_Deduplication verifies that findings from multiple
// arg-set calls are deduplicated — the same pattern match should appear at most once.
func TestExposureChecker_MultipleArgSets_Deduplication(t *testing.T) {
	// A search tool whose "query" param triggers the wildcard variant.
	// Both calls return the same AWS key; we expect exactly 1 finding, not 2.
	tool := ToolInfo{
		Name:        "search_data",
		Description: "Search for data",
		Parameters: []ParamInfo{
			{Name: "query", Type: "string", Required: true},
		},
	}
	caller := newMockCaller()
	// Always return an AWS key regardless of argument.
	caller.defaultResp = []byte(`{"content":[{"type":"text","text":"key: AKIAIOSFODNN7EXAMPLE"}]}`)

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), []ToolInfo{tool}, caller)

	count := 0
	for _, f := range findings {
		if f.Category == CategoryExposure && f.Tool == "search_data" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 deduplicated finding, got %d", count)
	}
}

// TestExposureChecker_MultipleArgSets_UnionFindings verifies that findings from different
// arg-set calls are merged — different patterns from different calls both appear.
func TestExposureChecker_MultipleArgSets_UnionFindings(t *testing.T) {
	// A tool with both query and action params so benignArgStrategy produces ≥2 sets.
	// First call (query="test") returns an AWS key; second call (query="*") returns a private key.
	tool := ToolInfo{
		Name:        "search_secure",
		Description: "Secure search",
		Parameters: []ParamInfo{
			{Name: "query", Type: "string", Required: true},
		},
	}

	// recordingCaller records calls and returns different responses per query value.
	type argRecord struct {
		queryVal interface{}
		resp     []byte
	}

	awsResp := []byte(`{"content":[{"type":"text","text":"AKIAIOSFODNN7EXAMPLE"}]}`)
	pkResp := []byte(`{"content":[{"type":"text","text":"-----BEGIN RSA PRIVATE KEY-----\nMIIE"}]}`)

	callNum := 0
	rc := &roundRobinCaller{
		responses: [][]byte{awsResp, pkResp},
		current:   &callNum,
	}

	checker := NewExposureChecker()
	findings := checker.Check(context.Background(), []ToolInfo{tool}, rc)

	hasAWS := false
	hasPK := false
	for _, f := range findings {
		if f.Category == CategoryExposure {
			if strings.Contains(f.Title, "AWS") {
				hasAWS = true
			}
			if strings.Contains(f.Title, "Private key") {
				hasPK = true
			}
		}
	}
	if !hasAWS {
		t.Error("expected AWS key finding from first arg set")
	}
	if !hasPK {
		t.Error("expected private key finding from second arg set")
	}
}

// roundRobinCaller returns responses in round-robin order.
type roundRobinCaller struct {
	responses [][]byte
	current   *int
}

func (r *roundRobinCaller) CallTool(_ context.Context, _ string, _ map[string]interface{}) ([]byte, error) {
	idx := *r.current % len(r.responses)
	*r.current++
	return r.responses[idx], nil
}

package checks

import (
	"context"
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

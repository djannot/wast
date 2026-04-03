package mcpscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// extractParameters tests
// ---------------------------------------------------------------------------

func TestExtractParameters(t *testing.T) {
	tests := []struct {
		name       string
		schema     map[string]interface{}
		wantNil    bool
		wantLen    int
		assertions func(t *testing.T, params []MCPToolParameterInfo)
	}{
		{
			name:    "nil schema returns nil",
			schema:  nil,
			wantNil: true,
		},
		{
			name:    "empty schema (no properties) returns nil",
			schema:  map[string]interface{}{},
			wantNil: true,
		},
		{
			name: "schema with empty properties returns nil",
			schema: map[string]interface{}{
				"properties": map[string]interface{}{},
			},
			wantNil: false,
			wantLen: 0,
		},
		{
			name: "required and optional params",
			schema: map[string]interface{}{
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "search query",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "max results",
					},
				},
				"required": []interface{}{"query"},
			},
			wantLen: 2,
			assertions: func(t *testing.T, params []MCPToolParameterInfo) {
				byName := make(map[string]MCPToolParameterInfo, len(params))
				for _, p := range params {
					byName[p.Name] = p
				}
				q, ok := byName["query"]
				if !ok {
					t.Fatal("expected 'query' param")
				}
				if !q.Required {
					t.Error("expected 'query' to be required")
				}
				if q.Type != "string" {
					t.Errorf("expected type 'string', got %q", q.Type)
				}
				if q.Description != "search query" {
					t.Errorf("unexpected description: %q", q.Description)
				}

				l, ok := byName["limit"]
				if !ok {
					t.Fatal("expected 'limit' param")
				}
				if l.Required {
					t.Error("expected 'limit' to be optional")
				}
			},
		},
		{
			name: "param with enum sets HasEnum",
			schema: map[string]interface{}{
				"properties": map[string]interface{}{
					"format": map[string]interface{}{
						"type": "string",
						"enum": []interface{}{"json", "xml", "csv"},
					},
				},
			},
			wantLen: 1,
			assertions: func(t *testing.T, params []MCPToolParameterInfo) {
				if !params[0].HasEnum {
					t.Error("expected HasEnum to be true")
				}
			},
		},
		{
			name: "param without type field leaves Type empty",
			schema: map[string]interface{}{
				"properties": map[string]interface{}{
					"data": map[string]interface{}{
						"description": "arbitrary data",
					},
				},
			},
			wantLen: 1,
			assertions: func(t *testing.T, params []MCPToolParameterInfo) {
				if params[0].Type != "" {
					t.Errorf("expected empty type, got %q", params[0].Type)
				}
				if params[0].HasEnum {
					t.Error("expected HasEnum to be false")
				}
			},
		},
		{
			name: "non-map property value is handled gracefully",
			schema: map[string]interface{}{
				"properties": map[string]interface{}{
					"bad": "not a map",
				},
			},
			wantLen: 1,
			assertions: func(t *testing.T, params []MCPToolParameterInfo) {
				if params[0].Name != "bad" {
					t.Errorf("expected name 'bad', got %q", params[0].Name)
				}
				if params[0].Type != "" {
					t.Errorf("expected empty type for bad prop, got %q", params[0].Type)
				}
			},
		},
		{
			name: "multiple required fields",
			schema: map[string]interface{}{
				"properties": map[string]interface{}{
					"a": map[string]interface{}{"type": "string"},
					"b": map[string]interface{}{"type": "number"},
					"c": map[string]interface{}{"type": "boolean"},
				},
				"required": []interface{}{"a", "b"},
			},
			wantLen: 3,
			assertions: func(t *testing.T, params []MCPToolParameterInfo) {
				byName := make(map[string]MCPToolParameterInfo)
				for _, p := range params {
					byName[p.Name] = p
				}
				if !byName["a"].Required {
					t.Error("expected 'a' required")
				}
				if !byName["b"].Required {
					t.Error("expected 'b' required")
				}
				if byName["c"].Required {
					t.Error("expected 'c' optional")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractParameters(tc.schema)
			if tc.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if tc.wantLen >= 0 && len(result) != tc.wantLen {
				t.Errorf("expected %d params, got %d", tc.wantLen, len(result))
			}
			if tc.assertions != nil {
				tc.assertions(t, result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractJSONFromSSE tests
// ---------------------------------------------------------------------------

func TestExtractJSONFromSSE(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantJSON string // empty string means expect nil
	}{
		{
			name:     "single data line returns its value",
			input:    "data: {\"id\":1}\n",
			wantJSON: `{"id":1}`,
		},
		{
			name:     "multiple data lines returns last",
			input:    "data: {\"id\":1}\ndata: {\"id\":2}\ndata: {\"id\":3}\n",
			wantJSON: `{"id":3}`,
		},
		{
			name:     "empty body returns nil",
			input:    "",
			wantJSON: "",
		},
		{
			name:     "lines without data prefix are ignored",
			input:    "event: message\nid: 42\ndata: {\"ok\":true}\n",
			wantJSON: `{"ok":true}`,
		},
		{
			name:     "blank data lines are skipped",
			input:    "data: \ndata: {\"result\":\"yes\"}\n",
			wantJSON: `{"result":"yes"}`,
		},
		{
			name:     "only non-data lines returns nil",
			input:    "event: ping\nid: 1\n",
			wantJSON: "",
		},
		{
			name:     "data with colon prefix whitespace trimmed",
			input:    "data:   {\"trimmed\":true}\n",
			wantJSON: `{"trimmed":true}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractJSONFromSSE([]byte(tc.input))
			if tc.wantJSON == "" {
				if result != nil {
					t.Errorf("expected nil, got %q", result)
				}
				return
			}
			if result == nil {
				t.Fatalf("expected %q, got nil", tc.wantJSON)
			}
			if string(result) != tc.wantJSON {
				t.Errorf("expected %q, got %q", tc.wantJSON, string(result))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseSSEResponse tests
// ---------------------------------------------------------------------------

func buildSSEStream(lines ...string) *strings.Reader {
	return strings.NewReader(strings.Join(lines, "\n"))
}

func mustMarshal(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestParseSSEResponse(t *testing.T) {
	matchID := uint64(42)

	tests := []struct {
		name      string
		stream    string
		id        interface{}
		wantErr   bool
		errSubstr string
		wantRaw   string
	}{
		{
			name: "matching ID returns result",
			stream: fmt.Sprintf("data: %s\n",
				mustMarshal(jsonrpcResponse{
					JSONRPC: "2.0",
					ID:      float64(matchID),
					Result:  json.RawMessage(`{"value":"hello"}`),
				})),
			id:      matchID,
			wantRaw: `{"value":"hello"}`,
		},
		{
			name: "mismatched ID skips and ends with error",
			stream: fmt.Sprintf("data: %s\n",
				mustMarshal(jsonrpcResponse{
					JSONRPC: "2.0",
					ID:      float64(99),
					Result:  json.RawMessage(`{}`),
				})),
			id:        matchID,
			wantErr:   true,
			errSubstr: "ended without matching",
		},
		{
			name:      "[DONE] sentinel skips without result",
			stream:    "data: [DONE]\n",
			id:        matchID,
			wantErr:   true,
			errSubstr: "ended without matching",
		},
		{
			name:      "empty stream returns error",
			stream:    "",
			id:        matchID,
			wantErr:   true,
			errSubstr: "ended without matching",
		},
		{
			name: "JSON-RPC error response propagates error",
			stream: fmt.Sprintf("data: %s\n",
				mustMarshal(jsonrpcResponse{
					JSONRPC: "2.0",
					ID:      float64(matchID),
					Error:   &jsonrpcError{Code: -32600, Message: "Invalid Request"},
				})),
			id:        matchID,
			wantErr:   true,
			errSubstr: "Invalid Request",
		},
		{
			name: "non-data lines are ignored before match",
			stream: fmt.Sprintf("event: ping\nid: 1\ndata: %s\n",
				mustMarshal(jsonrpcResponse{
					JSONRPC: "2.0",
					ID:      float64(matchID),
					Result:  json.RawMessage(`{"pong":true}`),
				})),
			id:      matchID,
			wantRaw: `{"pong":true}`,
		},
		{
			name: "invalid JSON data lines are skipped",
			stream: fmt.Sprintf("data: not-json\ndata: %s\n",
				mustMarshal(jsonrpcResponse{
					JSONRPC: "2.0",
					ID:      float64(matchID),
					Result:  json.RawMessage(`{"found":true}`),
				})),
			id:      matchID,
			wantRaw: `{"found":true}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := strings.NewReader(tc.stream)
			raw, err := parseSSEResponse(r, tc.id)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tc.errSubstr != "" && !strings.Contains(err.Error(), tc.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tc.errSubstr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(raw) != tc.wantRaw {
				t.Errorf("expected result %q, got %q", tc.wantRaw, string(raw))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// callHTTP tests (via httptest.Server)
// ---------------------------------------------------------------------------

func makeJSONRPCResp(id interface{}, result interface{}) []byte {
	resp := jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
	}
	if result != nil {
		b, _ := json.Marshal(result)
		resp.Result = json.RawMessage(b)
	}
	b, _ := json.Marshal(resp)
	return b
}

func TestCallHTTP(t *testing.T) {
	t.Run("success JSON response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Decode the incoming request to read the ID.
			var req jsonrpcRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(makeJSONRPCResp(req.ID, map[string]string{"status": "ok"}))
		}))
		defer srv.Close()

		c := NewHTTPClient(srv.URL)
		raw, err := c.call(t.Context(), "test/method", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var got map[string]string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if got["status"] != "ok" {
			t.Errorf("expected status ok, got %q", got["status"])
		}
	})

	t.Run("401 returns ErrAuthRequired", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
		}))
		defer srv.Close()

		c := NewHTTPClient(srv.URL)
		_, err := c.call(t.Context(), "test/method", nil)
		if err == nil {
			t.Fatal("expected error")
		}
		var authErr *ErrAuthRequired
		ok := false
		if e, isAuth := err.(*ErrAuthRequired); isAuth {
			authErr = e
			ok = true
		}
		if !ok {
			t.Fatalf("expected *ErrAuthRequired, got %T: %v", err, err)
		}
		if authErr.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", authErr.StatusCode)
		}
	})

	t.Run("403 returns ErrAuthRequired", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "forbidden", http.StatusForbidden)
		}))
		defer srv.Close()

		c := NewHTTPClient(srv.URL)
		_, err := c.call(t.Context(), "test/method", nil)
		if err == nil {
			t.Fatal("expected error")
		}
		authErr, ok := err.(*ErrAuthRequired)
		if !ok {
			t.Fatalf("expected *ErrAuthRequired, got %T: %v", err, err)
		}
		if authErr.StatusCode != http.StatusForbidden {
			t.Errorf("expected 403, got %d", authErr.StatusCode)
		}
	})

	t.Run("non-200 status returns error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		c := NewHTTPClient(srv.URL)
		_, err := c.call(t.Context(), "test/method", nil)
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("expected HTTP 500 in error, got %q", err.Error())
		}
	})

	t.Run("SSE content-type response parsed correctly", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req jsonrpcRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "text/event-stream")
			respBytes := makeJSONRPCResp(req.ID, map[string]string{"sse": "yes"})
			fmt.Fprintf(w, "data: %s\n\n", string(respBytes))
		}))
		defer srv.Close()

		c := NewHTTPClient(srv.URL)
		raw, err := c.call(t.Context(), "test/method", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var got map[string]string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["sse"] != "yes" {
			t.Errorf("expected 'yes', got %q", got["sse"])
		}
	})

	t.Run("SSE with no data returns error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintln(w, "event: ping")
		}))
		defer srv.Close()

		c := NewHTTPClient(srv.URL)
		_, err := c.call(t.Context(), "test/method", nil)
		if err == nil {
			t.Fatal("expected error for empty SSE")
		}
	})

	t.Run("JSON-RPC error in response propagated", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req jsonrpcRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			resp := jsonrpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &jsonrpcError{Code: -32601, Message: "Method not found"},
			}
			b, _ := json.Marshal(resp)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
		}))
		defer srv.Close()

		c := NewHTTPClient(srv.URL)
		_, err := c.call(t.Context(), "unknown/method", nil)
		if err == nil {
			t.Fatal("expected JSON-RPC error")
		}
		if !strings.Contains(err.Error(), "Method not found") {
			t.Errorf("expected 'Method not found' in error, got %q", err.Error())
		}
	})
}

// ---------------------------------------------------------------------------
// callSSE tests (via httptest.Server)
// ---------------------------------------------------------------------------

func TestCallSSE(t *testing.T) {
	t.Run("SSE content-type streams result by ID", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req jsonrpcRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "text/event-stream")
			respBytes := makeJSONRPCResp(req.ID, map[string]string{"transport": "sse"})
			fmt.Fprintf(w, "data: %s\n\n", string(respBytes))
		}))
		defer srv.Close()

		c := NewSSEClient(srv.URL)
		raw, err := c.call(t.Context(), "test/method", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var got map[string]string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["transport"] != "sse" {
			t.Errorf("expected 'sse', got %q", got["transport"])
		}
	})

	t.Run("plain JSON fallback when content-type is not SSE", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req jsonrpcRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(makeJSONRPCResp(req.ID, map[string]string{"mode": "plain"}))
		}))
		defer srv.Close()

		c := NewSSEClient(srv.URL)
		raw, err := c.call(t.Context(), "test/method", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var got map[string]string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["mode"] != "plain" {
			t.Errorf("expected 'plain', got %q", got["mode"])
		}
	})

	t.Run("SSE stream with mismatched ID returns error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			// Respond with an ID that will never match.
			respBytes := makeJSONRPCResp(float64(99999), map[string]string{})
			fmt.Fprintf(w, "data: %s\n\n", string(respBytes))
		}))
		defer srv.Close()

		c := NewSSEClient(srv.URL)
		_, err := c.call(t.Context(), "test/method", nil)
		if err == nil {
			t.Fatal("expected error for ID mismatch")
		}
	})
}

// ---------------------------------------------------------------------------
// notify tests (HTTP/SSE transports)
// ---------------------------------------------------------------------------

func TestNotifyHTTP(t *testing.T) {
	received := make(chan map[string]interface{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL)
	err := c.notify(t.Context(), "notifications/initialized", map[string]interface{}{})
	if err != nil {
		t.Fatalf("notify returned error: %v", err)
	}

	select {
	case msg := <-received:
		if msg["method"] != "notifications/initialized" {
			t.Errorf("expected method 'notifications/initialized', got %v", msg["method"])
		}
		if msg["jsonrpc"] != "2.0" {
			t.Errorf("expected jsonrpc '2.0', got %v", msg["jsonrpc"])
		}
	default:
		t.Error("no notification received by server")
	}
}

func TestNotifySSE(t *testing.T) {
	received := make(chan map[string]interface{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewSSEClient(srv.URL)
	err := c.notify(t.Context(), "notifications/initialized", map[string]interface{}{})
	if err != nil {
		t.Fatalf("notify returned error: %v", err)
	}

	select {
	case msg := <-received:
		if msg["method"] != "notifications/initialized" {
			t.Errorf("expected method 'notifications/initialized', got %v", msg["method"])
		}
	default:
		t.Error("no notification received by server")
	}
}

// ---------------------------------------------------------------------------
// ErrAuthRequired tests
// ---------------------------------------------------------------------------

func TestErrAuthRequired_Error(t *testing.T) {
	err := &ErrAuthRequired{StatusCode: 401, Body: "unauthorized"}
	got := err.Error()
	if !strings.Contains(got, "401") {
		t.Errorf("expected '401' in error message, got %q", got)
	}
	if !strings.Contains(got, "authentication required") {
		t.Errorf("expected 'authentication required' in error message, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// jsonrpcError tests
// ---------------------------------------------------------------------------

func TestJSONRPCError_Error(t *testing.T) {
	e := &jsonrpcError{Code: -32600, Message: "Invalid Request"}
	got := e.Error()
	if !strings.Contains(got, "-32600") {
		t.Errorf("expected code in message, got %q", got)
	}
	if !strings.Contains(got, "Invalid Request") {
		t.Errorf("expected message text, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Client constructor option tests
// ---------------------------------------------------------------------------

func TestClientOptions(t *testing.T) {
	t.Run("WithHTTPClient overrides http client", func(t *testing.T) {
		customClient := &http.Client{}
		c := NewHTTPClient("http://localhost", WithHTTPClient(customClient))
		if c.httpClient != customClient {
			t.Error("expected custom http client to be set")
		}
	})

	t.Run("NewSSEClient sets SSE transport", func(t *testing.T) {
		c := NewSSEClient("http://localhost/sse")
		if c.transport != TransportSSE {
			t.Errorf("expected SSE transport, got %q", c.transport)
		}
		if c.target != "http://localhost/sse" {
			t.Errorf("unexpected target %q", c.target)
		}
	})

	t.Run("NewHTTPClient sets HTTP transport", func(t *testing.T) {
		c := NewHTTPClient("http://localhost/mcp")
		if c.transport != TransportHTTP {
			t.Errorf("expected HTTP transport, got %q", c.transport)
		}
	})

	t.Run("NewStdioClient sets stdio transport", func(t *testing.T) {
		c := NewStdioClient("echo", []string{"hello"})
		if c.transport != TransportStdio {
			t.Errorf("expected stdio transport, got %q", c.transport)
		}
		if c.target != "echo" {
			t.Errorf("unexpected target %q", c.target)
		}
	})

	t.Run("WithMaxRetries sets maxRetries field", func(t *testing.T) {
		c := NewHTTPClient("http://localhost", WithMaxRetries(5))
		if c.maxRetries != 5 {
			t.Errorf("expected maxRetries=5, got %d", c.maxRetries)
		}
	})

	t.Run("default maxRetries is defaultMaxRetries", func(t *testing.T) {
		c := NewHTTPClient("http://localhost")
		if c.maxRetries != defaultMaxRetries {
			t.Errorf("expected maxRetries=%d, got %d", defaultMaxRetries, c.maxRetries)
		}
	})
}

// ---------------------------------------------------------------------------
// parseRetryAfter tests
// ---------------------------------------------------------------------------

func TestParseRetryAfter(t *testing.T) {
	fallback := 5 * time.Second

	tests := []struct {
		name     string
		header   string
		fallback time.Duration
		wantMin  time.Duration
		wantMax  time.Duration
	}{
		{
			name:     "empty header returns fallback",
			header:   "",
			fallback: fallback,
			wantMin:  fallback,
			wantMax:  fallback,
		},
		{
			name:     "delta-seconds 0",
			header:   "0",
			fallback: fallback,
			wantMin:  0,
			wantMax:  0,
		},
		{
			name:     "delta-seconds 3",
			header:   "3",
			fallback: fallback,
			wantMin:  3 * time.Second,
			wantMax:  3 * time.Second,
		},
		{
			name:     "negative delta-seconds returns fallback",
			header:   "-1",
			fallback: fallback,
			wantMin:  fallback,
			wantMax:  fallback,
		},
		{
			name:     "whitespace-padded delta-seconds",
			header:   "  10  ",
			fallback: fallback,
			wantMin:  10 * time.Second,
			wantMax:  10 * time.Second,
		},
		{
			name:     "invalid header returns fallback",
			header:   "not-a-number",
			fallback: fallback,
			wantMin:  fallback,
			wantMax:  fallback,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseRetryAfter(tc.header, tc.fallback)
			if got < tc.wantMin || got > tc.wantMax {
				t.Errorf("parseRetryAfter(%q, %v) = %v; want [%v, %v]",
					tc.header, tc.fallback, got, tc.wantMin, tc.wantMax)
			}
		})
	}

	t.Run("HTTP-date in the future", func(t *testing.T) {
		// Use a date well in the past to generate a zero-or-negative duration.
		past := "Mon, 01 Jan 2001 00:00:00 GMT"
		got := parseRetryAfter(past, fallback)
		if got != 0 {
			t.Errorf("expected 0 for past date, got %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// retryableDo / 429 backoff tests
// ---------------------------------------------------------------------------

// make429Handler returns a handler that serves 429 for the first `failCount`
// requests (with an optional Retry-After header) then responds with a valid
// JSON-RPC result.
func make429Handler(t *testing.T, failCount int, retryAfterHeader string) http.HandlerFunc {
	t.Helper()
	var calls int
	return func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= failCount {
			if retryAfterHeader != "" {
				w.Header().Set("Retry-After", retryAfterHeader)
			}
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprintln(w, "rate limited")
			return
		}
		// Decode incoming JSON-RPC request to echo the ID back.
		var req jsonrpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(makeJSONRPCResp(req.ID, map[string]string{"status": "ok"}))
	}
}

// fastRetryOpts returns client options that make retry backoff effectively
// instant (1 µs), keeping unit tests fast.
func fastRetryOpts() []ClientOption {
	return []ClientOption{withRetryBackoff(time.Microsecond, time.Microsecond)}
}

func TestRetryableDo_429WithRetryAfterHeader(t *testing.T) {
	// Server returns 429 twice with "Retry-After: 0", then 200.
	srv := httptest.NewServer(make429Handler(t, 2, "0"))
	defer srv.Close()

	opts := append(fastRetryOpts(), WithMaxRetries(3))
	c := NewHTTPClient(srv.URL, opts...)

	raw, err := c.call(t.Context(), "test/method", nil)
	if err != nil {
		t.Fatalf("unexpected error after retries: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if got["status"] != "ok" {
		t.Errorf("expected status ok, got %q", got["status"])
	}

	if c.RetryCount() != 2 {
		t.Errorf("expected 2 retries, got %d", c.RetryCount())
	}
}

func TestRetryableDo_429WithoutRetryAfterHeader(t *testing.T) {
	// Server returns 429 once with no Retry-After header, then 200.
	// Uses instant backoff so the test doesn't sleep.
	srv := httptest.NewServer(make429Handler(t, 1, ""))
	defer srv.Close()

	opts := append(fastRetryOpts(), WithMaxRetries(3))
	c := NewHTTPClient(srv.URL, opts...)

	raw, err := c.call(t.Context(), "test/method", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if got["status"] != "ok" {
		t.Errorf("expected status ok, got %q", got["status"])
	}

	if c.RetryCount() != 1 {
		t.Errorf("expected 1 retry, got %d", c.RetryCount())
	}
}

func TestRetryableDo_MaxRetriesExceeded(t *testing.T) {
	// Server always returns 429; client should exhaust retries and return an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	opts := append(fastRetryOpts(), WithMaxRetries(2))
	c := NewHTTPClient(srv.URL, opts...)

	_, err := c.call(t.Context(), "test/method", nil)
	if err == nil {
		t.Fatal("expected error when max retries exceeded, got nil")
	}

	var rateLimitErr *ErrMaxRetriesExceeded
	if !strings.Contains(err.Error(), "rate limited") && !strings.Contains(err.Error(), "429") {
		t.Errorf("expected rate-limit error, got: %v", err)
	}
	// The error should unwrap to *ErrMaxRetriesExceeded.
	if !errors.As(err, &rateLimitErr) {
		t.Errorf("expected *ErrMaxRetriesExceeded in error chain, got %T: %v", err, err)
	}
	if rateLimitErr.Retries != 2 {
		t.Errorf("expected Retries=2, got %d", rateLimitErr.Retries)
	}
}

func TestRetryableDo_SSE429WithRetryAfterHeader(t *testing.T) {
	// SSE transport: server returns 429 once with Retry-After: 0, then a valid SSE response.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		var req jsonrpcRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "text/event-stream")
		respBytes := makeJSONRPCResp(req.ID, map[string]string{"transport": "sse-retry"})
		fmt.Fprintf(w, "data: %s\n\n", string(respBytes))
	}))
	defer srv.Close()

	opts := append(fastRetryOpts(), WithMaxRetries(3))
	c := NewSSEClient(srv.URL, opts...)

	raw, err := c.call(t.Context(), "test/method", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["transport"] != "sse-retry" {
		t.Errorf("expected 'sse-retry', got %q", got["transport"])
	}

	if c.RetryCount() != 1 {
		t.Errorf("expected 1 retry, got %d", c.RetryCount())
	}
}

func TestRetryableDo_ZeroMaxRetries(t *testing.T) {
	// When maxRetries=0, a single 429 should immediately return an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := NewHTTPClient(srv.URL, WithMaxRetries(0))

	_, err := c.call(t.Context(), "test/method", nil)
	if err == nil {
		t.Fatal("expected error for 429 with maxRetries=0")
	}

	var rateLimitErr *ErrMaxRetriesExceeded
	if !errors.As(err, &rateLimitErr) {
		t.Errorf("expected *ErrMaxRetriesExceeded, got %T: %v", err, err)
	}
	if c.RetryCount() != 0 {
		t.Errorf("expected 0 retries (no sleep performed), got %d", c.RetryCount())
	}
}

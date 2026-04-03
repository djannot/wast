package mcpscan

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
}

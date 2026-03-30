package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthConfig_IsEmpty(t *testing.T) {
	tests := []struct {
		name   string
		config *AuthConfig
		want   bool
	}{
		{
			name:   "nil config",
			config: nil,
			want:   true,
		},
		{
			name:   "empty config",
			config: &AuthConfig{},
			want:   true,
		},
		{
			name: "with auth header",
			config: &AuthConfig{
				AuthHeader: "Authorization: Bearer token123",
			},
			want: false,
		},
		{
			name: "with bearer token",
			config: &AuthConfig{
				BearerToken: "token123",
			},
			want: false,
		},
		{
			name: "with basic auth",
			config: &AuthConfig{
				BasicAuth: "user:pass",
			},
			want: false,
		},
		{
			name: "with cookies",
			config: &AuthConfig{
				Cookies: []string{"session=abc123"},
			},
			want: false,
		},
		{
			name: "with empty cookies slice",
			config: &AuthConfig{
				Cookies: []string{},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.IsEmpty(); got != tt.want {
				t.Errorf("AuthConfig.IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthConfig_ApplyToRequest(t *testing.T) {
	tests := []struct {
		name           string
		config         *AuthConfig
		expectedHeader map[string]string
		expectedCookie map[string]string
	}{
		{
			name:           "nil config",
			config:         nil,
			expectedHeader: map[string]string{},
			expectedCookie: map[string]string{},
		},
		{
			name: "bearer token",
			config: &AuthConfig{
				BearerToken: "mytoken123",
			},
			expectedHeader: map[string]string{
				"Authorization": "Bearer mytoken123",
			},
			expectedCookie: map[string]string{},
		},
		{
			name: "basic auth",
			config: &AuthConfig{
				BasicAuth: "admin:secret",
			},
			expectedHeader: map[string]string{
				"Authorization": "Basic YWRtaW46c2VjcmV0", // base64("admin:secret")
			},
			expectedCookie: map[string]string{},
		},
		{
			name: "custom auth header",
			config: &AuthConfig{
				AuthHeader: "X-API-Key: abc123",
			},
			expectedHeader: map[string]string{
				"X-Api-Key": "abc123",
			},
			expectedCookie: map[string]string{},
		},
		{
			name: "cookie",
			config: &AuthConfig{
				Cookies: []string{"session=xyz789"},
			},
			expectedHeader: map[string]string{},
			expectedCookie: map[string]string{
				"session": "xyz789",
			},
		},
		{
			name: "multiple cookies",
			config: &AuthConfig{
				Cookies: []string{"session=xyz789", "user_id=123"},
			},
			expectedHeader: map[string]string{},
			expectedCookie: map[string]string{
				"session": "xyz789",
				"user_id": "123",
			},
		},
		{
			name: "combined auth methods",
			config: &AuthConfig{
				BearerToken: "token123",
				Cookies:     []string{"session=abc"},
			},
			expectedHeader: map[string]string{
				"Authorization": "Bearer token123",
			},
			expectedCookie: map[string]string{
				"session": "abc",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://example.com", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			tt.config.ApplyToRequest(req)

			// Check headers
			for key, expectedValue := range tt.expectedHeader {
				got := req.Header.Get(key)
				if got != expectedValue {
					t.Errorf("Header %s = %q, want %q", key, got, expectedValue)
				}
			}

			// Check cookies
			for name, expectedValue := range tt.expectedCookie {
				cookie, err := req.Cookie(name)
				if err != nil {
					t.Errorf("Expected cookie %s not found", name)
					continue
				}
				if cookie.Value != expectedValue {
					t.Errorf("Cookie %s = %q, want %q", name, cookie.Value, expectedValue)
				}
			}
		})
	}
}

func TestAuthConfig_Summary(t *testing.T) {
	tests := []struct {
		name   string
		config *AuthConfig
		want   string
	}{
		{
			name:   "nil config",
			config: nil,
			want:   "none",
		},
		{
			name:   "empty config",
			config: &AuthConfig{},
			want:   "none",
		},
		{
			name: "bearer token",
			config: &AuthConfig{
				BearerToken: "secret-token",
			},
			want: "bearer:***",
		},
		{
			name: "basic auth",
			config: &AuthConfig{
				BasicAuth: "admin:password",
			},
			want: "basic:admin:***",
		},
		{
			name: "custom header",
			config: &AuthConfig{
				AuthHeader: "X-API-Key: secret",
			},
			want: "header:X-API-Key",
		},
		{
			name: "single cookie",
			config: &AuthConfig{
				Cookies: []string{"session=abc123"},
			},
			want: "cookies:[session]",
		},
		{
			name: "multiple cookies",
			config: &AuthConfig{
				Cookies: []string{"session=abc123", "user=john"},
			},
			want: "cookies:[session,user]",
		},
		{
			name: "combined",
			config: &AuthConfig{
				BearerToken: "token",
				Cookies:     []string{"session=abc"},
			},
			want: "bearer:***, cookies:[session]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.config.Summary(); got != tt.want {
				t.Errorf("AuthConfig.Summary() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuthConfig_BearerOverridesBasic(t *testing.T) {
	// When both bearer and basic are set, bearer should be applied last
	// (overriding the Authorization header set by basic auth)
	config := &AuthConfig{
		BasicAuth:   "user:pass",
		BearerToken: "mytoken",
	}

	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	config.ApplyToRequest(req)

	got := req.Header.Get("Authorization")
	want := "Bearer mytoken"
	if got != want {
		t.Errorf("Authorization header = %q, want %q", got, want)
	}
}

func TestAuthConfig_CustomHeaderFormat(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantKey    string
		wantValue  string
	}{
		{
			name:       "standard format",
			authHeader: "Authorization: Bearer token",
			wantKey:    "Authorization",
			wantValue:  "Bearer token",
		},
		{
			name:       "with extra spaces",
			authHeader: "Authorization:   Bearer token  ",
			wantKey:    "Authorization",
			wantValue:  "Bearer token",
		},
		{
			name:       "custom header",
			authHeader: "X-Custom-Auth: my-secret-value",
			wantKey:    "X-Custom-Auth",
			wantValue:  "my-secret-value",
		},
		{
			name:       "invalid format (no colon)",
			authHeader: "InvalidHeader",
			wantKey:    "",
			wantValue:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &AuthConfig{
				AuthHeader: tt.authHeader,
			}

			req, err := http.NewRequest("GET", "http://example.com", nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			config.ApplyToRequest(req)

			if tt.wantKey != "" {
				got := req.Header.Get(tt.wantKey)
				if got != tt.wantValue {
					t.Errorf("Header %s = %q, want %q", tt.wantKey, got, tt.wantValue)
				}
			}
		})
	}
}

func TestAuthConfig_PerformLogin_Success(t *testing.T) {
	// Create a test server that simulates a successful login
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			t.Errorf("Failed to parse form: %v", err)
		}

		// Verify credentials
		username := r.FormValue("username")
		password := r.FormValue("password")
		if username != "testuser" || password != "testpass" {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Set session cookie on successful login
		http.SetCookie(w, &http.Cookie{
			Name:  "session_id",
			Value: "abc123xyz",
			Path:  "/",
		})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Login successful"))
	}))
	defer server.Close()

	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL:      server.URL,
			Username:      "testuser",
			Password:      "testpass",
			UsernameField: "username",
			PasswordField: "password",
		},
	}

	ctx := context.Background()
	err := config.PerformLogin(ctx)
	if err != nil {
		t.Fatalf("PerformLogin failed: %v", err)
	}

	// Verify cookies were captured
	if len(config.Cookies) == 0 {
		t.Fatal("Expected cookies to be captured, got none")
	}

	// Verify the session cookie
	found := false
	for _, cookie := range config.Cookies {
		if strings.Contains(cookie, "session_id=abc123xyz") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected session_id cookie to be captured, got: %v", config.Cookies)
	}
}

func TestAuthConfig_PerformLogin_JSONFormat(t *testing.T) {
	// Create a test server that accepts JSON login
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify content type
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected application/json, got %s", contentType)
		}

		// Set session cookie on successful login
		http.SetCookie(w, &http.Cookie{
			Name:  "auth_token",
			Value: "json123",
			Path:  "/",
		})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true}`))
	}))
	defer server.Close()

	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL:    server.URL,
			Username:    "jsonuser",
			Password:    "jsonpass",
			ContentType: "json",
		},
	}

	ctx := context.Background()
	err := config.PerformLogin(ctx)
	if err != nil {
		t.Fatalf("PerformLogin failed: %v", err)
	}

	// Verify cookies were captured
	if len(config.Cookies) == 0 {
		t.Fatal("Expected cookies to be captured, got none")
	}
}

func TestAuthConfig_PerformLogin_WithRedirect(t *testing.T) {
	// Create a test server that redirects after login
	loginCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			loginCalled = true
			// Set cookie and redirect
			http.SetCookie(w, &http.Cookie{
				Name:  "session",
				Value: "redirect123",
				Path:  "/",
			})
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		} else if r.URL.Path == "/dashboard" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Dashboard"))
		}
	}))
	defer server.Close()

	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL: server.URL + "/login",
			Username: "testuser",
			Password: "testpass",
		},
	}

	ctx := context.Background()
	err := config.PerformLogin(ctx)
	if err != nil {
		t.Fatalf("PerformLogin failed: %v", err)
	}

	if !loginCalled {
		t.Error("Login endpoint was not called")
	}

	// Verify cookies were captured
	if len(config.Cookies) == 0 {
		t.Fatal("Expected cookies to be captured, got none")
	}
}

func TestAuthConfig_PerformLogin_FailureStatusCode(t *testing.T) {
	// Create a test server that returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Unauthorized"))
	}))
	defer server.Close()

	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL: server.URL,
			Username: "wronguser",
			Password: "wrongpass",
		},
	}

	ctx := context.Background()
	err := config.PerformLogin(ctx)
	if err == nil {
		t.Fatal("Expected error for failed login, got nil")
	}

	if !strings.Contains(err.Error(), "login failed with status 401") {
		t.Errorf("Expected status code error, got: %v", err)
	}
}

func TestAuthConfig_PerformLogin_ErrorMessage(t *testing.T) {
	// Create a test server that returns success status but error message
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Invalid credentials - please try again"))
	}))
	defer server.Close()

	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL: server.URL,
			Username: "testuser",
			Password: "wrongpass",
		},
	}

	ctx := context.Background()
	err := config.PerformLogin(ctx)
	if err == nil {
		t.Fatal("Expected error for failed login with error message, got nil")
	}

	if !strings.Contains(err.Error(), "invalid credentials") {
		t.Errorf("Expected error message detection, got: %v", err)
	}
}

func TestAuthConfig_PerformLogin_NoCookies(t *testing.T) {
	// Create a test server that doesn't set cookies
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	}))
	defer server.Close()

	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL: server.URL,
			Username: "testuser",
			Password: "testpass",
		},
	}

	ctx := context.Background()
	err := config.PerformLogin(ctx)
	if err == nil {
		t.Fatal("Expected error when no cookies received, got nil")
	}

	if !strings.Contains(err.Error(), "no cookies were received") {
		t.Errorf("Expected no cookies error, got: %v", err)
	}
}

func TestAuthConfig_PerformLogin_MissingConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *AuthConfig
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name:   "nil login config",
			config: &AuthConfig{Login: nil},
		},
		{
			name: "empty login URL",
			config: &AuthConfig{
				Login: &LoginConfig{
					LoginURL: "",
				},
			},
		},
		{
			name: "missing username",
			config: &AuthConfig{
				Login: &LoginConfig{
					LoginURL: "http://example.com/login",
					Password: "pass",
				},
			},
		},
		{
			name: "missing password",
			config: &AuthConfig{
				Login: &LoginConfig{
					LoginURL: "http://example.com/login",
					Username: "user",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := tt.config.PerformLogin(ctx)
			if err == nil {
				t.Fatal("Expected error for missing config, got nil")
			}
		})
	}
}

func TestAuthConfig_PerformLogin_AdditionalFields(t *testing.T) {
	// Create a test server that expects additional fields
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("Failed to parse form: %v", err)
		}

		// Verify additional field is present
		csrfToken := r.FormValue("csrf_token")
		if csrfToken != "token123" {
			http.Error(w, "Missing CSRF token", http.StatusBadRequest)
			return
		}

		// Set session cookie
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "session_with_csrf",
			Path:  "/",
		})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	}))
	defer server.Close()

	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL: server.URL,
			Username: "testuser",
			Password: "testpass",
			AdditionalFields: map[string]string{
				"csrf_token": "token123",
			},
		},
	}

	ctx := context.Background()
	err := config.PerformLogin(ctx)
	if err != nil {
		t.Fatalf("PerformLogin failed: %v", err)
	}

	// Verify cookies were captured
	if len(config.Cookies) == 0 {
		t.Fatal("Expected cookies to be captured, got none")
	}
}

func TestAuthConfig_IsEmpty_WithLogin(t *testing.T) {
	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL: "http://example.com/login",
			Username: "user",
			Password: "pass",
		},
	}

	if config.IsEmpty() {
		t.Error("Expected IsEmpty() to return false when login config is set")
	}
}

// fakeJWT is a syntactically valid-looking JWT (3 dot-separated non-empty parts).
const fakeJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

func TestAuthConfig_PerformLogin_JWTInTokenField(t *testing.T) {
	// Server returns a JWT in {"token": "..."} with no cookies.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"` + fakeJWT + `"}`))
	}))
	defer server.Close()

	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL:    server.URL,
			Username:    "user",
			Password:    "pass",
			ContentType: "json",
		},
	}

	ctx := context.Background()
	if err := config.PerformLogin(ctx); err != nil {
		t.Fatalf("PerformLogin failed: %v", err)
	}

	if config.BearerToken != fakeJWT {
		t.Errorf("BearerToken = %q, want %q", config.BearerToken, fakeJWT)
	}
	if len(config.Cookies) != 0 {
		t.Errorf("Expected no cookies, got: %v", config.Cookies)
	}
}

func TestAuthConfig_PerformLogin_JWTNestedCustomTokenField(t *testing.T) {
	// OWASP Juice Shop-style: {"authentication":{"token":"..."}}
	// with TokenField = "authentication.token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"authentication":{"token":"` + fakeJWT + `","umail":"user@example.com"}}`))
	}))
	defer server.Close()

	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL:    server.URL,
			Username:    "user@example.com",
			Password:    "pass",
			ContentType: "json",
			TokenField:  "authentication.token",
		},
	}

	ctx := context.Background()
	if err := config.PerformLogin(ctx); err != nil {
		t.Fatalf("PerformLogin failed: %v", err)
	}

	if config.BearerToken != fakeJWT {
		t.Errorf("BearerToken = %q, want %q", config.BearerToken, fakeJWT)
	}
}

func TestAuthConfig_PerformLogin_CookiesTakePriorityOverJWT(t *testing.T) {
	// When the server sets both a cookie AND returns a JWT in the body,
	// cookies should be captured (primary path) and BearerToken left empty.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "cookieval",
			Path:  "/",
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"` + fakeJWT + `"}`))
	}))
	defer server.Close()

	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL:    server.URL,
			Username:    "user",
			Password:    "pass",
			ContentType: "json",
		},
	}

	ctx := context.Background()
	if err := config.PerformLogin(ctx); err != nil {
		t.Fatalf("PerformLogin failed: %v", err)
	}

	// Cookies should be captured; BearerToken must remain empty.
	if len(config.Cookies) == 0 {
		t.Error("Expected cookies to be captured")
	}
	if config.BearerToken != "" {
		t.Errorf("Expected BearerToken to be empty when cookies were received, got %q", config.BearerToken)
	}
}

func TestAuthConfig_PerformLogin_NeitherCookiesNorJWT(t *testing.T) {
	// Server returns 200 with a JSON body that has no recognisable token field.
	// PerformLogin must still return an error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","message":"welcome"}`))
	}))
	defer server.Close()

	config := &AuthConfig{
		Login: &LoginConfig{
			LoginURL: server.URL,
			Username: "user",
			Password: "pass",
		},
	}

	ctx := context.Background()
	err := config.PerformLogin(ctx)
	if err == nil {
		t.Fatal("Expected error when neither cookies nor JWT token received, got nil")
	}
	if !strings.Contains(err.Error(), "no cookies were received") {
		t.Errorf("Expected 'no cookies were received' error, got: %v", err)
	}
}

func TestExtractBearerTokenFromBody(t *testing.T) {
	tests := []struct {
		name             string
		body             []byte
		customTokenField string
		wantToken        string
		wantErr          bool
	}{
		{
			name:      "token field",
			body:      []byte(`{"token":"` + fakeJWT + `"}`),
			wantToken: fakeJWT,
		},
		{
			name:      "access_token field",
			body:      []byte(`{"access_token":"` + fakeJWT + `"}`),
			wantToken: fakeJWT,
		},
		{
			name:      "accessToken camelCase field",
			body:      []byte(`{"accessToken":"` + fakeJWT + `"}`),
			wantToken: fakeJWT,
		},
		{
			name:      "jwt field",
			body:      []byte(`{"jwt":"` + fakeJWT + `"}`),
			wantToken: fakeJWT,
		},
		{
			name:      "id_token field",
			body:      []byte(`{"id_token":"` + fakeJWT + `"}`),
			wantToken: fakeJWT,
		},
		{
			name:      "authentication.token nested",
			body:      []byte(`{"authentication":{"token":"` + fakeJWT + `"}}`),
			wantToken: fakeJWT,
		},
		{
			name:      "data.token nested",
			body:      []byte(`{"data":{"token":"` + fakeJWT + `"}}`),
			wantToken: fakeJWT,
		},
		{
			name:             "custom token field",
			body:             []byte(`{"auth":{"bearer":"` + fakeJWT + `"}}`),
			customTokenField: "auth.bearer",
			wantToken:        fakeJWT,
		},
		{
			name:    "empty body",
			body:    []byte{},
			wantErr: true,
		},
		{
			name:    "non-JSON body",
			body:    []byte("Login successful"),
			wantErr: true,
		},
		{
			name:    "JSON without token fields",
			body:    []byte(`{"status":"ok"}`),
			wantErr: true,
		},
		{
			name:    "token value not a JWT",
			body:    []byte(`{"token":"plainstring"}`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractBearerTokenFromBody(tt.body, tt.customTokenField)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got token %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantToken {
				t.Errorf("got token %q, want %q", got, tt.wantToken)
			}
		})
	}
}

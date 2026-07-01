package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClientSetsTimeout(t *testing.T) {
	c := NewClient("http://example.com", "token")
	if c.httpClient.Timeout != 30*time.Second {
		t.Fatalf("expected timeout 30s, got %v", c.httpClient.Timeout)
	}
}

func TestNewClientWithHTTP_NilClient(t *testing.T) {
	c := NewClientWithHTTP("http://example.com", "token", nil)
	if c.httpClient == nil {
		t.Fatal("expected non-nil httpClient")
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Fatalf("expected default timeout 30s, got %v", c.httpClient.Timeout)
	}
}

func TestSetAuthHeader(t *testing.T) {
	c := NewClient("http://example.com", "my-secret-token")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c.SetAuthHeader(req)

	auth := req.Header.Get("Authorization")
	expected := "Bearer my-secret-token"
	if auth != expected {
		t.Fatalf("expected auth header %q, got %q", expected, auth)
	}
}

func TestPostContext_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/cli/context" {
			t.Fatalf("expected path /api/v1/cli/context, got %s", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("expected Content-Type application/json, got %s", ct)
		}
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") {
			t.Fatalf("expected Bearer auth, got %s", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job-123"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	id, err := client.PostContext(context.Background(), ContextPayload{RepoRoot: "/repo"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "job-123" {
		t.Fatalf("expected job-123, got %s", id)
	}
}

func TestPostReview_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cli/review" {
			t.Fatalf("expected path /api/v1/cli/review, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job-456"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	id, err := client.PostReview(context.Background(), ReviewPayload{RepoRoot: "/repo", Submit: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "job-456" {
		t.Fatalf("expected job-456, got %s", id)
	}
}

func TestGetStatus_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/api/v1/cli/status/job-789"
		if r.URL.Path != expectedPath {
			t.Fatalf("expected path %s, got %s", expectedPath, r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Fatalf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(StatusResponse{ID: "job-789", Status: "completed", ResultURL: "http://result"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	status, err := client.GetStatus(context.Background(), "job-789")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.ID != "job-789" || status.Status != "completed" || status.ResultURL != "http://result" {
		t.Fatalf("unexpected status response: %+v", status)
	}
}

func TestPostContext_ErrorParsing(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "invalid token", "code": "AUTH_001"})
	}))
	defer server.Close()

	client := NewClient(server.URL, "bad-token")
	_, err := client.PostContext(context.Background(), ContextPayload{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *api.Error, got %T", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "invalid token" {
		t.Fatalf("expected message 'invalid token', got %q", apiErr.Message)
	}
	if apiErr.Code != "AUTH_001" {
		t.Fatalf("expected code AUTH_001, got %q", apiErr.Code)
	}
}

func TestPostContext_ErrorPlainTextBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token")
	_, err := client.PostContext(context.Background(), ContextPayload{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	apiErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *api.Error, got %T", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", apiErr.StatusCode)
	}
	if apiErr.Message != "bad request" {
		t.Fatalf("expected message 'bad request', got %q", apiErr.Message)
	}
}

func TestContextPropagation(t *testing.T) {
	var receivedCtx context.Context
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedCtx = r.Context()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "job-ctx"})
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := NewClient(server.URL, "token")
	_, err := client.PostContext(ctx, ContextPayload{})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	_ = receivedCtx // server may not have been reached, that's fine for cancelled context
}

package helpers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPPrefixAndTLSWithDeadline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/custom/v1/auth/token" {
			t.Errorf("wrong URL %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"token"}`))
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	token, err := NewHttpCaller(ctx, true).GetJwtToken(ctx, server.URL+"/custom", "root@localhost", "secret")
	if err != nil || token != "token" {
		t.Fatalf("%q %v", token, err)
	}
	if _, err := NewHttpCaller(ctx, false).GetJwtToken(ctx, server.URL+"/custom", "root@localhost", "secret"); err == nil {
		t.Fatal("trusted untrusted certificate")
	}
	for host, want := range map[string]string{"http://mac:8080": "http://mac:8080/api/v1", "http://mac:8080/api": "http://mac:8080/api/v1", "https://[::1]:8443/custom/": "https://[::1]:8443/custom/v1"} {
		if got := GetHostApiVersionedBaseUrl(host); got != want {
			t.Fatalf("%s != %s", got, want)
		}
	}
}

func TestHTTPStatusRedactsResponseAndHonorsCancellation(t *testing.T) {
	secret := "a-very-sensitive-password"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"` + secret + `","code":200}`))
	}))
	defer server.Close()
	response, err := NewHttpCaller(context.Background(), false).GetDataFromClient(context.Background(), server.URL, nil, nil, nil)
	var status *HTTPStatusError
	if !errors.As(err, &status) || status.StatusCode != http.StatusUnauthorized || response.ApiError.Code != 401 || strings.Contains(err.Error(), secret) {
		t.Fatalf("invalid sanitized status %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = NewHttpCaller(ctx, false).GetDataFromClient(ctx, server.URL, nil, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
}

// A call that takes longer than the default client timeout succeeds when the request's context allows it (a resource's timeouts),
// and is still cut off when the context has no deadline.
func TestRequestDeadlineGovernsTheClientTimeout(t *testing.T) {
	previous := defaultClientTimeout
	defaultClientTimeout = 100 * time.Millisecond
	defer func() { defaultClientTimeout = previous }()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond) // like an orchestrator creating a VM from a catalog: it answers when the VM exists
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"vm-1"}`))
	}))
	defer server.Close()

	var created map[string]string
	if _, err := NewHttpCaller(context.Background(), false).PostDataToClient(context.Background(), server.URL, nil, map[string]string{}, nil, &created); err == nil {
		t.Fatal("a request without a deadline outlived the default client timeout")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := NewHttpCaller(ctx, false).PostDataToClient(ctx, server.URL, nil, map[string]string{}, nil, &created); err != nil {
		t.Fatalf("a request with a 5 s deadline was cut off by the client timeout: %v", err)
	}
	if created["id"] != "vm-1" {
		t.Fatalf("got %v", created)
	}
}

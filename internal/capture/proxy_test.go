package capture

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyUnixSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "capture.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sources" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if r.Method == http.MethodPost && string(body) != `{"Name":"test","Interface":"lo","Ports":[7070]}` {
			t.Errorf("unexpected payload %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"Sources":[]}`))
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	handler := NewProxy(socketPath)
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		request := httptest.NewRequest(method, "/api/capture/sources", strings.NewReader(`{"Name":"test","Interface":"lo","Ports":[7070]}`))
		if method == http.MethodPost {
			request.ContentLength = -1
		} // chunked clients
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusAccepted || recorder.Body.String() != `{"Sources":[]}` {
			t.Fatalf("bad proxy response %d: %s", recorder.Code, recorder.Body.String())
		}
	}
}

func TestUnavailableAndOversized(t *testing.T) {
	handler := NewProxy(filepath.Join(t.TempDir(), "missing.sock"))
	for _, test := range []struct {
		method, body string
		status       int
	}{
		{http.MethodGet, "", http.StatusServiceUnavailable},
		{http.MethodPost, strings.Repeat("x", 65537), http.StatusRequestEntityTooLarge},
		{http.MethodPut, "", http.StatusMethodNotAllowed},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(test.method, "/api/capture/sources", strings.NewReader(test.body)))
		if recorder.Code != test.status {
			t.Errorf("got %d want %d", recorder.Code, test.status)
		}
	}
}

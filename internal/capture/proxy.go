// Package capture exposes the local packet collector through the authenticated UI API.
package capture

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
)

func RegisterRoutes(router chi.Router) {
	socketPath := os.Getenv("PKAPPA2_CAPTURE_SOCKET")
	if socketPath == "" {
		socketPath = "/run/pkappa2-capture/control.sock"
	}
	handler := NewProxy(socketPath)
	router.Method(http.MethodGet, "/api/capture/sources", handler)
	router.Method(http.MethodPost, "/api/capture/sources", handler)
	router.Method(http.MethodDelete, "/api/capture/sources", handler)
}

func NewProxy(socketPath string) http.Handler {
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body := http.MaxBytesReader(w, r.Body, 65536)
		defer body.Close()
		payload, err := io.ReadAll(body)
		if err != nil {
			http.Error(w, "Capture request is too large or invalid", http.StatusRequestEntityTooLarge)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), r.Method, "http://capture/sources", bytes.NewReader(payload))
		if err != nil {
			http.Error(w, "Invalid capture request", http.StatusBadRequest)
			return
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			http.Error(w, "Capture collector unavailable. Start the capture service with docker compose up -d --build.", http.StatusServiceUnavailable)
			return
		}
		defer response.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	})
}

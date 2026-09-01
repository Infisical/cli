package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func requireBasicAuth(username, password string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actualUsername, actualPassword, ok := r.BasicAuth()
		if !ok || actualUsername != username || actualPassword != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="web-server-test"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func sanitizeHeaders(headers http.Header) http.Header {
	sanitized := headers.Clone()
	for _, name := range []string{
		"Authorization",
		"Proxy-Authorization",
		"Cookie",
		"Set-Cookie",
		"X-Api-Key",
		"X-Auth-Token",
	} {
		if _, exists := sanitized[name]; exists {
			sanitized[name] = []string{"[REDACTED]"}
		}
	}
	return sanitized
}

func main() {
	username := os.Getenv("WEB_TEST_USERNAME")
	if username == "" {
		username = "demo"
	}
	password := os.Getenv("WEB_TEST_PASSWORD")
	if password == "" {
		password = "secret"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "unable to read body", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"method":  r.Method,
			"path":    r.URL.Path,
			"query":   r.URL.RawQuery,
			"headers": sanitizeHeaders(r.Header),
			"body":    string(body),
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	log.Printf("Starting test web server on http://127.0.0.1:4040")

	server := &http.Server{
		Addr:              "127.0.0.1:4040",
		Handler:           requireBasicAuth(username, password, mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

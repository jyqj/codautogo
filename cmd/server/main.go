package main

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"codex/internal/codex"
)

//go:embed web
var webFS embed.FS

func main() {
	host := envOrDefault("APP_HOST", "0.0.0.0")
	port := envOrDefaultInt("APP_PORT", 8318)
	dataDir := envOrDefault("APP_DATA_DIR", ".")
	dataDir, _ = filepath.Abs(dataDir)

	configPath := filepath.Join(dataDir, "config.json")
	if p := os.Getenv("APP_CONFIG_PATH"); p != "" {
		configPath = p
	}

	adminToken := codex.ResolveAdminToken(dataDir)

	serverCfg := &codex.ServerConfig{
		Host:       host,
		Port:       port,
		AdminToken: adminToken,
		DataDir:    dataDir,
		ConfigPath: configPath,
		LogsDir:    filepath.Join(dataDir, "logs"),
	}

	srv := codex.NewServer(serverCfg)

	mux := http.NewServeMux()

	// API routes
	mux.Handle("/api/", srv)

	// CORS preflight
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// Serve embedded static files
		if strings.HasPrefix(r.URL.Path, "/api/") {
			srv.ServeHTTP(w, r)
			return
		}

		subFS, err := fs.Sub(webFS, "web")
		if err != nil {
			http.Error(w, "internal error", 500)
			return
		}
		// try exact file first, fallback to index.html (SPA)
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" || path == "/" {
			data, err := fs.ReadFile(subFS, "index.html")
			if err != nil {
				http.Error(w, "not found", 404)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
			return
		}
		if _, err := fs.Stat(subFS, path); err != nil {
			data, _ := fs.ReadFile(subFS, "index.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
			return
		}
		http.FileServer(http.FS(subFS)).ServeHTTP(w, r)
	})

	addr := fmt.Sprintf("%s:%d", host, port)
	fmt.Printf("\n========================================\n")
	fmt.Printf("  Codex Server\n")
	fmt.Printf("  Listen: http://%s\n", addr)
	fmt.Printf("  Admin Token: %s\n", adminToken)
	fmt.Printf("  Config: %s\n", configPath)
	fmt.Printf("  Data: %s\n", dataDir)
	fmt.Printf("========================================\n\n")

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Printf("Server error: %v\n", err)
		os.Exit(1)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envOrDefaultInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

package main

import (
	"crypto/sha256"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/d80y6/YemenDDoS/controller/internal/api"
	"github.com/gin-gonic/gin"
)

func TestConsoleEmbed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	sub, err := fs.Sub(webDist, webRoot)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	api.ServeSPA(router, sub)
	types := map[string]string{".html": "text/html", ".js": "application/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".json": "application/json", ".woff2": "font/woff2", ".woff": "font/woff", ".png": "image/png", ".ico": "image/x-icon"}
	files := 0
	err = filepath.WalkDir("console/dist", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		name, relErr := filepath.Rel("console/dist", path)
		if relErr != nil {
			return relErr
		}
		t.Run(filepath.ToSlash(name), func(t *testing.T) {
			want, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, (&url.URL{Path: "/" + filepath.ToSlash(name)}).String(), nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status: got %d want 200", response.Code)
			}
			if got, expected := sha256.Sum256(response.Body.Bytes()), sha256.Sum256(want); got != expected {
				t.Fatalf("sha256: got %x want %x", got, expected)
			}
			contentType, known := types[filepath.Ext(name)]
			if !known {
				t.Fatalf("unregistered extension: %s", name)
			}
			if got := response.Header().Get("Content-Type"); got != contentType {
				t.Fatalf("Content-Type: got %q want %q", got, contentType)
			}
		})
		files++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("empty console/dist")
	}
	t.Logf("all-files=%d status/sha256/Content-Type checked", files)
	index, err := os.ReadFile("console/dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/overview", "/attacks/123"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != 200 || sha256.Sum256(response.Body.Bytes()) != sha256.Sum256(index) {
				t.Fatal("SPA fallback differs from index.html")
			}
			if response.Header().Get("Content-Type") != "text/html; charset=utf-8" {
				t.Fatal("SPA Content-Type")
			}
		})
	}
	t.Run("api-nope", func(t *testing.T) {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/nope", nil))
		var body map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if response.Code != 404 || body["error"] != "not found" || response.Header().Get("Content-Type") != "application/json; charset=utf-8" {
			t.Fatalf("API fallback: %d %s", response.Code, response.Body.String())
		}
	})
}

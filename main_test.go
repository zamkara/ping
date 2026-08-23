package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ping/config"
	"ping/internal/handlers"
	"ping/internal/models"
	"ping/internal/useragent"
)

func TestUserAgentParser(t *testing.T) {
	uaStr := "Mozilla/5.0 (X11; Linux x86_64; rv:154.0) Gecko/20100101 Firefox/154.0"
	info := useragent.Parse(uaStr)

	if info.Browser != "Mozilla Firefox" {
		t.Errorf("Expected browser Firefox, got %s", info.Browser)
	}
	if info.OS != "Linux" {
		t.Errorf("Expected OS Linux, got %s", info.OS)
	}

	curlStr := "curl/8.21.0"
	curlInfo := useragent.Parse(curlStr)
	if !curlInfo.IsCLI {
		t.Errorf("Expected curl to be CLI tool")
	}
}

func TestDataJSONEndpoint(t *testing.T) {
	cfg := config.Load()
	h := handlers.NewHandler(cfg)

	req := httptest.NewRequest("GET", "/json", nil)
	req.Header.Set("User-Agent", "Go-Test-Client")
	req.Header.Set("CF-Connecting-IP", "203.0.113.195")
	req.Header.Set("CF-IPCountry", "ID")

	w := httptest.NewRecorder()
	h.HandleJSON(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", resp.StatusCode)
	}

	var pingResp models.PingResponse
	err := json.NewDecoder(resp.Body).Decode(&pingResp)
	if err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if pingResp.Client.IP != "203.0.113.195" {
		t.Errorf("Expected client IP 203.0.113.195, got %s", pingResp.Client.IP)
	}
	if pingResp.Geo.CountryCode != "ID" {
		t.Errorf("Expected country ID, got %s", pingResp.Geo.CountryCode)
	}
	if pingResp.Cloudflare == nil || pingResp.Cloudflare.Country != "ID" {
		t.Errorf("Expected Cloudflare CF object compatibility")
	}
}

func TestIPEndpoint(t *testing.T) {
	cfg := config.Load()
	h := handlers.NewHandler(cfg)

	req := httptest.NewRequest("GET", "/ip", nil)
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	w := httptest.NewRecorder()
	h.HandleIP(w, req)

	if w.Body.String() != "1.1.1.1\n" {
		t.Errorf("Expected IP 1.1.1.1, got %q", w.Body.String())
	}
}

package handler

import (
	"net/http"

	"ping/config"
	"ping/pkg/handlers"
)

var h *handlers.Handler

func init() {
	cfg := config.Load()
	h = handlers.NewHandler(cfg)
}

// Handler is the Vercel Serverless Function entrypoint
func Handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/json":
		h.HandleJSON(w, r)
	case "/ip":
		h.HandleIP(w, r)
	case "/headers":
		h.HandleHeaders(w, r)
	case "/user-agent", "/ua":
		h.HandleUserAgent(w, r)
	case "/geo":
		h.HandleGeo(w, r)
	case "/network":
		h.HandleNetwork(w, r)
	case "/security":
		h.HandleSecurity(w, r)
	case "/tls":
		h.HandleTLS(w, r)
	case "/echo":
		h.HandleEcho(w, r)
	case "/dns":
		h.HandleDNS(w, r)
	case "/ping", "/health":
		h.HandleHealth(w, r)
	default:
		if r.URL.Path == "/" {
			h.HandleIndex(w, r)
		} else if len(r.URL.Path) > 8 && r.URL.Path[:8] == "/header/" {
			h.HandleHeaderByKey(w, r)
		} else {
			h.HandleIndex(w, r)
		}
	}
}

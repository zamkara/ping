package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ping/config"
	"ping/pkg/handlers"
)

func main() {
	cfg := config.Load()

	h := handlers.NewHandler(cfg)

	mux := http.NewServeMux()

	// Register Data Endpoints
	mux.HandleFunc("/", h.HandleIndex)
	mux.HandleFunc("/json", h.HandleJSON)
	mux.HandleFunc("/ip", h.HandleIP)
	mux.HandleFunc("/headers", h.HandleHeaders)
	mux.HandleFunc("/header/", h.HandleHeaderByKey)
	mux.HandleFunc("/user-agent", h.HandleUserAgent)
	mux.HandleFunc("/ua", h.HandleUserAgent)
	mux.HandleFunc("/geo", h.HandleGeo)
	mux.HandleFunc("/network", h.HandleNetwork)
	mux.HandleFunc("/security", h.HandleSecurity)
	mux.HandleFunc("/tls", h.HandleTLS)
	mux.HandleFunc("/echo", h.HandleEcho)
	mux.HandleFunc("/ws", h.HandleWebSocket)
	mux.HandleFunc("/dns", h.HandleDNS)
	mux.HandleFunc("/ping", h.HandleHealth)
	mux.HandleFunc("/health", h.HandleHealth)

	serverAddr := fmt.Sprintf(":%d", cfg.Port)
	server := &http.Server{
		Addr:         serverAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("🚀 Ping data engine listening on http://localhost%s", serverAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down Ping server gracefully...")
}

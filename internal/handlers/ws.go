package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"ping/internal/geo"
	"ping/internal/models"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for latency tool
	},
}

func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	clientIP, _ := geo.GetClientIP(r)

	for {
		var msg models.LatencyPingMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			break
		}

		if msg.Type == "ping" {
			msg.Type = "pong"
			msg.ServerTs = time.Now().UnixNano() / int64(time.Millisecond)
			msg.ClientIP = clientIP

			err = conn.WriteJSON(msg)
			if err != nil {
				break
			}
		}
	}
}

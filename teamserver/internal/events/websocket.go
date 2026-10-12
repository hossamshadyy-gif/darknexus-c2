package events

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // allow all origins in dev, restrict in production
	},
}

// Event represents a real-time event pushed to operators
type Event struct {
	Type      string      `json:"type"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// Hub manages WebSocket connections and broadcasts
type Hub struct {
	clients    map[*websocket.Conn]bool
	mu         sync.RWMutex
	broadcast  chan Event
}

var hub *Hub
var once sync.Once

// GetHub returns the singleton event hub
func GetHub() *Hub {
	once.Do(func() {
		hub = &Hub{
			clients:   make(map[*websocket.Conn]bool),
			broadcast: make(chan Event, 256),
		}
		go hub.run()
	})
	return hub
}

func (h *Hub) run() {
	for event := range h.broadcast {
		data, err := json.Marshal(event)
		if err != nil {
			log.Printf("[events] marshal error: %v", err)
			continue
		}

		h.mu.RLock()
		for conn := range h.clients {
			err := conn.WriteMessage(websocket.TextMessage, data)
			if err != nil {
				log.Printf("[events] write error: %v", err)
				conn.Close()
				delete(h.clients, conn)
			}
		}
		h.mu.RUnlock()
	}
}

// AuthFunc is a function that validates a token string and returns an error if invalid
type AuthFunc func(token string) error

// authValidator holds the WebSocket auth validator. Set via SetAuthValidator.
var authValidator AuthFunc

// SetAuthValidator sets the function used to authenticate WebSocket connections
func SetAuthValidator(fn AuthFunc) {
	authValidator = fn
}

// HandleWebSocket upgrades HTTP to WebSocket and registers the client
func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// authenticate: check token from query param or Authorization header
	if authValidator != nil {
		token := r.URL.Query().Get("token")
		if token == "" {
			tokenStr := r.Header.Get("Authorization")
			if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
				token = tokenStr[7:]
			}
		}
		if token == "" {
			http.Error(w, `{"error":"missing authentication"}`, http.StatusUnauthorized)
			return
		}
		if err := authValidator(token); err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[events] upgrade error: %v", err)
		return
	}

	h.mu.Lock()
	h.clients[conn] = true
	h.mu.Unlock()

	log.Printf("[events] new client connected (%d total)", len(h.clients))

	// keep connection alive, read pongs
	go func() {
		defer func() {
			h.mu.Lock()
			delete(h.clients, conn)
			h.mu.Unlock()
			conn.Close()
			log.Printf("[events] client disconnected (%d total)", len(h.clients))
		}()
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				break
			}
		}
	}()
}

// Emit sends an event to all connected WebSocket clients
func Emit(eventType string, data interface{}) {
	GetHub().broadcast <- Event{
		Type:      eventType,
		Data:      data,
		Timestamp: time.Now(),
	}
}

// Event types
const (
	EventImplantNew      = "implant.new"
	EventImplantCheckin  = "implant.checkin"
	EventImplantDead     = "implant.dead"
	EventImplantRemoved  = "implant.removed"
	EventTaskCreated     = "task.created"
	EventTaskCompleted   = "task.completed"
	EventListenerStarted = "listener.started"
	EventListenerStopped = "listener.stopped"
	EventOperatorLogin   = "operator.login"
)

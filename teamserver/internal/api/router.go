package api

import (
	"context"
	"net/http"

	"github.com/darknexus/teamserver/internal/auth"
	"github.com/darknexus/teamserver/internal/db"
	"github.com/darknexus/teamserver/internal/events"
	"github.com/darknexus/teamserver/internal/implant"
	"github.com/gorilla/mux"
)

type contextKey string

const (
	ctxOperator contextKey = "operator"
	ctxRole     contextKey = "role"
)

// Server holds the API server state
type Server struct {
	Router   *mux.Router
	DB       *db.Database
	Registry *implant.Registry
}

func NewServer(database *db.Database, registry *implant.Registry) *Server {
	s := &Server{
		Router:   mux.NewRouter(),
		DB:       database,
		Registry: registry,
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	// public routes
	s.Router.HandleFunc("/api/auth/login", s.handleLogin).Methods("POST")
	s.Router.HandleFunc("/api/auth/setup", s.handleSetup).Methods("POST")

	// websocket
	s.Router.HandleFunc("/api/ws", events.GetHub().HandleWebSocket)

	// protected routes
	api := s.Router.PathPrefix("/api").Subrouter()
	api.Use(s.authMiddleware)

	// operators (admin only)
	api.HandleFunc("/operators", s.handleListOperators).Methods("GET")
	admin := api.PathPrefix("").Subrouter()
	admin.Use(s.adminOnly)
	admin.HandleFunc("/operators", s.handleCreateOperator).Methods("POST")
	admin.HandleFunc("/operators/{id}", s.handleDeleteOperator).Methods("DELETE")
	admin.HandleFunc("/operators/{id}/password", s.handleChangePassword).Methods("PUT")
	admin.HandleFunc("/operators/{id}/role", s.handleChangeRole).Methods("PUT")

	// implants
	api.HandleFunc("/implants", s.handleListImplants).Methods("GET")
	api.HandleFunc("/implants/{id}", s.handleGetImplant).Methods("GET")
	api.HandleFunc("/implants/{id}", s.handleRemoveImplant).Methods("DELETE")
	api.HandleFunc("/implants/{id}/kill", s.handleKillImplant).Methods("POST")

	// tasks
	api.HandleFunc("/implants/{id}/tasks", s.handleListTasks).Methods("GET")
	api.HandleFunc("/implants/{id}/tasks", s.handleCreateTask).Methods("POST")

	// listeners
	api.HandleFunc("/listeners", s.handleListListeners).Methods("GET")
	api.HandleFunc("/listeners", s.handleCreateListener).Methods("POST")
	api.HandleFunc("/listeners/{id}/stop", s.handleStopListener).Methods("POST")
	api.HandleFunc("/listeners/{id}", s.handleRemoveListener).Methods("DELETE")

	// loot
	api.HandleFunc("/loot", s.handleListLoot).Methods("GET")

	// events
	api.HandleFunc("/events", s.handleListEvents).Methods("GET")

	// dashboard stats
	api.HandleFunc("/dashboard", s.handleDashboard).Methods("GET")
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		// strip "Bearer " prefix
		if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
			tokenStr = tokenStr[7:]
		}

		claims, err := auth.ValidateToken(tokenStr)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		// store claims in request context
		ctx := context.WithValue(r.Context(), ctxOperator, claims.Username)
		ctx = context.WithValue(ctx, ctxRole, claims.Role)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getOperator extracts the authenticated operator username from the request context
func getOperator(r *http.Request) string {
	if v, ok := r.Context().Value(ctxOperator).(string); ok {
		return v
	}
	return ""
}

// getRole extracts the authenticated operator role from the request context
func getRole(r *http.Request) string {
	if v, ok := r.Context().Value(ctxRole).(string); ok {
		return v
	}
	return ""
}

// adminOnly is middleware that restricts access to admin role
func (s *Server) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := getRole(r)
		if role != "admin" {
			jsonError(w, http.StatusForbidden, "admin access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CORS middleware for development
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

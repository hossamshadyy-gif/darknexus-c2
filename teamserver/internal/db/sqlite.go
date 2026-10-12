package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	conn *sql.DB
}

// Implant represents a registered implant/beacon
type Implant struct {
	ID         string    `json:"id"`
	Hostname   string    `json:"hostname"`
	Username   string    `json:"username"`
	Domain     string    `json:"domain"`
	InternalIP string    `json:"internal_ip"`
	ExternalIP string    `json:"external_ip"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	PID        int       `json:"pid"`
	ProcessName string   `json:"process_name"`
	Sleep      int       `json:"sleep"`
	Jitter     int       `json:"jitter"`
	Channel    string    `json:"channel"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Alive      bool      `json:"alive"`
}

// Task represents a queued command for an implant
type Task struct {
	ID        string    `json:"id"`
	ImplantID string    `json:"implant_id"`
	Command   string    `json:"command"`
	Args      string    `json:"args"`
	Status    string    `json:"status"` // pending, sent, completed, failed
	Result    string    `json:"result"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Operator  string    `json:"operator"`
}

// Listener represents a running listener
type Listener struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"` // https, dns, smb
	BindAddr string `json:"bind_addr"`
	Port     int    `json:"port"`
	Status   string `json:"status"` // running, stopped
	Profile  string `json:"profile"`
}

// Operator represents an authenticated user
type Operator struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	PassHash string `json:"-"`
	Role     string `json:"role"` // admin, operator, viewer
}

// Loot represents captured credentials or data
type Loot struct {
	ID        string    `json:"id"`
	ImplantID string    `json:"implant_id"`
	Type      string    `json:"type"` // credential, file, screenshot
	Data      string    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
}

func NewDatabase(path string) (*Database, error) {
	conn, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &Database{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return db, nil
}

func (db *Database) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS implants (
		id TEXT PRIMARY KEY,
		hostname TEXT NOT NULL,
		username TEXT NOT NULL,
		domain TEXT DEFAULT '',
		internal_ip TEXT DEFAULT '',
		external_ip TEXT DEFAULT '',
		os TEXT DEFAULT '',
		arch TEXT DEFAULT '',
		pid INTEGER DEFAULT 0,
		process_name TEXT DEFAULT '',
		sleep INTEGER DEFAULT 5,
		jitter INTEGER DEFAULT 10,
		channel TEXT DEFAULT 'https',
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		alive INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS tasks (
		id TEXT PRIMARY KEY,
		implant_id TEXT NOT NULL,
		command TEXT NOT NULL,
		args TEXT DEFAULT '',
		status TEXT DEFAULT 'pending',
		result TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		operator TEXT DEFAULT '',
		FOREIGN KEY (implant_id) REFERENCES implants(id)
	);

	CREATE TABLE IF NOT EXISTS listeners (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		bind_addr TEXT DEFAULT '0.0.0.0',
		port INTEGER NOT NULL,
		status TEXT DEFAULT 'stopped',
		profile TEXT DEFAULT 'default'
	);

	CREATE TABLE IF NOT EXISTS operators (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		pass_hash TEXT NOT NULL,
		role TEXT DEFAULT 'operator'
	);

	CREATE TABLE IF NOT EXISTS loot (
		id TEXT PRIMARY KEY,
		implant_id TEXT NOT NULL,
		type TEXT NOT NULL,
		data TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (implant_id) REFERENCES implants(id)
	);

	CREATE TABLE IF NOT EXISTS event_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		operator TEXT DEFAULT '',
		event_type TEXT NOT NULL,
		message TEXT NOT NULL,
		implant_id TEXT DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_tasks_implant ON tasks(implant_id);
	CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
	CREATE INDEX IF NOT EXISTS idx_loot_implant ON loot(implant_id);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON event_log(timestamp);
	`
	_, err := db.conn.Exec(schema)
	return err
}

// --- Implant CRUD ---

func (db *Database) RegisterImplant(imp *Implant) error {
	_, err := db.conn.Exec(`
		INSERT OR REPLACE INTO implants
		(id, hostname, username, domain, internal_ip, external_ip, os, arch, pid, process_name, sleep, jitter, channel, first_seen, last_seen, alive)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		imp.ID, imp.Hostname, imp.Username, imp.Domain, imp.InternalIP, imp.ExternalIP,
		imp.OS, imp.Arch, imp.PID, imp.ProcessName, imp.Sleep, imp.Jitter, imp.Channel,
		imp.FirstSeen, imp.LastSeen, imp.Alive,
	)
	return err
}

func (db *Database) UpdateImplantLastSeen(id string) error {
	_, err := db.conn.Exec(`UPDATE implants SET last_seen = ?, alive = 1 WHERE id = ?`, time.Now(), id)
	return err
}

func (db *Database) GetImplant(id string) (*Implant, error) {
	imp := &Implant{}
	err := db.conn.QueryRow(`SELECT id, hostname, username, domain, internal_ip, external_ip, os, arch, pid, process_name, sleep, jitter, channel, first_seen, last_seen, alive FROM implants WHERE id = ?`, id).
		Scan(&imp.ID, &imp.Hostname, &imp.Username, &imp.Domain, &imp.InternalIP, &imp.ExternalIP, &imp.OS, &imp.Arch, &imp.PID, &imp.ProcessName, &imp.Sleep, &imp.Jitter, &imp.Channel, &imp.FirstSeen, &imp.LastSeen, &imp.Alive)
	if err != nil {
		return nil, err
	}
	return imp, nil
}

func (db *Database) ListImplants() ([]Implant, error) {
	rows, err := db.conn.Query(`SELECT id, hostname, username, domain, internal_ip, external_ip, os, arch, pid, process_name, sleep, jitter, channel, first_seen, last_seen, alive FROM implants ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var implants []Implant
	for rows.Next() {
		var imp Implant
		if err := rows.Scan(&imp.ID, &imp.Hostname, &imp.Username, &imp.Domain, &imp.InternalIP, &imp.ExternalIP, &imp.OS, &imp.Arch, &imp.PID, &imp.ProcessName, &imp.Sleep, &imp.Jitter, &imp.Channel, &imp.FirstSeen, &imp.LastSeen, &imp.Alive); err != nil {
			return nil, err
		}
		implants = append(implants, imp)
	}
	return implants, nil
}

func (db *Database) MarkImplantDead(id string) error {
	_, err := db.conn.Exec(`UPDATE implants SET alive = 0 WHERE id = ?`, id)
	return err
}

func (db *Database) RemoveImplant(id string) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	tx.Exec(`DELETE FROM tasks WHERE implant_id = ?`, id)
	tx.Exec(`DELETE FROM loot WHERE implant_id = ?`, id)
	tx.Exec(`DELETE FROM implants WHERE id = ?`, id)
	return tx.Commit()
}

// --- Task CRUD ---

func (db *Database) CreateTask(task *Task) error {
	_, err := db.conn.Exec(`
		INSERT INTO tasks (id, implant_id, command, args, status, operator, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		task.ID, task.ImplantID, task.Command, task.Args, task.Status, task.Operator, task.CreatedAt, task.UpdatedAt,
	)
	return err
}

func (db *Database) GetPendingTasks(implantID string) ([]Task, error) {
	rows, err := db.conn.Query(`SELECT id, implant_id, command, args, status, operator FROM tasks WHERE implant_id = ? AND status = 'pending' ORDER BY created_at ASC`, implantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.ImplantID, &t.Command, &t.Args, &t.Status, &t.Operator); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

func (db *Database) UpdateTaskStatus(id, status, result string) error {
	_, err := db.conn.Exec(`UPDATE tasks SET status = ?, result = ?, updated_at = ? WHERE id = ?`, status, result, time.Now(), id)
	return err
}

func (db *Database) GetTasksByImplant(implantID string) ([]Task, error) {
	rows, err := db.conn.Query(`SELECT id, implant_id, command, args, status, result, created_at, updated_at, operator FROM tasks WHERE implant_id = ? ORDER BY created_at DESC LIMIT 100`, implantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.ImplantID, &t.Command, &t.Args, &t.Status, &t.Result, &t.CreatedAt, &t.UpdatedAt, &t.Operator); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

// --- Listener CRUD ---

func (db *Database) SaveListener(l *Listener) error {
	_, err := db.conn.Exec(`INSERT OR REPLACE INTO listeners (id, name, type, bind_addr, port, status, profile) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.Name, l.Type, l.BindAddr, l.Port, l.Status, l.Profile)
	return err
}

func (db *Database) ListListeners() ([]Listener, error) {
	rows, err := db.conn.Query(`SELECT id, name, type, bind_addr, port, status, profile FROM listeners`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var listeners []Listener
	for rows.Next() {
		var l Listener
		if err := rows.Scan(&l.ID, &l.Name, &l.Type, &l.BindAddr, &l.Port, &l.Status, &l.Profile); err != nil {
			return nil, err
		}
		listeners = append(listeners, l)
	}
	return listeners, nil
}

func (db *Database) GetListener(id string) (*Listener, error) {
	l := &Listener{}
	err := db.conn.QueryRow(`SELECT id, name, type, bind_addr, port, status, profile FROM listeners WHERE id = ?`, id).
		Scan(&l.ID, &l.Name, &l.Type, &l.BindAddr, &l.Port, &l.Status, &l.Profile)
	if err != nil {
		return nil, err
	}
	return l, nil
}

func (db *Database) UpdateListenerStatus(id, status string) error {
	_, err := db.conn.Exec(`UPDATE listeners SET status = ? WHERE id = ?`, status, id)
	return err
}

func (db *Database) RemoveListener(id string) error {
	_, err := db.conn.Exec(`DELETE FROM listeners WHERE id = ?`, id)
	return err
}

// --- Operator CRUD ---

func (db *Database) CreateOperator(op *Operator) error {
	_, err := db.conn.Exec(`INSERT INTO operators (id, username, pass_hash, role) VALUES (?, ?, ?, ?)`,
		op.ID, op.Username, op.PassHash, op.Role)
	return err
}

func (db *Database) GetOperatorByID(id string) (*Operator, error) {
	op := &Operator{}
	err := db.conn.QueryRow(`SELECT id, username, pass_hash, role FROM operators WHERE id = ?`, id).
		Scan(&op.ID, &op.Username, &op.PassHash, &op.Role)
	if err != nil {
		return nil, err
	}
	return op, nil
}

func (db *Database) GetOperatorByUsername(username string) (*Operator, error) {
	op := &Operator{}
	err := db.conn.QueryRow(`SELECT id, username, pass_hash, role FROM operators WHERE username = ?`, username).
		Scan(&op.ID, &op.Username, &op.PassHash, &op.Role)
	if err != nil {
		return nil, err
	}
	return op, nil
}

func (db *Database) OperatorCount() (int, error) {
	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM operators`).Scan(&count)
	return count, err
}

func (db *Database) ListOperators() ([]Operator, error) {
	rows, err := db.conn.Query(`SELECT id, username, pass_hash, role FROM operators ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var operators []Operator
	for rows.Next() {
		var op Operator
		if err := rows.Scan(&op.ID, &op.Username, &op.PassHash, &op.Role); err != nil {
			return nil, err
		}
		operators = append(operators, op)
	}
	return operators, nil
}

func (db *Database) DeleteOperator(id string) error {
	_, err := db.conn.Exec(`DELETE FROM operators WHERE id = ?`, id)
	return err
}

func (db *Database) UpdateOperatorPassword(id, passHash string) error {
	_, err := db.conn.Exec(`UPDATE operators SET pass_hash = ? WHERE id = ?`, passHash, id)
	return err
}

func (db *Database) UpdateOperatorRole(id, role string) error {
	_, err := db.conn.Exec(`UPDATE operators SET role = ? WHERE id = ?`, role, id)
	return err
}

// --- Loot ---

func (db *Database) SaveLoot(l *Loot) error {
	_, err := db.conn.Exec(`INSERT INTO loot (id, implant_id, type, data, created_at) VALUES (?, ?, ?, ?, ?)`,
		l.ID, l.ImplantID, l.Type, l.Data, l.CreatedAt)
	return err
}

func (db *Database) ListLoot() ([]Loot, error) {
	rows, err := db.conn.Query(`SELECT id, implant_id, type, data, created_at FROM loot ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var loot []Loot
	for rows.Next() {
		var l Loot
		if err := rows.Scan(&l.ID, &l.ImplantID, &l.Type, &l.Data, &l.CreatedAt); err != nil {
			return nil, err
		}
		loot = append(loot, l)
	}
	return loot, nil
}

// --- Event Log ---

func (db *Database) LogEvent(operator, eventType, message, implantID string) error {
	_, err := db.conn.Exec(`INSERT INTO event_log (operator, event_type, message, implant_id) VALUES (?, ?, ?, ?)`,
		operator, eventType, message, implantID)
	return err
}

func (db *Database) GetEvents(limit int) ([]map[string]interface{}, error) {
	rows, err := db.conn.Query(`SELECT id, timestamp, operator, event_type, message, implant_id FROM event_log ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var id int
		var ts time.Time
		var op, et, msg, iid string
		if err := rows.Scan(&id, &ts, &op, &et, &msg, &iid); err != nil {
			return nil, err
		}
		events = append(events, map[string]interface{}{
			"id": id, "timestamp": ts, "operator": op,
			"type": et, "message": msg, "implant_id": iid,
		})
	}
	return events, nil
}

func (db *Database) Close() error {
	return db.conn.Close()
}

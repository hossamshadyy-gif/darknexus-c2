package statemachine

import (
	"fmt"
	"log"
	"sync"
)

type StateID string

const (
	StateInit       StateID = "init"
	StateHandshake  StateID = "handshake"
	StateAuth       StateID = "auth"
	StateReady      StateID = "ready"
	StateData       StateID = "data"
	StateError      StateID = "error"
	StateClosed     StateID = "closed"
)

type TransitionResult struct {
	NextState StateID
	Response  []byte
	Error     error
}

type TransitionFunc func(input []byte, response []byte) TransitionResult

type State struct {
	ID          StateID
	Transitions map[string]TransitionFunc
	OnEnter     func()
	OnExit      func()
	Fuzzable    bool
	Templates   [][]byte
}

type StateMachine struct {
	states       map[StateID]*State
	currentState StateID
	history      []StateID
	mu           sync.RWMutex
	verbose      bool
}

func New(verbose bool) *StateMachine {
	return &StateMachine{
		states:       make(map[StateID]*State),
		currentState: StateInit,
		verbose:      verbose,
	}
}

func (sm *StateMachine) AddState(state *State) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.states[state.ID] = state
}

func (sm *StateMachine) CurrentState() StateID {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentState
}

func (sm *StateMachine) IsFuzzable() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	state, ok := sm.states[sm.currentState]
	if !ok {
		return false
	}
	return state.Fuzzable
}

func (sm *StateMachine) GetTemplates() [][]byte {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	state, ok := sm.states[sm.currentState]
	if !ok {
		return nil
	}
	return state.Templates
}

func (sm *StateMachine) Transition(event string, input []byte, response []byte) (TransitionResult, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	state, ok := sm.states[sm.currentState]
	if !ok {
		return TransitionResult{}, fmt.Errorf("unknown current state: %s", sm.currentState)
	}

	transition, ok := state.Transitions[event]
	if !ok {
		return TransitionResult{}, fmt.Errorf("no transition for event %q in state %s", event, sm.currentState)
	}

	result := transition(input, response)

	if result.NextState != "" && result.NextState != sm.currentState {
		if state.OnExit != nil {
			state.OnExit()
		}

		sm.history = append(sm.history, sm.currentState)
		sm.currentState = result.NextState

		if sm.verbose {
			log.Printf("[statemachine] %s -> %s (event: %s)", sm.history[len(sm.history)-1], sm.currentState, event)
		}

		if nextState, ok := sm.states[sm.currentState]; ok && nextState.OnEnter != nil {
			nextState.OnEnter()
		}
	}

	return result, nil
}

func (sm *StateMachine) Reset() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.currentState = StateInit
	sm.history = nil
}

func (sm *StateMachine) History() []StateID {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	h := make([]StateID, len(sm.history))
	copy(h, sm.history)
	return h
}

func (sm *StateMachine) FuzzableStates() []StateID {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	var result []StateID
	for id, state := range sm.states {
		if state.Fuzzable {
			result = append(result, id)
		}
	}
	return result
}

func HTTPStateMachine(verbose bool) *StateMachine {
	sm := New(verbose)

	sm.AddState(&State{
		ID:       StateInit,
		Fuzzable: false,
		Transitions: map[string]TransitionFunc{
			"connect": func(input, response []byte) TransitionResult {
				return TransitionResult{NextState: StateReady}
			},
		},
	})

	sm.AddState(&State{
		ID:       StateReady,
		Fuzzable: true,
		Templates: [][]byte{
			[]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			[]byte("POST /api/data HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"),
			[]byte("OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n"),
		},
		Transitions: map[string]TransitionFunc{
			"send": func(input, response []byte) TransitionResult {
				if len(response) == 0 {
					return TransitionResult{NextState: StateError}
				}
				return TransitionResult{NextState: StateData, Response: response}
			},
			"error": func(input, response []byte) TransitionResult {
				return TransitionResult{NextState: StateError}
			},
		},
	})

	sm.AddState(&State{
		ID:       StateData,
		Fuzzable: true,
		Transitions: map[string]TransitionFunc{
			"continue": func(input, response []byte) TransitionResult {
				return TransitionResult{NextState: StateReady}
			},
			"close": func(input, response []byte) TransitionResult {
				return TransitionResult{NextState: StateClosed}
			},
		},
	})

	sm.AddState(&State{
		ID:       StateError,
		Fuzzable: false,
		Transitions: map[string]TransitionFunc{
			"reset": func(input, response []byte) TransitionResult {
				return TransitionResult{NextState: StateInit}
			},
		},
	})

	sm.AddState(&State{
		ID:       StateClosed,
		Fuzzable: false,
		Transitions: map[string]TransitionFunc{
			"reconnect": func(input, response []byte) TransitionResult {
				return TransitionResult{NextState: StateInit}
			},
		},
	})

	return sm
}

func DNSStateMachine(verbose bool) *StateMachine {
	sm := New(verbose)

	sm.AddState(&State{
		ID:       StateInit,
		Fuzzable: false,
		Transitions: map[string]TransitionFunc{
			"connect": func(input, response []byte) TransitionResult {
				return TransitionResult{NextState: StateReady}
			},
		},
	})

	sm.AddState(&State{
		ID:       StateReady,
		Fuzzable: true,
		Templates: [][]byte{
			{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
				0x00, 0x01, 0x00, 0x01},
			{0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x04, 't', 'e', 's', 't', 0x03, 'c', '2', 'c', 0x00,
				0x00, 0x10, 0x00, 0x01},
		},
		Transitions: map[string]TransitionFunc{
			"query": func(input, response []byte) TransitionResult {
				if len(response) == 0 {
					return TransitionResult{NextState: StateError}
				}
				return TransitionResult{NextState: StateData, Response: response}
			},
		},
	})

	sm.AddState(&State{
		ID:       StateData,
		Fuzzable: true,
		Transitions: map[string]TransitionFunc{
			"next_query": func(input, response []byte) TransitionResult {
				return TransitionResult{NextState: StateReady}
			},
		},
	})

	sm.AddState(&State{
		ID:       StateError,
		Fuzzable: false,
		Transitions: map[string]TransitionFunc{
			"reset": func(input, response []byte) TransitionResult {
				return TransitionResult{NextState: StateInit}
			},
		},
	})

	return sm
}

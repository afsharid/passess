package harness

import (
	"fmt"
	"slices"
)

// Desired is an MCP server passess wants a harness to start.
type Desired struct {
	Name string
	Argv []string // passess mcp-exec NAME, with passess as an absolute path
}

// Server states.
const (
	StateOK        = "ok"        // present and pointing at passess
	StateMissing   = "missing"   // not in the harness config
	StateDrift     = "drift"     // points at passess, but a different binary or arguments
	StateUnmanaged = "unmanaged" // an entry of that name exists and is not passess's
)

// ServerStatus is one desired server's state in one harness.
type ServerStatus struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// Action is one change to a harness.
type Action struct {
	Kind     string     `json:"kind"` // add | replace | remove
	Server   string     `json:"server"`
	Commands [][]string `json:"commands"`
}

// Plan compares what passess wants with what the harness has.
func Plan(a Adapter, desired []Desired, entries []Entry, force bool) ([]ServerStatus, []Action) {
	byName := map[string]Entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	var statuses []ServerStatus
	var actions []Action
	for _, d := range desired {
		e, ok := byName[d.Name]
		self := d.Argv[0]
		switch {
		case !ok:
			statuses = append(statuses, ServerStatus{Name: d.Name, State: StateMissing})
			actions = append(actions, Action{Kind: "add", Server: d.Name, Commands: [][]string{a.AddCommand(d.Name, d.Argv)}})
		case e.ManagedBy(self) && e.Command == self && slices.Equal(e.Args, d.Argv[1:]):
			statuses = append(statuses, ServerStatus{Name: d.Name, State: StateOK})
		case e.ManagedBy(self):
			statuses = append(statuses, ServerStatus{Name: d.Name, State: StateDrift,
				Detail: fmt.Sprintf("runs %s; passess is now %s", e.Command, d.Argv[0])})
			actions = append(actions, replace(a, d))
		default:
			st := ServerStatus{Name: d.Name, State: StateUnmanaged,
				Detail: "an entry with this name exists and does not run passess; --force replaces it"}
			if len(e.Leaks) > 0 {
				st.Detail = fmt.Sprintf("an entry with this name holds credentials in clear (%v); --force replaces it", e.Leaks)
			}
			statuses = append(statuses, st)
			if force {
				actions = append(actions, replace(a, d))
			}
		}
	}
	return statuses, actions
}

func replace(a Adapter, d Desired) Action {
	return Action{Kind: "replace", Server: d.Name, Commands: [][]string{a.RemoveCommand(d.Name), a.AddCommand(d.Name, d.Argv)}}
}

// PlanRemoval removes every entry that runs passess (self or any binary named passess).
func PlanRemoval(a Adapter, entries []Entry, self string) []Action {
	var actions []Action
	for _, e := range entries {
		if e.ManagedBy(self) {
			actions = append(actions, Action{Kind: "remove", Server: e.Name, Commands: [][]string{a.RemoveCommand(e.Name)}})
		}
	}
	return actions
}

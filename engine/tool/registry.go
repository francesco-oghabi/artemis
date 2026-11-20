package tool

import (
	"strings"

	"artemis/engine/llm"
)

// Registry is an ordered, name-indexed collection of tools (FR-04.3).
type Registry struct {
	order  []string
	byName map[string]CoreTool
}

// NewRegistry builds a registry from tools, preserving order.
func NewRegistry(tools ...CoreTool) *Registry {
	r := &Registry{byName: map[string]CoreTool{}}
	for _, t := range tools {
		r.Add(t)
	}
	return r
}

// Add registers a tool, replacing any existing one with the same name.
func (r *Registry) Add(t CoreTool) {
	if _, ok := r.byName[t.Name()]; !ok {
		r.order = append(r.order, t.Name())
	}
	r.byName[t.Name()] = t
}

// Get returns the named tool.
func (r *Registry) Get(name string) (CoreTool, bool) {
	t, ok := r.byName[name]
	return t, ok
}

// normalizeToolName lowercases a name and drops every non-alphanumeric rune, so
// "Add_intent", "add-intent" and "addintent" all collapse to "addintent". Used
// only as a tolerant fallback when an exact lookup misses.
func normalizeToolName(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Resolve returns the tool for name. It first tries an exact match; failing that,
// it falls back to a case- and separator-insensitive match, so a weak model that
// emits "Add_intent" or "GraphOverview" still reaches add_intent / graph_overview.
// The fallback fires ONLY when exactly one registered tool normalizes to the same
// string, so it never guesses between ambiguous names (a genuinely unknown or
// wrong-role tool still misses). Callers should use the returned tool's Name() as
// the canonical name for permission checks and logging.
func (r *Registry) Resolve(name string) (CoreTool, bool) {
	if t, ok := r.byName[name]; ok {
		return t, true
	}
	norm := normalizeToolName(name)
	if norm == "" {
		return nil, false
	}
	var match CoreTool
	n := 0
	for key, t := range r.byName {
		if normalizeToolName(key) == norm {
			match, n = t, n+1
		}
	}
	if n == 1 {
		return match, true
	}
	return nil, false
}

// List returns all tools in registration order.
func (r *Registry) List() []CoreTool {
	out := make([]CoreTool, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.byName[n])
	}
	return out
}

// Schemas renders the registry into provider-facing tool definitions, merging
// each tool's extended Prompt into its description.
func (r *Registry) Schemas() []llm.ToolSchema {
	tools := r.List()
	out := make([]llm.ToolSchema, 0, len(tools))
	for _, t := range tools {
		desc := t.Description()
		if p := t.Prompt(); p != "" {
			desc += "\n\n" + p
		}
		out = append(out, llm.ToolSchema{Name: t.Name(), Description: desc, InputSchema: t.InputSchema()})
	}
	return out
}

// DefaultTools returns the core toolset every agent gets: the file/shell tools
// (Read, Write, Edit, MultiEdit, LS, Glob, Grep, Bash) plus Sleep — a small
// context-cancellable wait that pairs with background execution. Network and
// stateful tools (WebFetch, TodoWrite) remain opt-in via their own constructors.
func DefaultTools() []CoreTool {
	return []CoreTool{
		NewRead(), NewWrite(), NewEdit(), NewMultiEdit(), NewLS(), NewGlob(), NewGrep(), NewBash(),
		NewSleep(),
	}
}

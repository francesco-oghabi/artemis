package agent

import (
	"strings"
	"testing"
)

func TestRenderSystemOverrideAndFallback(t *testing.T) {
	t.Cleanup(func() { PromptOverride = nil })

	// no override → built-in default
	PromptOverride = nil
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "g"}); got != "DEFAULT" {
		t.Fatalf("no override should give default, got %q", got)
	}

	// override → rendered with vars
	PromptOverride = func(k string) (string, bool) {
		if k == "planner" {
			return "Goal:{{.Goal}} Scope:{{.Scope}}", true
		}
		return "", false
	}
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "take X", Scope: "*.x.com"}); got != "Goal:take X Scope:*.x.com" {
		t.Fatalf("override render: %q", got)
	}

	// override referencing a non-catalog var → execution error → fallback to default
	PromptOverride = func(k string) (string, bool) { return "{{.NotInCatalog}}", true }
	if got := renderSystem("planner", "DEFAULT", PlannerVars{Goal: "x"}); got != "DEFAULT" {
		t.Fatalf("bad var should fall back to default, got %q", got)
	}

	// full plannerSystem path: DB body [A] is honored, then the code-owned tail
	// [C] (artifactSpec) is ALWAYS appended: editing the body can't drop it.
	PromptOverride = func(k string) (string, bool) { return "PLANNER {{.Goal}}", true }
	got := plannerSystem("take X", "/data")
	if !strings.HasPrefix(got, "PLANNER take X") {
		t.Fatalf("plannerSystem body not honored: %q", got)
	}
	if !strings.Contains(got, "Intermediate-artifact output convention") || !strings.Contains(got, "/data") {
		t.Fatalf("plannerSystem missing code-owned artifact tail: %q", got)
	}

	// worker dual-text via {{if .ProxyAddr}} in a user template, plus the code tail:
	// [B] trafficTool present only with a proxy, [C] artifact spec always present.
	PromptOverride = func(k string) (string, bool) {
		return "{{if .ProxyAddr}}via proxy {{.ProxyAddr}}{{else}}manual{{end}}", true
	}
	withProxy := workerSystem("127.0.0.1:8080", "/data")
	if !strings.HasPrefix(withProxy, "via proxy 127.0.0.1:8080") {
		t.Fatalf("worker proxy branch body: %q", withProxy)
	}
	if !strings.Contains(withProxy, "traffic_search") {
		t.Fatalf("worker with proxy should inject trafficTool: %q", withProxy)
	}
	if !strings.Contains(withProxy, "Intermediate-artifact output convention") {
		t.Fatalf("worker missing artifact tail: %q", withProxy)
	}
	noProxy := workerSystem("", "/data")
	if !strings.HasPrefix(noProxy, "manual") {
		t.Fatalf("worker no-proxy branch body: %q", noProxy)
	}
	if strings.Contains(noProxy, "traffic_search") {
		t.Fatalf("worker without proxy must NOT inject trafficTool: %q", noProxy)
	}
}

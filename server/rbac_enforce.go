package server

import (
	"net/http"
	"strings"

	"artemis/db"
)

// RBAC permission enforcement: route -> required-permission mapping.
// Safety valve: unmapped routes pass through (not turned into a 403, to avoid an omission breaking the platform); admin has all permissions and is never blocked.
// Switch: the settings key rbac.enforce (default true).

// isAdmin reports whether the current request was made by the built-in admin role. Used to further
// tighten "can execute commands on the host" high-risk operations (stdio MCP, command/script/shell
// custom tools): these are equivalent to host command execution and should only be used by admin,
// not delegated to operator via tool:write / mcp:write. When there is no authorization profile it is
// treated as non-admin (fail-closed).
func isAdmin(r *http.Request) bool {
	acc := CurrentAccess(r)
	if acc == nil {
		return false
	}
	for _, role := range acc.Roles {
		if role.ID == db.RBACRoleAdmin {
			return true
		}
	}
	return false
}

// hostExecToolKind reports whether a custom-tool kind executes commands/scripts on the host.
func hostExecToolKind(kind string) bool {
	switch kind {
	case "command", "script", "shell":
		return true
	}
	return false
}

// crudPerm maps an HTTP method to a read/write/delete permission.
func crudPerm(method, module string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return module + ":read"
	case http.MethodDelete:
		// Some modules have no ":delete" permission in the catalog (llm/agent/mcp/
		// tool/intercept) — for those, delete is gated by ":write". Without this
		// fallback even admin (whose perm set == the catalog) hits a nonexistent
		// "<module>:delete" and gets 403 on every delete.
		if p := module + ":delete"; db.RBACPermissions[p] != "" {
			return p
		}
		return module + ":write"
	default:
		return module + ":write"
	}
}

// permissionForRequest returns the permission required for the request; "" means unmapped (pass through).
func permissionForRequest(method, fullPath string) string {
	p := strings.TrimPrefix(fullPath, "/api")
	switch {
	case p == "/rbac/me":
		return "auth:self"
	case strings.HasPrefix(p, "/rbac"):
		if method == http.MethodGet {
			return "rbac:read"
		}
		return "rbac:write"
	case strings.HasPrefix(p, "/audit"):
		return "log:read"
	case strings.HasPrefix(p, "/logs"):
		return "log:read"
	case p == "/stats" || strings.HasPrefix(p, "/tokens"):
		return "dashboard:read"
	case strings.HasPrefix(p, "/tasks"), p == "/active", strings.HasPrefix(p, "/exploration"),
		strings.HasPrefix(p, "/chat"), strings.HasPrefix(p, "/conversations"):
		return crudPerm(method, "task")
	case strings.HasPrefix(p, "/findings"):
		return crudPerm(method, "finding")
	case strings.HasPrefix(p, "/traffic"):
		return "traffic:read"
	case strings.HasPrefix(p, "/assets"), strings.HasPrefix(p, "/companies"), strings.HasPrefix(p, "/sync"):
		return crudPerm(method, "asset")
	case strings.HasPrefix(p, "/llm"):
		return crudPerm(method, "llm")
	case strings.HasPrefix(p, "/agents"), strings.HasPrefix(p, "/triggers"), strings.HasPrefix(p, "/visibility"):
		return crudPerm(method, "agent")
	case strings.HasPrefix(p, "/mcp"):
		return crudPerm(method, "mcp")
	case strings.HasPrefix(p, "/skills"):
		return crudPerm(method, "skill")
	case strings.HasPrefix(p, "/tools"):
		return crudPerm(method, "tool")
	case strings.HasPrefix(p, "/intercept"):
		return crudPerm(method, "intercept")
	case strings.HasPrefix(p, "/knowledge"):
		// search/categories/logs are read actions even though search is POST.
		if p == "/knowledge/search" || p == "/knowledge/categories" || p == "/knowledge/logs" {
			return "knowledge:read"
		}
		return crudPerm(method, "knowledge")
	case strings.HasPrefix(p, "/settings"):
		return crudPerm(method, "config")
	case strings.HasPrefix(p, "/update"):
		// one-click update falls under system config: check/progress = config:read; apply/rollback(POST) = config:write
		// (config:write is granted to admin only, so the high-risk download-swap/rollback can only be triggered by admin).
		return crudPerm(method, "config")
	case strings.HasPrefix(p, "/report"):
		// covers /report, /reports, /report/generate, /report-settings,
		// /report-templates, /report-assets (all start with /report).
		// GET=read (view/download/status), POST/PUT=write (generate reports/manage template settings),
		// DELETE=delete (delete reports/templates). The report module has full read/write/delete.
		return crudPerm(method, "report")
	default:
		return "" // unmapped -> pass through
	}
}

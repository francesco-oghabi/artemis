package agent

import (
	"context"
	"encoding/json"
	"strings"

	actool "artemis/engine/tool"
	"artemis/db"
	"artemis/knowledge"
)

// =====================================================================
// Unified asset insertion tools
// =====================================================================

// SetAssetStore wires the asset store and company store onto this ToolSet
// so the insert_assets, add_company_scope, and list_assets tools are active.
func (t *ToolSet) SetAssetStore(as *db.AssetStore, cs *db.CompanyStore) {
	t.as = as
	t.cs = cs
	if t.kb == nil && as != nil { // server-level ToolSet (nil ExplorationStore): wire KB off the asset store's DB
		t.kb = knowledge.NewService(as.DB())
	}
}

// assetInputItem is one element of the insert_assets "assets" array.
type assetInputItem struct {
	Type string `json:"type"` // root_domain|ip|subdomain|app|service|endpoint

	// ---- root_domain / subdomain ----
	Domain      string   `json:"domain"`
	ICP         string   `json:"icp"`
	RecordType  string   `json:"record_type"`
	RecordValue []string `json:"record_value"`

	// ---- ip ----
	IP           string           `json:"ip"`
	BoundDomains []string         `json:"bound_domains"`
	OpenPorts    []db.PortService `json:"open_ports"`

	// ---- app ----
	AppName     string `json:"app_name"`
	BundleID    string `json:"bundle_id"`
	Category    string `json:"category"`
	Description string `json:"description"`
	AppICP      string `json:"app_icp"`
	CompanyID   *int64 `json:"company_id"` // explicit company link (app only; others auto-attribute via scope)

	// ---- service (http) ----
	URL           string           `json:"url"`
	Technologies  []string         `json:"technologies"`
	StatusCode    *int             `json:"status_code"`
	ContentLength *int64           `json:"content_length"`
	PageTitle     string           `json:"page_title"`
	FaviconMMH3   string           `json:"favicon_mmh3"`
	Auth          []map[string]any `json:"auth"`
	ServiceName   string           `json:"service_name"`
	ServiceIP     string           `json:"service_ip"` // optional enrichment IP

	// ---- service (other) ----
	Port  int    `json:"port"`
	Proto string `json:"proto"`

	// ---- endpoint ----
	Method string           `json:"method"`
	Params []map[string]any `json:"params"`
}

// insertAssets is the unified insert_assets agent tool.
func (t *ToolSet) insertAssets() actool.CoreTool {
	return writeTool(
		"insert_assets",
		"When you discover new assets, immediately batch-insert them into the asset store. Supports submitting multiple asset types at once: root_domain/ip/subdomain/app/service/endpoint.\n"+
			"Field notes for each asset:\n"+
			"• root_domain: domain (root domain, required), icp (ICP filing, optional)\n"+
			"• ip: ip (IP address, required), bound_domains ([domains]), open_ports ([{port,service}])\n"+
			"• subdomain: domain (subdomain, required), record_type (A/AAAA/CNAME etc.), record_value (record values), icp (optional)\n"+
			"• app: app_name (application name, required), bundle_id (bundle id, optional), category, description, app_icp, company_id (owning company id, optional)\n"+
			"• service(http): url (required), technologies ([fingerprints]), status_code, content_length, page_title, favicon_mmh3, auth ([{type,username,password,...}]), service_ip\n"+
			"• service(other): service_name (required), ip or domain (at least one), port (required), auth ([...])\n"+
			"• endpoint: url (required), method (required), params ([{location,name,value,type}]), service_ip\n"+
			"auth/technologies/params are all [append-merged] (append), they do not overwrite existing values.\n"+
			"Returns: {results:[{index,id,type}], errors:[{index,error}]}",
		obj(map[string]any{
			"task_id": intp("task id (optional, used to associate task_ids)"),
			"assets": map[string]any{
				"type":        "array",
				"description": "array of assets; each element corresponds to one asset record",
				"items": obj(map[string]any{
					"type": map[string]any{
						"type":        "string",
						"enum":        []string{"root_domain", "ip", "subdomain", "app", "service", "endpoint"},
						"description": "asset type",
					},
					// root_domain / subdomain
					"domain":       str("root domain or subdomain (required for root_domain/subdomain)"),
					"icp":          str("ICP filing number (optional)"),
					"record_type":  str("DNS record type: A/AAAA/CNAME/MX etc. (optional for subdomain)"),
					"record_value": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "list of DNS record values (optional for subdomain, e.g. [\"1.2.3.4\",\"2.3.4.5\"])",
					},
					// ip
					"ip":           str("IP address (required for the ip type; optional for service/endpoint types, used to associate an IP)"),
					"bound_domains": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "list of domains bound to this IP (optional for the ip type)",
					},
					"open_ports": map[string]any{
						"type":        "array",
						"description": "list of open ports (optional for the ip type)",
						"items": obj(map[string]any{
							"port":    intp("port number"),
							"service": str("service name, e.g. http/ssh/mysql etc. (optional)"),
						}, "port"),
					},
					// app
					"app_name":    str("application name (required for the app type)"),
					"bundle_id":   str("Bundle ID (optional for the app type)"),
					"category":    str("application category (optional)"),
					"description": str("application description (optional)"),
					"app_icp":     str("application ICP filing (optional)"),
					"company_id":  intp("owning company id (optional for the app type; an app cannot be auto-attributed via scope, so it must be specified explicitly. The id is returned by add_company_scope)"),
					// service (http)
					"url":           str("full URL, including protocol and port (required for an HTTP service; service_type is automatically set to http)"),
					"status_code":   intp("HTTP response status code, e.g. 200/301/403/404 (optional)"),
					"content_length": map[string]any{
						"type":        "integer",
						"description": "HTTP response body size in bytes (optional)",
					},
					"page_title":   str("page <title> content (optional)"),
					"favicon_mmh3": str("favicon MMH3 hash (optional)"),
					"technologies": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "list of fingerprints/tech stack, e.g. [\"Nginx\",\"Vue\",\"Bootstrap\"] (optional)",
					},
					"auth": map[string]any{
						"type":        "array",
						"description": "list of discovered authentication info; each entry has fields such as type/username/password (optional, appended not overwritten)",
						"items":       map[string]any{"type": "object"},
					},
					// service (other，非 HTTP)
					"service_name": str("service name, e.g. ssh/mysql/redis (required for a non-HTTP service)"),
					"port":         intp("port number (required for a non-HTTP service)"),
					// endpoint
					"method": str("HTTP method: GET/POST/PUT/PATCH/DELETE etc. (required for endpoint)"),
					"params": map[string]any{
						"type":        "array",
						"description": "list of request parameters; each entry has location(query/body/header/path)/name/value/type (optional, appended not overwritten)",
						"items":       map[string]any{"type": "object"},
					},
				}, "type"),
			},
		}, "assets"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("insert_assets not enabled: AssetStore not initialized"), nil
			}
			var a struct {
				Assets []assetInputItem `json:"assets"`
				TaskID int64            `json:"task_id"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			// use ToolSet.taskID as fallback
			taskID := a.TaskID
			if taskID == 0 {
				taskID = t.taskID
			}

			type result struct {
				Index int    `json:"index"`
				ID    int64  `json:"id"`
				Type  string `json:"type"`
			}
			type errEntry struct {
				Index int    `json:"index"`
				Error string `json:"error"`
			}

			var results []result
			var errs []errEntry

			for i, item := range a.Assets {
				typ := strings.TrimSpace(item.Type)
				var id int64
				var err error

				switch typ {
				case "root_domain":
					id, err = t.as.UpsertRootDomain(db.UpsertRootDomainReq{
						Domain: item.Domain,
						ICP:    item.ICP,
						TaskID: taskID,
					})

				case "ip":
					id, err = t.as.UpsertIP(db.UpsertIPReq{
						IP:           item.IP,
						BoundDomains: item.BoundDomains,
						OpenPorts:    item.OpenPorts,
						TaskID:       taskID,
					})

				case "subdomain":
					id, err = t.as.UpsertSubdomain(db.UpsertSubdomainReq{
						Domain:      item.Domain,
						RecordType:  item.RecordType,
						RecordValue: item.RecordValue,
						ICP:         item.ICP,
						TaskID:      taskID,
					})

				case "app":
					id, err = t.as.UpsertApp(db.UpsertAppReq{
						Name:        item.AppName,
						BundleID:    item.BundleID,
						Category:    item.Category,
						Description: item.Description,
						ICP:         item.AppICP,
						CompanyID:   item.CompanyID,
						TaskID:      taskID,
					})

				case "service":
					// distinguish HTTP vs other by presence of url
					if item.URL != "" {
						// agent may send "ip" or "service_ip" for the enrichment IP; accept both
						svcIP := item.ServiceIP
						if svcIP == "" {
							svcIP = item.IP
						}
						id, err = t.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
							URL:           item.URL,
							Technologies:  item.Technologies,
							StatusCode:    item.StatusCode,
							ContentLength: item.ContentLength,
							PageTitle:     item.PageTitle,
							FaviconMMH3:   item.FaviconMMH3,
							Auth:          item.Auth,
							IP:            svcIP,
							TaskID:        taskID,
						})
					} else {
						id, err = t.as.UpsertOtherService(db.UpsertOtherServiceReq{
							Domain:      item.Domain,
							IP:          item.IP,
							Port:        item.Port,
							ServiceName: item.ServiceName,
							Auth:        item.Auth,
							TaskID:      taskID,
						})
					}

				case "endpoint":
					id, err = t.as.UpsertEndpoint(db.UpsertEndpointReq{
						URL:    item.URL,
						Method: item.Method,
						Params: item.Params,
						IP:     item.ServiceIP,
						TaskID: taskID,
					})

				default:
					errs = append(errs, errEntry{Index: i, Error: "unknown type: " + typ})
					continue
				}

				if err != nil {
					errs = append(errs, errEntry{Index: i, Error: err.Error()})
					continue
				}
				results = append(results, result{Index: i, ID: id, Type: typ})
				t.writes.Assets++
				t.anchorOwner(id)
			}

			return jsonResult(map[string]any{
				"results": results,
				"errors":  errs,
			})
		},
	)
}

// addCompanyScope writes to company_scope table and triggers asset attribution.
func (t *ToolSet) addCompanyScope() actool.CoreTool {
	return writeTool(
		"add_company_scope",
		"Add a root domain/IP/IP range (CIDR) to a company's [asset scope]: once added, the system automatically claims all matching assets (existing + future).\n"+
			"The company name is unique: if company does not exist it is created, if it exists it is reused (only merging the scope in).\n"+
			"scope: one entry per line, supporting: a root domain / a single IP / a CIDR range (e.g. 1.2.3.0/24).\n"+
			"Be sure to give reason explaining the attribution basis (whois/certificate/ASN etc.).\n"+
			"Guardrail: rejects a bare TLD and overly broad ranges (IPv4 <=/16, IPv6 <=/32); invalid lines are skipped and returned in errors.",
		obj(map[string]any{
			"company": str("company name (created if it does not exist, reused if it does; the name is unique)"),
			"scope":   str("asset scope, one entry per line: root domain / IP / CIDR"),
			"reason":  str("attribution basis (evidence/source), must be filled in"),
			"logo":    str("company logo URL (optional; only takes effect when creating a new company)"),
		}, "company", "scope"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("add_company_scope not enabled: CompanyStore not initialized"), nil
			}
			var a struct {
				Company string `json:"company"`
				Scope   string `json:"scope"`
				Reason  string `json:"reason"`
				Logo    string `json:"logo"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if strings.TrimSpace(a.Company) == "" {
				return actool.Errorf("company cannot be empty"), nil
			}
			companyID, _, err := t.cs.UpsertCompany(a.Company, a.Logo)
			if err != nil {
				return actool.Errorf("failed to create/get company: " + err.Error()), nil
			}
			lines := splitLines(a.Scope)
			added, skipped, invalid, errMsgs := t.cs.AddScope(companyID, lines, a.Reason)
			out := map[string]any{
				"company_id": companyID,
				"added":      added,
				"skipped":    skipped,
				"invalid":    invalid,
			}
			if len(errMsgs) > 0 {
				out["errors"] = errMsgs
			}
			return jsonResult(out)
		},
	)
}

// listAssets lets an agent query the asset table.
func (t *ToolSet) listAssets() actool.CoreTool {
	return readTool(
		"list_assets",
		"Query the asset store. Supports DSL expression search, direct fetch by id/ids, and pagination.\n"+
			"DSL syntax: field=value fuzzy (ILIKE) | field==value exact | field!=value exclude | port>80 numeric comparison | a bare word = full-text fuzzy.\n"+
			"Logical operators: AND / OR (keywords, AND has higher precedence than OR), with parentheses for grouping.\n"+
			"Asset type is filtered with the separate type parameter; the DSL does not contain a type field.\n"+
			"Constraint: when id/ids is not passed, dsl must be non-empty: querying all assets without conditions is not allowed, a query condition is required.\n"+
			"Field overview:\n"+
			"  domain      domain (root domain/subdomain/service domain)\n"+
			"  root_domain root domain (only subdomain/service assets have it)\n"+
			"  ip          IPv4/IPv6 address\n"+
			"  url         full URL (service/endpoint)\n"+
			"  page_title  page title (HTTP service)\n"+
			"  icp         ICP filing number (root domain)\n"+
			"  service_name service name (non-HTTP service)\n"+
			"  app_name    application name (app type)\n"+
			"  method      HTTP method (endpoint type, e.g. GET/POST)\n"+
			"  service_type HTTP service type: http|other\n"+
			"  record_type DNS record type (subdomain, e.g. A/CNAME)\n"+
			"  technology  fingerprint/tech stack (array field, = fuzzy == exact)\n"+
			"  port        port number (integer, supports > >= < <=)\n"+
			"  status_code HTTP status code (integer, supports > >= < <=)\n"+
			"  company_id  owning company id (integer)\n"+
			"  task_id     source task id (integer)\n"+
			"Examples: status_code>=400 AND technology=shiro\n"+
			"      method==POST AND url=/api/admin\n"+
			"      icp=京 OR icp=沪\n"+
			"      (port==80 OR port==443) AND technology=nginx",
		obj(map[string]any{
			"dsl":    str(`DSL query expression, see the tool description. Must be non-empty when id/ids is not passed. e.g.: status_code>=400 technology=shiro / method==POST url=/api/admin`),
			"type":   str("asset type filter: root_domain|ip|subdomain|app|service|endpoint (a separate field, can be combined with dsl; type alone is not enough to query, dsl is still required)"),
			"id":     intp("fetch directly by a single asset id (optional, mutually exclusive with dsl/type)"),
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "fetch directly by multiple asset ids (optional, mutually exclusive with dsl/type)"},
			"limit":  intp("return limit, default 10 (optional)"),
			"offset": intp("pagination offset, default 0 (optional)"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.as == nil {
				return actool.Errorf("list_assets not enabled: AssetStore not initialized"), nil
			}
			var a struct {
				DSL    string  `json:"dsl"`
				Type   string  `json:"type"`
				ID     int64   `json:"id"`
				IDs    []int64 `json:"ids"`
				Limit  int     `json:"limit"`
				Offset int     `json:"offset"`
			}
			_ = json.Unmarshal(in, &a)
			if a.Limit <= 0 {
				a.Limit = 10
			}

			var assets []*db.Asset
			var err error
			switch {
			case a.ID > 0:
				assets, err = t.as.GetByIDs([]int64{a.ID})
			case len(a.IDs) > 0:
				assets, err = t.as.GetByIDs(a.IDs)
			case a.DSL != "":
				assets, err = t.as.QueryDSL(a.DSL, a.Type, a.Limit, a.Offset)
			default:
				return actool.Errorf("dsl cannot be empty when id/ids is not passed: querying all assets without conditions is not allowed, please provide a query condition"), nil
			}
			if err != nil {
				return actool.Errorf("DSL error: " + err.Error()), nil
			}
			return jsonResult(map[string]any{
				"count":  len(assets),
				"assets": assets,
			})
		},
	)
}

// listCompanies lets an agent enumerate companies (企业) with their scope + asset count.
func (t *ToolSet) listCompanies() actool.CoreTool {
	return readTool(
		"list_companies",
		"List the [enterprises/companies] in the asset store along with their asset scope and the number of assets already attributed. Used to see which companies exist, "+
			"and to obtain company_id (used when insert_assets associates an app, and when list_assets filters by company_id). "+
			"The optional search does a fuzzy filter by company name (case-insensitive); leave it empty to return all.",
		obj(map[string]any{
			"search": str("fuzzy filter by company name (optional, case-insensitive); leave empty to return all"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			if t.cs == nil {
				return actool.Errorf("list_companies not enabled: CompanyStore not initialized"), nil
			}
			var a struct {
				Search string `json:"search"`
			}
			_ = json.Unmarshal(in, &a)
			cos, err := t.cs.ListCompanies()
			if err != nil {
				return actool.Errorf("failed to query companies: " + err.Error()), nil
			}
			q := strings.ToLower(strings.TrimSpace(a.Search))
			type companyOut struct {
				ID         int64    `json:"id"`
				Name       string   `json:"name"`
				AssetCount int      `json:"asset_count"`
				Scope      []string `json:"scope"`
			}
			out := make([]companyOut, 0, len(cos))
			for _, c := range cos {
				if q != "" && !strings.Contains(strings.ToLower(c.Name), q) {
					continue
				}
				scope := make([]string, 0, len(c.Scope))
				for _, r := range c.Scope {
					scope = append(scope, r.Raw)
				}
				out = append(out, companyOut{ID: c.ID, Name: c.Name, AssetCount: c.AssetCount, Scope: scope})
			}
			return jsonResult(map[string]any{"count": len(out), "companies": out})
		},
	)
}

// splitLines splits a multi-line string into non-empty trimmed lines.
func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// WorkerTools returns the tool set for a work agent.
func (t *ToolSet) WorkerTools() []actool.CoreTool {
	base := []actool.CoreTool{
		t.listFindings(), t.listFacts(), t.nodeDetail(),
		t.addFinding(), t.recordFact(),
		// cross-work retrieval
		t.searchAllWorkerTraces(), t.listWorkerTraces(), t.getWorkerTrace(),
		// asset management (handlers guard nil store internally)
		t.insertAssets(), t.addCompanyScope(), t.listAssets(), t.listCompanies(),
		// knowledge base (global + this task); nil store guarded internally
		t.searchKnowledge(), t.listKnowledgeCategories(),
	}
	// Deterministic class verifiers (xss_verify, redirect_verify, ...), one per
	// registered VulnClass. Centralized in vulnClasses so adding an oracle is a
	// single registry entry. See vulnclass.go.
	return append(base, t.verifierTools()...)
}

// MainAgentTools returns the human-interface tool set.
func (t *ToolSet) MainAgentTools() []actool.CoreTool {
	return []actool.CoreTool{
		t.graphOverview(), t.listFindings(), t.listFacts(), t.nodeDetail(),
		t.getWorkerOutput(), t.getWorkerTrace(), t.searchAllWorkerTraces(), t.addHint(), t.addIntent(),
		// asset management (handlers guard nil store internally)
		t.insertAssets(), t.addCompanyScope(), t.listAssets(),
		// knowledge base (global + this task)
		t.searchKnowledge(), t.listKnowledgeCategories(),
	}
}

// AllDomainTools returns the union of all domain tools across all agent types,
// deduped by name (mainagent order wins). Used by the server to build a registry
// for injecting domain tools into agents (Auto, custom) that don't own a per-task
// ToolSet. The caller provides real stores; tools are callable at taskID=0 scope.
func (t *ToolSet) AllDomainTools() []actool.CoreTool {
	seen := map[string]bool{}
	var out []actool.CoreTool
	all := append(append(t.MainAgentTools(), t.PlannerTools()...), t.WorkerTools()...)
	for _, tool := range all {
		if !seen[tool.Name()] {
			seen[tool.Name()] = true
			out = append(out, tool)
		}
	}
	return out
}

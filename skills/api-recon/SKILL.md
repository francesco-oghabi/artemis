---
name: api-recon
description: Invoke this skill when collecting a website's API interfaces.
---

# API Recon (Frontend Interface Reconnaissance)

Under **authorized** conditions, discover as completely as possible: **backend APIs** (paths, methods, parameters, response bodies), **frontend routes**, and **UI feature trigger points** (tabs, dialogs, table actions, etc.).

---

## Boundaries and Prohibitions (Agent must read; violation is out of scope)

This skill **only performs API / parameter-surface reconnaissance**; it is not the vulnerability-hunting or penetration-exploitation phase.

### Task Boundaries

| Scope | Allowed | Prohibited |
|---|---|---|
| **Target** | Enumerate paths, methods, parameters, routes, UI trigger points | SQLi/XSS/privilege-escalation/brute-force/fuzz vulnerabilities, tampered-packet attacks, destructive operations |
| **Authentication** | Hook + stub/mock to bypass the **client-side** login gate | Asking the user for or guessing accounts/passwords; attempting a real login form submission |
| **Runtime** | Hook interfaces without credentials, use mock responses to make the SPA enter the post-login shell | Flows that require a real backend session to continue |

### Credential-less Dynamic Analysis (Phase 3 default)

1. Use `preload.js` / `runtime_harvest.js` to **intercept and stub** bootstrap interfaces such as login, permissions, and menus;
2. Return mock bodies that are **structurally correct, with a successful business code, and with possibly empty data** for business query interfaces;
3. Let the frontend still render post-login pages in an environment with no backend or with 401, thereby triggering more XHR/fetch/WebSocket calls;
4. **Empty data, blank tables, and placeholder UI are all expected** — do not switch to real login or vulnerability testing because of this.

**In one sentence**: use mocks to force the frontend routes and components to mount, and **only record outbound requests**; what the backend returns does not matter, what matters is **which further interfaces the frontend will call**.

### Hard Process Prohibitions

| Prohibited | Alternative |
|---|---|
| grep/curl/Read the main entry `index-*.js` to extract API paths before Phase 1 is complete | Run `OUTDIR/harvest_static.py` |
| Hand-writing scripts such as `extract_apis.py` that replace harvest | Modify `OUTDIR/harvest_static.py` and rerun |
| Repeating the same grep/command after it has failed ≥2 times | Change strategy: read tool_logs, modify harvest, check reference |
| Skipping gates A/B and directly running the original `scripts/` | Copy to OUTDIR and adjust for the target |
| Real username/password, OTP, OAuth, or other authentication | stub/mock (see above) |
| Skipping stubs under the pretext of "getting real data" to do privilege-escalation/injection testing | Record only outbound; this is within the recon boundary |
| Irreversible operations such as deleting, exporting sensitive data, or bulk writes | Same applies to coverage clicks |
| Claiming to have obtained all pages and interfaces before runtime + dynamic enumeration is complete | See "Definition of Done" or annotate the limitations |
| Claiming to have captured all parameters before the parameter trigger matrix + diff is complete | Phase 3b matrix + Phase 5 diff |
| Inferring required/optional from a single runtime sample | Multi-sample diff, or validation rules / error-based inference |

---

## Two-Layer Model + Run Modes

| Layer | Output | Upper limit |
|---|---|---|
| **Static** (JS bundle) | Full endpoint paths, route draft, request-assembly field candidates | No HTTP methods; parameters require Phase 1b; misses runtime-concatenated URLs |
| **Runtime** (live session) | Method + body + response + dynamic URLs + WS/SSE; multi-sample diff to complete parameters | The page must actually render before requests are sent; a single sample is not enough to determine required/optional |

| Run mode | Engine | Suitable for |
|---|---|---|
| **depth** | `runtime_harvest.js` (Puppeteer) | API inventory, METHOD/params/response body, WS/SSE, reproducible batch runs |
| **coverage** | browser + `preload.js` | Clicking tabs/dialogs/tables, deeper feature-point coverage |
| **both** | depth first, then coverage | Most complete, longest time |

**Parameter methodology** (no general-purpose script): use harvest/regex for paths; use **anchor window expansion + UI binding chain + multi-sample diff + error-based inference** for parameters (grep recipes in [reference.md](reference.md) section J).

---

## Definition of Done

Recon can only be claimed complete when all of the following are met:

- [ ] **Static**: Phase 1 harvest produces `api_static.txt`, `routes.txt`, `js/`
- [ ] **Runtime**: at least one of depth or coverage; coverage/both require **Hook in effect + dynamic enumeration loop**
- [ ] **In the shell**: accessing a business path does not land on `/login` (watch for hash routing)
- [ ] **Parameters**: coverage/both complete the parameter trigger matrix + `param_samples.json`; Phase 5 merges `params_merged.json`
- [ ] **Depth** (if module pages are blank): Phase 4 permission-tree reconstruction and rerun, until **module-level APIs** appear (not just locale/bootstrap)
- [ ] **Delivery**: Phase 5 outputs are complete (see the Phase 5 output table); `insert_assets` writes the service and endpoint assets

---

## Scripts and Gates

`scripts/` are only reference templates; **do not** directly run the originals and treat them as the final result.

**Rule**: read first → adjust for the target → write to `OUTDIR` (such as `recon/`) → record in `CHANGES.md`; if they do not match, rewrite following the methodology, borrowing only the structure.

| Gate | When | Reference script → OUTDIR copy | Common must-change items |
|---|---|---|---|
| **A (static)** | After Phase 0, before running harvest/spider for the **first time** | `harvest_static.py` / `spider_mpa.py` | **The default regex runs directly on most sites**; only change the endpoint regex, webpack/Vite `publicPath`, MPA exclude/cookie when the manifest/dialect does not match |
| **B (runtime)** | After Phase 2, before running depth/coverage | `runtime_harvest.js` / `preload.js` + `config.json` | Cookie/localStorage keys, neutralize success value, stubs, login regex, api prefix, hash/history |

**Mandatory SPA order** (not interchangeable; the Phase numbering takes precedence over "explore first then script"):

| Step | Must | Prohibited |
|---|---|---|
| After Phase 0 is complete | Next Bash = `python3 OUTDIR/harvest_static.py <URL> OUTDIR` | curl/grep/Read the main entry `index-*.js` (usually >500KB) |
| Gate A | Copy the script → make small changes as needed → **run immediately** | Manually extracting APIs first before deciding whether to harvest |
| Before Phase 1 is complete | `wc -l` to validate the output; on 404 modify harvest and retry | Hand-writing an extract script; repeatedly grepping URLs that were not downloaded |
| From Phase 1b | grep only `OUTDIR/js/*.js` | Using the main bundle in place of harvest |

- ✅ Copy `harvest_static.py` → (optional) change regex → **run immediately**
- ❌ curl the main bundle → grep repeatedly → write a temporary extract → harvest only at the end
- **MPA**: after Phase 0, the next Bash = `python3 OUTDIR/spider_mpa.py ...`

---

## Tool and Output Constraints

| Constraint | Description |
|---|---|
| Large files | **Do not** Read/grep `index-*.js` larger than 100KB into context; batch-process with OUTDIR scripts |
| grep output | Must use `\| head -20` or `-m 5`; keep only a path summary in the conversation, do not paste bundle fragments |
| Validation | Use `wc -l`, `ls \| wc -l`; do not Read an entire directory |
| regex probe | Optional, ≤1 time, only on ≤50KB small chunks or HTML; the authoritative static source is harvest |
| reference | Recipes/templates/troubleshooting are in [reference.md](reference.md), do not repeat the full text inline |

---

## Execution Roadmap

```
Phase 0 classify + OUTDIR
  → Gate A → Phase 1 harvest (★ run immediately ★)
  → Phase 1b parameter reversing
  → Phase 2 three authentication gates → config.json
  → Gate B → Phase 3 runtime + parameter matrix
  → Phase 4 permission tree (when necessary) → rerun Phase 3
  → Phase 5 merge report + insert_assets bulk-insert of all discovered service and endpoint API assets; in any case, do not omit any discovered asset when inserting
```

Check off in order; **you may not enter the next Phase before the previous item is complete**.

1. [ ] **Phase 0**: initial SPA/MPA probe; create `OUTDIR` → [Phase 0](#phase-0--classification)
2. [ ] **Gate A + Phase 1**: copy the script → **immediately** harvest → `wc -l` validation → [Phase 1](#phase-1--static)
3. [ ] **Phase 1b**: anchor window expansion + binding layer → `param_candidates.json` → [Phase 1b](#phase-1b--parameter-reversing)
4. [ ] **Phase 2**: three authentication gates → `config.json` → [Phase 2](#phase-2--three-authentication-gates)
5. [ ] **Gate B**: adjust the runtime script → [Phase 3](#phase-3--runtime)
6. [ ] **Phase 3**: depth / coverage / both; confirm in the shell; parameter trigger matrix → `param_samples.json`
7. [ ] **Phase 4** (if needed): permission tree → patch stubs → rerun Phase 3 → [Phase 4](#phase-4--permission-tree-reconstruction)
8. [ ] **Phase 5**: merge outputs + report + `insert_assets` → [Phase 5](#phase-5--merge-and-report)

---

## Phase 0 — Classification

Pull the entry HTML, **create `OUTDIR`** (do not modify `scripts/` inside the skill):

- **SPA**: empty shell + `<div id=app>` + chunks → Phase 1–5
- **MPA**: SSR + `<form>`, no endpoint bundle → after Gate A:

```bash
python3 recon/spider_mpa.py <BASE_URL> <OUTDIR> [--cookie "session=..."] [--max 300] [--depth 5] [--exclude "logout|delete|destroy"]
```

Produces `forms.txt`, `links.txt`, `api_inline.txt`. If it is an SPA with forms ≈ 0 → switch to Phase 1.

---

## Phase 1 — Static

Follow [Scripts and Gates](#scripts-and-gates) · [Tool and Output Constraints](#tool-and-output-constraints).

```bash
python3 recon/harvest_static.py <BASE_URL> <OUTDIR>
```

harvest: parse HTML script → webpack/Vite manifest → download all lazy chunks → produce `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt`.

```bash
wc -l OUTDIR/api_static.txt OUTDIR/routes.txt
ls OUTDIR/js | wc -l
```

- chunk count vs manifest: on 404 you must modify harvest and retry, do not manually curl each chunk one by one
- `api_static.txt` too few → loosen the endpoint regex inside OUTDIR and rerun (see reference)

### Phase 1b — Parameter Reversing

Paths come from Phase 1; parameter fields must be reconned separately. For grep rules see [Tool and Output Constraints](#tool-and-output-constraints).

**Completion criterion**: for important interfaces you can answer — field name, transport location, type inference, whether required, sample value, confidence.

#### 1b.0 — Transport Form

| Form | Where the parameters are | What to look at first statically |
|---|---|---|
| REST JSON | body + query | `(params\|data\|body)\s*:\s*\{` next to the path anchor |
| GraphQL | `variables` | gql template, `$page: Int` |
| Traditional form | urlencoded | `<form>`, `FormData` |
| File upload | multipart | `FormData.append` |
| Path parameter | `/user/:id` | route table + `useParams` / `$route.params` |
| Encrypted/signed | wrapped into `sign`/`data` | Hook the encryption function's arguments (reference section D) |

Output: annotate each interface with `transport: query|json|form|graphql|encrypted`.

#### 1b.1 — Anchor Window Expansion

Using a known path as the anchor, expand the window to find the request-assembly object:

```bash
grep -n '"/api/user/list"' OUTDIR/js/*.js | head -20
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' OUTDIR/js/*.js | head -20
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' OUTDIR/js/*.js | head -20
```

| Wrapper layer | Parameter clue |
|---|---|
| axios instance | `data` / `params` |
| unified request | interceptor injects global fields |
| OpenAPI client | generated method signatures |
| React Query / SWR | hook second argument |
| Vue composable | composable arguments |

Type residue: `yup`/`zod`/rules, `Form.Item name=`, embedded Swagger.

→ `param_candidates.json`: `{ path, fields[], source: "static-callsite", confidence }`

#### 1b.2 — Binding Layer

```
Form field → onFinish/handleSubmit → transform → API payload
```

| Binding source | Technique |
|---|---|
| form submit | follow submit → transform → API |
| table search | `getFieldsValue()` → `params` |
| route | `:id` / `?tab=` |
| interceptor | global `tenantId`, pagination, sign |
| enum select | `options` → API enum values |

In DevTools, walk up the call stack from `fetch`/`XHR.send` to the request-assembly function.

#### 1b.3 — Three Assembly Questions (≠ Phase 2 three authentication gates)

| Question | What to answer |
|---|---|
| **Assembly** | where the payload is built, transform traces |
| **Validation** | required, pattern, enum |
| **Transport** | path / query / body / multipart / header |

The interceptor gate (Phase 2) incidentally reads the globally injected fields (Authorization, `X-Tenant-Id`, sign).

#### 1b.4 — Handoff to Phase 3

Candidate fields come from static/binding layers; **required/optional/conditional dependencies** require the Phase 3 parameter matrix + diff + Phase 5 error-based inference.

---

## Phase 2 — Three Authentication Gates

grep in `OUTDIR/js/` (with `head`), write into `config.json` (recipes in reference):

| Gate | Question | Keywords |
|---|---|---|
| **Render gate** | How is login status determined? | `isLogin`, `getToken`, Cookie/localStorage |
| **Interceptor gate** | What triggers a redirect to `/login`? | `response_code`, `errno`, axios interceptor |
| **Content gate** | Where do menus/permissions come from? | `menu`, `permission`, `role`, `acl`, `routes` |

Do not treat a localStorage key name as a credential — it must be confirmed from the chunk/request chain.

**Exit = Gate B**: conclusions land in `config.json`, and modify `OUTDIR/runtime_harvest.js` / `preload.js`.

### Phase 2b — API Observation (Optional)

Use `preload.js` inside OUTDIR to confirm session key names, Authorization, and nested API URLs:

| Configuration | Output |
|---|---|
| `recordDetail: true` | `__API_RECON_DETAIL__` |
| `observe.xhrHeaders: true` | header observation |
| `extractUrlsFromResponse: true` | sub-APIs inside responses |
| `observe.storageReads/cookieReads: true` | backfill config |
| `neutralizeVueRouter: true` | `__API_RECON_ROUTES__` |

coverage exports each round: `__API_RECON_LOG__`, `__API_RECON_DETAIL__`, `__API_RECON_ROUTES__`, `__API_RECON_OBSERVE__`.

---

## Phase 3 — Runtime

Must have passed Gate B; follow [Boundaries and Prohibitions](#boundaries-and-prohibitions-agent-must-read-violation-is-out-of-scope) · the credential-less mock strategy.

In `config.json` set `"runtimeMode": "depth" | "coverage" | "both"` (templates in reference).

### Hook and stub (shared by depth + coverage)

| Layer | Scope | Purpose |
|---|---|---|
| L1 precise | auth/permission/bootstrap stub | pass the first-screen authentication |
| L2 negative correction | all JSON responses | not-logged-in code → success |
| L3 fallback | `/api` and others not matched by L1 | empty success body, force the UI open |

- **depth**: fake auth + `forward` to rewrite the business code + `stubs`; traverse `routes` (hash/history); produce `runtime_api.json`
- **coverage**: inject `preload.js` at **document-start** (CDP `addScriptToEvaluateOnNewDocument` or Userscript)

Verification: `window.__API_RECON_PRELOAD__` exists; a business path does not return to `/login`.

```bash
cd recon && npm install
node runtime_harvest.js config.json
```

### 3b — coverage dynamic enumeration (mandatory)

1. Main nav/sidebar — click each item, wait 1–3s for the network
2. Tabs — `role=tab`, `.ant-tabs-tab`
3. Tables — view/edit/detail on the first row
4. Toolbar — export, filter, create (**avoid irreversible deletes**)
5. Each time you enter a module — merge APIs/routes
6. SPA — controlled `pushState` for paths not covered by `routes.txt` (prohibited for MPA)

**Parameter trigger matrix** (mandatory): record once per operation type for each module, and **diff multiple samples**:

| Operation | Parameters usually added |
|---|---|
| List first screen | pagination + default filters |
| Click search | keyword, filter |
| Advanced filter | more optional ones |
| Create/edit | complete entity |
| Bulk/export/sort | `ids[]`, `exportType`, `sortField` |

**Under stubs the outbound body/headers are still real** — use the request as the source of truth. Record → `scan_raw.json`, `param_samples.json`, `api_detail.json`.

- **Vue**: `neutralizeVueRouter: true` + document-start preload
- **React**: `routes.txt` + sidebar clicks + `pushState`
- **both**: 3a depth first, then 3b coverage

---

## Phase 4 — Permission Tree Reconstruction

**Trigger**: module pages blank / each route only bootstrap (such as locale) → the content gate was not passed.

| Symptom | Meaning |
|---|---|
| Entered the shell successfully | render gate + interceptor gate already passed |
| Sidebar missing items / clicking yields blank | stub shape or incomplete permission codes |
| Each route has the same and very few APIs | `v-if permission` did not pass |
| `routes.txt` far fewer than the bundle | must be completed from the auth module |

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl)[^"]*"' OUTDIR/js/*.js | sort -u | head -30
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|menuList|authList' OUTDIR/js/*.js | head -20
```

Typical chain: `role_permissions` (flat codes) + `permissions/all` (tree) → `getResultTree` → `userRouteAuth[CODE].url`.

```bash
python3 recon/extract_route_map.py recon/js recon/
python3 recon/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Intermediate outputs: `route_map.json`, `userRouteAuth.json`, `permissions_tree.json`, `*_stub.json`, `perm_codes_all.txt`.

stub check: the outer `response_code` matches the interceptor gate; flat codes align with the tree; `routes` covers all links in `route_map`.

After updating `config.json`, **rerun Phase 3**. For large SPAs you can tune `waitUntil`, `routeTimeout`, `perRouteMs` (see reference sections A3/I).

---

## Phase 5 — Merge and Report

### Output Table

| File | Phase | Contents |
|---|---|---|
| `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt` | 1 | static bundle and paths |
| `param_candidates.json` | 1b | static parameter field candidates |
| `config.json` | 2 | three gates + runtime configuration |
| `runtime_api.json` | 3a | depth detailed recording (including WS/SSE) |
| `param_samples.json`, `scan_raw.json`, `api_detail.json` | 3b | multiple samples, click log, detail |
| `route_map.json` etc. | 4 | permission-tree intermediate files (if executed) |
| `params_merged.json` | 5 | merged parameter fields + confidence |
| `api_merged.txt` | 5 | `METHOD /path [params] [static\|runtime\|both]` |
| `site_map.json` | 5 | routes, APIs, params, feature points, limitations |
| **insert_assets** | 5 | write all service and endpoint assets into the asset store |

### 5b — Parameter Merge

diff from `param_samples.json`, **no general-purpose merge script**. Confidence rules are in reference J7 (high/medium/low/pending-trigger).

### 5c — Error-based Inference

Within the authorized scope you may send incomplete requests to read the 400 (**this is parameter recon, not vulnerability testing**): `field 'x' is required`, enum errors, etc. Watch for `data` wrappers, `variables`, and the pre-encryption `bizData`.

The report must note: runtimeMode, static/runtime API counts, parameter confidence, uncovered modules, and a `CHANGES.md` summary relative to the reference scripts.

Suggested `site_map.json` structure:

```json
{
  "site": "https://example.com",
  "runtimeMode": "both",
  "appType": "vue-spa",
  "routeGuardStrategy": ["nav-neutralize", "L1-auth", "L2-patch", "forward"],
  "apisFromStatic": [],
  "apisFromRuntime": [],
  "apis": [],
  "params": [{ "method": "POST", "path": "/api/user/list", "transport": "json", "fields": [] }],
  "frontendRoutes": [],
  "routesVerifiedByClick": [],
  "featuresTriggered": [],
  "limitations": ""
}
```

For more fields and grep recipes see [reference.md](reference.md).

---

## General Notes

- **Framework-agnostic**: the method is the same for webpack/Vite/Angular lazy loading
- **Transport**: REST/JSON, GraphQL, WebSocket, SSE; gRPC-web is out of scope
- **SSR**: client-side fetch can be recorded; RSC/Server Actions are not fully enumerable
- **Blind spots**: JSVMP, WASM, HMAC/mTLS strong validation → static + annotate the limitation
- **Parameter blind spots**: conditional linkage, hidden params, WASM assembly → "pending-trigger" / "unreachable"
- **Static is the safety net**: when runtime is blocked, static can still enumerate endpoints

---

## Additional Resources

- Grep recipes, `config.json` template, troubleshooting, Hook, parameter reversing section J, site_map template: **[reference.md](reference.md)**
- Reference script paths are in the [Scripts and Gates](#scripts-and-gates) table

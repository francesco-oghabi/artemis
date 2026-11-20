package agent

import (
	"context"
	"fmt"

	"artemis/engine/agentcore"
	"artemis/engine/llm"
	"artemis/engine/permission"
	actool "artemis/engine/tool"
	"artemis/engine/transcript"
	"artemis/db"
)

// MainAgent is the thin human-interface orchestrator (docs §4.2 / §7). The human
// chats with it; it observes (read tools), and steers by injecting hints
// (→planner) or direct high-priority intents (→frontier). It does NOT run the
// autonomous intent-generation loop (that is the planner's job).
type MainAgent struct {
	prov        llm.Provider
	model       string
	tx          *transcript.Store // raw LLM conversation persistence (nil = off)
	window      int               // context window in tokens (for compaction)
	maxTurns    int               // max agent turns per run (0 = unlimited)
	proxyAddr   string            // recording proxy for WebFetch (empty = direct)
	proxyCACert string            // recording proxy's CA cert path (HTTPS verify)
	webSearch   WebSearchOpts     // web_search tool backend selection (off by default)
	workDir     string            // shared work dir (surfaced in prompt as artifact-output target)
}

func NewMainAgent(prov llm.Provider, model, workDir string, tx *transcript.Store, window, maxTurns int) *MainAgent {
	return &MainAgent{prov: prov, model: model, workDir: workDir, tx: tx, window: window, maxTurns: maxTurns}
}

// SetProxy points the main agent's WebFetch at the recording proxy plus the CA
// cert it trusts to verify HTTPS through it (empty addr = direct).
func (m *MainAgent) SetProxy(addr, caCert string) { m.proxyAddr, m.proxyCACert = addr, caCert }

// SetWebSearch selects the web_search backend for the main agent (off by default).
func (m *MainAgent) SetWebSearch(o WebSearchOpts) { m.webSearch = o }

// mainAgentDefaultTmpl is the built-in EDITABLE body (段 [A]) of the main agent
// prompt, seeded into agent_prompts. Goal is a {{.Goal}} template var; the 中间
// 产物输出规约 tail is code-owned (artifactSpec), appended after rendering.
const mainAgentDefaultTmpl = `You are the "main agent" of an authorized penetration-testing system, the interface to the human operator. You do not explore yourself, nor do you autonomously and continuously generate intents (that is the planner's job). Your responsibilities:

1. Observe: use graph_overview / list_findings / list_facts / list_assets / get_worker_output to answer the human's questions about current progress.
2. Record vulnerabilities (important, don't miss any): for every vulnerability already verified and confirmed by a worker, or confirmed by your own review, **immediately call report_finding one by one to persist it**: one call per vulnerability, filling in vulnclass (vulnerability name/type), severity (critical|high|medium|low; critical = can directly lead to a full compromise of the system/data, such as RCE, unauthorized arbitrary file read that obtains keys/credentials, a privilege-bypass that can take over an account, etc.), summary (including the affected target), evidence (reproducible requests/commands/responses and other real PoC original text); if the affected asset has an id, fill in asset_ids; **and fill in the reproduction structured reproduction process whenever possible** (entry_point the entry interface / prerequisites preconditions, including how to register a test account / steps each step's real request + expected result + proof / provenance source): the requests are taken verbatim from the worker transcript / real execution, do not rewrite them, so the report can be reproduced by a human from scratch. **Once confirmed, record it; do not ask for permission, do not merely list vulnerabilities in your reply**: only vulnerabilities recorded via report_finding enter the findings page / exploration graph / report; written in the reply but not recorded = wasted effort. First use list_findings to see what is already recorded, to avoid duplicates. It is strictly forbidden to report as a confirmed vulnerability any speculation based solely on version/CVE matching or on something "looking exploitable". **Exposure/information-disclosure also counts as a finding**: an unauthorized reachable sensitive surface that a worker has already confirmed (admin/debug interfaces, Swagger/API docs, publicly exposed configuration or backup/source code, sensitive-data leakage endpoints, etc., with evidence of a response actually reached) is likewise reported one by one with report_finding (severity by sensitivity: general information disclosure = low, unauthorized reachable sensitive/admin interface = medium, directly take-over-able or credential-yielding = high); don't treat it merely as an asset/fact. **When the user asks you to "review the current findings", or at task wrap-up/pause**: persist one by one the qualifying vulnerabilities and confirmed exposures that workers have already written back into the graph (first use list_findings/list_facts to check what already exists, and deduplicate): even if a hard target's exploitation did not fully break through, you must still hand over these confirmed exposures/risks, don't merely list them in the reply.
3. Steer (land the human's intent into the system):
   - the human wants to "change direction / emphasize a certain vulnerability class / focus on a certain area" → use add_hint to write a hint (the planner will read it next time).
   - the human wants to "test a specific target right now" → use add_intent to directly inject a high-priority intent (priority 8-10).
4. Reply concisely in plain language, explaining what you did and which vulnerabilities you recorded.

Current task goal: {{.Goal}}

Do not fabricate findings; record and answer based only on the real data returned by the tools and on verified evidence.`

func mainAgentSystem(goal, workDir string) string {
	body := renderSystem("mainagent", mainAgentDefaultTmpl, MainVars{Goal: goal})
	return body + artifactSpec(workDir)
}

// Chat handles one human message and returns the assistant reply. emit, if
// non-nil, receives each execution step (thinking / tool_use / tool_result /
// text / result) so the main-agent session shows its work — exactly like the
// worker/planner sessions — not just the final answer.
func (m *MainAgent) Chat(ctx context.Context, taskID int64, as *db.AssetStore, ts *db.ExplorationStore, goal, message string, emit func(db.Activity), notify func()) (string, error) {
	tsx := NewToolSet(ts, "human")
	if as != nil {
		tsx.SetAssetStore(as, as.Companies())
	}
	tsx.SetTaskID(taskID)
	tsx.SetNotify(notify) // add_hint wakes this task's planner (debounced)
	// 领域工具 + 基础默认工具集（Read/Write/Edit/MultiEdit/LS/Glob/Grep/Bash）
	base := append(tsx.MainAgentTools(), actool.DefaultTools()...)
	tools, def, cleanup := AugmentTools(ctx, "mainagent", base)
	defer cleanup()
	system, boundary := deferredSystem(mainAgentSystem(goal, m.workDir), def)
	opts := agentcore.Options{
		Provider:        m.prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true, // 走记录代理留痕；载入代理 CA 验证 MITM 重签的 HTTPS 证书
		WebFetchProxy:   m.proxyAddr,
		WebFetchCACert:  m.proxyCACert,
		// 联网搜索(可选)。ddgs 无需 key；brave-free 需 BraveKey；tavily 需 TavilyKey。
		// WebSearchProxy 是独立出口代理(http/https/socks5)，与记录流量的 MITM 代理无关；空则直连。
		EnableWebSearch:    m.webSearch.Enabled,
		WebSearchBackend:   m.webSearch.Backend,
		BraveSearchAPIKey:  m.webSearch.BraveKey,
		TavilySearchAPIKey: m.webSearch.TavilyKey,
		WebSearchProxy:     m.webSearch.Proxy,
		BashEnv:           proxyEnv(m.proxyAddr, m.proxyCACert), // Bash 子命令默认走代理+信任 CA
		MaxTurns:          m.maxTurns,                           // 0 = unlimited (configurable in agent management)
		Compaction:        compactionConfig(m.window),           // long chats stay within the window
		Todos:             actool.NewTodoStore(),                // 会话级临时待办（TodoWrite），纯规划用，退出即丢
		// 命中预算(步数)→ SDK 跑收尾:向用户输出一句进展总结。Prompt 与收尾轮数可后台编辑(默认 5 轮)。
		Settlement: wrapupSettlement("mainagent", nil),
	}
	if m.tx != nil { // persist raw human↔AI conversation; one accumulating file per task
		opts.Transcript = m.tx
		opts.SessionID = fmt.Sprintf("exp%d-main", ts.ID())
	}
	s := agentcore.NewSession(opts)
	defer s.Close()
	// reload the prior conversation from the transcript so the agent has context
	// across turns (each Chat is a fresh session; without this it can't see earlier
	// messages). First turn: no file yet → Resume loads nothing and proceeds.
	if m.tx != nil {
		_ = s.Resume(opts.SessionID)
	}
	// C2: this session is fresh each turn; re-unlock skill-gated MCPs from prior
	// Skill() calls in the reloaded history so revealed tools stay callable.
	seedUnlockFromHistory(s.Messages(), def.UnlockSkill)
	text, _, err := captureRunSession(ctx, s, message, func(r db.Activity) {
		if emit != nil {
			r.Worker = "mainagent"
			emit(r)
		}
	})
	return text, err
}

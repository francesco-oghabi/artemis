package agent

import actool "artemis/engine/tool"

// VulnClass is one vulnerability class the deterministic pipeline knows end to end.
// It bundles the TWO halves that used to live apart (an expandClass slice entry for
// the recognizer + a hand-registered WorkerTool for the oracle) behind one type, so
// adding a class is implementing this interface once and registering it in
// vulnClasses, nothing else:
//
//   - Expand turns the discovered Surface into self-contained, executable intent
//     texts (URL + the exact verifier tool to call), engine-side and deterministic;
//     an empty slice means "not ready / nothing discovered", so the engine retries
//     the class next round. maxN bounds how many intents it writes (<=0 => the
//     class default, DefaultCap).
//   - VerifyTool returns the worker tool that deterministically CONFIRMS or REFUTES
//     the class (xss_verify, redirect_verify, ...). The worker calls it when it runs
//     an intent; a negative verdict is recorded as a fact, never a finding. Keeping
//     verification a worker tool (not engine-side) preserves the validated
//     xss/redirect flow while still centralizing registration here.
//   - DefaultCap is the per-class intent cap used when the caller passes no positive
//     override (Manager.*ExpandCap / the caps map in ExpandReadyClasses).
//
// This REPLACES the earlier lightweight expandClass slice: with the jump from 2 to
// ~10 classes (plus a stateful injection prober) the slice stopped fitting, exactly
// the "revisit at the third class" trigger noted in memory. See
// expander-lightweight-abstraction.
type VulnClass interface {
	Name() string
	Expand(s Surface, maxN int) []string
	VerifyTool(t *ToolSet) actool.CoreTool
	DefaultCap() int
}

// vulnClasses is the single registry the generic expander AND the worker tool set
// iterate. Adding a class is adding one entry here. Order is stable (XSS first), so
// the frontier fills in a predictable order.
var vulnClasses = []VulnClass{
	xssClass{},
	openRedirectClass{},
	exposureClass{},
	cspClass{},
	injectionClass{},
	captchaClass{},
	traversalClass{},
	jwtClass{},
	idorClass{},
	buslogicClass{},
	massassignClass{},
	storedXSSClass{},
}

// ExpandClassNames returns the registered class names in registry order. The
// engine uses it to seed its per-task "already fired" tracking and the "all classes
// done" check, so adding a class never needs an engine edit.
func ExpandClassNames() []string {
	out := make([]string, len(vulnClasses))
	for i, c := range vulnClasses {
		out[i] = c.Name()
	}
	return out
}

// verifierTools returns every class's verifier tool, in registry order, for the
// worker tool set. One place to wire a new oracle.
func (t *ToolSet) verifierTools() []actool.CoreTool {
	out := make([]actool.CoreTool, 0, len(vulnClasses))
	for _, c := range vulnClasses {
		out = append(out, c.VerifyTool(t))
	}
	return out
}

// --- xss ---------------------------------------------------------------------

type xssClass struct{}

func (xssClass) Name() string                             { return "xss" }
func (xssClass) Expand(s Surface, maxN int) []string      { return xssSummaries(s, maxN) }
func (xssClass) VerifyTool(t *ToolSet) actool.CoreTool    { return t.xssVerify() }
func (xssClass) DefaultCap() int                          { return maxXSSExpandIntents }

// --- open redirect -----------------------------------------------------------

type openRedirectClass struct{}

func (openRedirectClass) Name() string                          { return "openredirect" }
func (openRedirectClass) Expand(s Surface, maxN int) []string   { return openRedirectSummaries(s, maxN) }
func (openRedirectClass) VerifyTool(t *ToolSet) actool.CoreTool { return t.redirectVerify() }
func (openRedirectClass) DefaultCap() int                       { return maxRedirectExpandIntents }

// --- sensitive-path exposure (V10 /ftp, V11 /encryptionkeys, V15 /metrics, ...) --

type exposureClass struct{}

func (exposureClass) Name() string                          { return "exposure" }
func (exposureClass) Expand(s Surface, maxN int) []string   { return exposureSummaries(s, maxN) }
func (exposureClass) VerifyTool(t *ToolSet) actool.CoreTool { return t.exposureVerify() }
func (exposureClass) DefaultCap() int                       { return 1 }

// --- missing Content-Security-Policy (V17) -----------------------------------

type cspClass struct{}

func (cspClass) Name() string                          { return "csp" }
func (cspClass) Expand(s Surface, maxN int) []string   { return cspSummaries(s, maxN) }
func (cspClass) VerifyTool(t *ToolSet) actool.CoreTool { return t.cspVerify() }
func (cspClass) DefaultCap() int                       { return 1 }

// --- SQL / NoSQL injection (V01 auth bypass, V02/V03 SQLi, V07 NoSQL) --------

type injectionClass struct{}

func (injectionClass) Name() string                          { return "injection" }
func (injectionClass) Expand(s Surface, maxN int) []string   { return injectionSummaries(s, maxN) }
func (injectionClass) VerifyTool(t *ToolSet) actool.CoreTool { return t.injectionVerify() }
func (injectionClass) DefaultCap() int                       { return maxInjectionExpandIntents }

// --- CAPTCHA answer disclosure (V18) -----------------------------------------

type captchaClass struct{}

func (captchaClass) Name() string                          { return "captcha" }
func (captchaClass) Expand(s Surface, maxN int) []string   { return captchaSummaries(s, maxN) }
func (captchaClass) VerifyTool(t *ToolSet) actool.CoreTool { return t.captchaVerify() }
func (captchaClass) DefaultCap() int                       { return 1 }

// --- path traversal / null-byte file access (V09) ----------------------------

type traversalClass struct{}

func (traversalClass) Name() string                          { return "traversal" }
func (traversalClass) Expand(s Surface, maxN int) []string   { return traversalSummaries(s, maxN) }
func (traversalClass) VerifyTool(t *ToolSet) actool.CoreTool { return t.traversalVerify() }
func (traversalClass) DefaultCap() int                       { return 1 }

// --- JWT forgery (V04) -------------------------------------------------------

type jwtClass struct{}

func (jwtClass) Name() string                          { return "jwt" }
func (jwtClass) Expand(s Surface, maxN int) []string   { return jwtSummaries(s, maxN) }
func (jwtClass) VerifyTool(t *ToolSet) actool.CoreTool { return t.jwtVerify() }
func (jwtClass) DefaultCap() int                       { return 1 }

// --- IDOR / broken object-level authorization (V06) --------------------------

type idorClass struct{}

func (idorClass) Name() string                          { return "idor" }
func (idorClass) Expand(s Surface, maxN int) []string   { return idorSummaries(s, maxN) }
func (idorClass) VerifyTool(t *ToolSet) actool.CoreTool { return t.idorVerify() }
func (idorClass) DefaultCap() int                       { return 1 }

// --- negative-quantity business-logic flaw (V16) -----------------------------

type buslogicClass struct{}

func (buslogicClass) Name() string                          { return "buslogic" }
func (buslogicClass) Expand(s Surface, maxN int) []string   { return buslogicSummaries(s, maxN) }
func (buslogicClass) VerifyTool(t *ToolSet) actool.CoreTool { return t.buslogicVerify() }
func (buslogicClass) DefaultCap() int                       { return 1 }

// --- mass assignment of a privileged field (V05) -----------------------------

type massassignClass struct{}

func (massassignClass) Name() string                          { return "massassign" }
func (massassignClass) Expand(s Surface, maxN int) []string   { return massassignSummaries(s, maxN) }
func (massassignClass) VerifyTool(t *ToolSet) actool.CoreTool { return t.massassignVerify() }
func (massassignClass) DefaultCap() int                       { return 1 }

// --- stored / persisted XSS (V08) --------------------------------------------

type storedXSSClass struct{}

func (storedXSSClass) Name() string                          { return "storedxss" }
func (storedXSSClass) Expand(s Surface, maxN int) []string   { return storedXSSSummaries(s, maxN) }
func (storedXSSClass) VerifyTool(t *ToolSet) actool.CoreTool { return t.storedXSSVerify() }
func (storedXSSClass) DefaultCap() int                       { return 1 }

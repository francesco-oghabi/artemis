package agent

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	actool "artemis/engine/tool"
)

// XSS rendering oracle (option B): a deterministic judge for client-side/DOM XSS.
// The weak model retrieves the right technique but does not apply it (it tests
// <script> on JSON APIs and never renders the SPA). This tool removes that
// dependency: it drives a real headless Chromium against a target URL, fires a
// battery of canonical non-<script> payloads, and reports whether any actually
// EXECUTED. The browser engine (Playwright + Chromium) ships in the runtime image.

//go:embed xss_oracle.mjs
var xssOracleJS string

var (
	xssScriptOnce sync.Once
	xssScriptPath string
	xssScriptErr  error
)

// xssOracleScript materializes the embedded oracle script to a stable temp path
// once per process and returns it.
func xssOracleScript() (string, error) {
	xssScriptOnce.Do(func() {
		p := filepath.Join(os.TempDir(), "artemis_xss_oracle.mjs")
		xssScriptErr = os.WriteFile(p, []byte(xssOracleJS), 0o644)
		if xssScriptErr == nil {
			xssScriptPath = p
		}
	})
	return xssScriptPath, xssScriptErr
}

type xssOracleOut struct {
	Target    string `json:"target"`
	Confirmed bool   `json:"confirmed"`
	Hit       *struct {
		Name  string `json:"name"`
		Tag   string `json:"tag"`
		Param string `json:"param"`
		URL   string `json:"url"`
	} `json:"hit"`
	Results []struct {
		Name               string `json:"name"`
		Param              string `json:"param"`
		Fired              bool   `json:"fired"`
		ReflectedUnescaped bool   `json:"reflectedUnescaped"`
		URL                string `json:"url"`
	} `json:"results"`
	Error string `json:"error"`
}

func (t *ToolSet) xssVerify() actool.CoreTool {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"url": map[string]any{
				"type": "string",
				"description": "URL of the page/route to render and test. Two ways: (1) put the marker FUZZ exactly where the input goes (e.g. http://host:3000/#/search?q=FUZZ) to test that precise point; (2) pass a bare route with NO parameter (e.g. http://host:3000/#/search) and the oracle sweeps a wordlist of common query parameters itself, probing which reflect into the DOM and firing payloads on those. Prefer (2) when you don't know the exact parameter name.",
			},
		},
		"required": []any{"url"},
	}
	desc := "Render a target URL in a real headless browser and DETERMINISTICALLY verify client-side/DOM XSS. Use this to CONFIRM or REFUTE an XSS vector instead of eyeballing an HTTP/JSON response: DOM XSS executes in the browser, so curl or a JSON API cannot confirm it. The tool fires a battery of canonical non-<script> payloads (img/svg/iframe/attribute-breakout) that execute via innerHTML and reports which, if any, actually ran. A confirmed execution is a report_finding. Pass either a url with the marker FUZZ at the injection point (e.g. /#/search?q=FUZZ), or a bare route with no parameter (e.g. /#/search) and the oracle sweeps common query parameters itself."
	return readTool("xss_verify", desc, schema, func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal(in, &a)
		url := strings.TrimSpace(a.URL)
		if url == "" {
			return actool.Errorf("url is required: pass the page/route to render, with FUZZ where the input goes (e.g. http://host:3000/#/search?q=FUZZ)."), nil
		}
		script, err := xssOracleScript()
		if err != nil {
			return actool.Errorf("xss oracle unavailable: " + err.Error()), nil
		}
		// Bound the whole run; the node script also bounds each payload internally.
		runCtx, cancel := context.WithTimeout(ctx, 150*time.Second)
		defer cancel()
		cmd := exec.CommandContext(runCtx, "node", script, url)
		cmd.Env = append(os.Environ(), "NODE_PATH=/usr/lib/node_modules")
		out, err := cmd.Output()
		if err != nil {
			stderr := ""
			if ee, ok := err.(*exec.ExitError); ok {
				stderr = strings.TrimSpace(string(ee.Stderr))
			}
			if runCtx.Err() == context.DeadlineExceeded {
				return actool.Errorf("xss_verify timed out while rendering the target."), nil
			}
			return actool.Errorf("xss_verify failed to run the browser oracle: " + err.Error() + " " + clipXSS(stderr, 400)), nil
		}
		var res xssOracleOut
		if e := json.Unmarshal(out, &res); e != nil {
			return actool.Errorf("xss_verify produced unparseable output: " + clipXSS(string(out), 400)), nil
		}
		if res.Error != "" {
			return actool.Errorf("xss_verify: " + res.Error), nil
		}
		if res.Confirmed && res.Hit != nil {
			paramNote := ""
			if res.Hit.Param != "" && res.Hit.Param != "(fuzz)" {
				paramNote = fmt.Sprintf(" (reflecting parameter: %q)", res.Hit.Param)
			}
			return actool.Text(fmt.Sprintf(
				"CONFIRMED XSS. Payload family %q EXECUTED in the rendered DOM at: %s%s\nThis is a verified exploit: report_finding (reflected/DOM XSS) with this URL and payload as reproduction. Do NOT record it as a negative.",
				res.Hit.Name, res.Hit.URL, paramNote)), nil
		}
		// Not confirmed: say whether anything reflected unescaped (worth another route/param).
		anyReflect := false
		for _, r := range res.Results {
			if r.ReflectedUnescaped {
				anyReflect = true
				break
			}
		}
		msg := fmt.Sprintf("No XSS execution detected across %d payloads on %s.", len(res.Results), res.Target)
		if anyReflect {
			msg += " Note: input was reflected UNESCAPED in the DOM but did not execute here; try a different injection point/route or confirm the sink is this page."
		} else {
			msg += " Input was not reflected into the DOM on this route: this is likely the wrong page/param for a reflected/DOM XSS (re-check where the value is rendered)."
		}
		return actool.Text(msg), nil
	})
}

func clipXSS(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

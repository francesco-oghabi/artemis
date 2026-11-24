package harness

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"artemis/engine/llm"
)

// Some models served over an OpenAI-compatible endpoint (notably the Qwen family)
// emit a tool call as plain text in the <function=NAME>…</function> form instead of
// as a structured tool_calls entry. When the serving gateway's own tool parser
// misses that shape, the whole call leaks into the assistant's content and is then
// silently dropped: the tool never runs. This was observed to drop ~1 call in every
// few turns against a live target (including the only jwt_verify attempt of a run),
// so the oracle never fired even though the model had selected it with the right
// argument. salvageTextToolCalls recovers these leaked calls so they still execute.
//
// The recovered shape, from live captures, is always:
//
//	<function=NAME>
//	<parameter=PNAME>
//	VALUE
//	</parameter>
//	...
//	</function>
//	</tool_call>
//
// with the opening <tool_call> wrapper already stripped by the gateway. No other
// leaked variant (e.g. <tool_call>{json}</tool_call>) was observed.
var (
	salvageFuncRe  = regexp.MustCompile(`(?s)<function=([A-Za-z0-9_.-]+)\s*>(.*?)</function>`)
	salvageParamRe = regexp.MustCompile(`(?s)<parameter=([A-Za-z0-9_.-]+)\s*>(.*?)</parameter>`)
)

// salvageTextToolCalls scans assembled assistant content for tool calls that leaked
// into text in the <function=…> form and promotes them to real tool_use blocks. It
// acts only when the turn produced no structured tool_use block, which is the exact
// signature of a gateway parser miss: a turn that already carries a proper tool_use
// is left untouched (returned unchanged, with a nil salvaged list). Matched spans are
// stripped from the surrounding text, a stray </tool_call> wrapper is removed, and a
// text block left blank by the stripping is dropped.
//
// It returns the rewritten content (text with the leaked spans removed, followed by
// the recovered tool_use blocks) and, separately, the list of recovered tool_use
// blocks so the caller can dispatch them.
func salvageTextToolCalls(blocks []llm.ContentBlock) (out []llm.ContentBlock, salvaged []llm.ContentBlock) {
	for _, b := range blocks {
		if b.Type == llm.BlockToolUse {
			return blocks, nil // structured tool_calls present: the parser worked
		}
	}
	for _, b := range blocks {
		if b.Type != llm.BlockText || !strings.Contains(b.Text, "<function=") {
			out = append(out, b)
			continue
		}
		ms := salvageFuncRe.FindAllStringSubmatch(b.Text, -1)
		if len(ms) == 0 {
			out = append(out, b)
			continue
		}
		for _, m := range ms {
			salvaged = append(salvaged, llm.ContentBlock{
				Type:  llm.BlockToolUse,
				ID:    fmt.Sprintf("call_salvaged_%d", len(salvaged)),
				Name:  m[1],
				Input: json.RawMessage(salvageParamsToJSON(m[2])),
			})
		}
		stripped := salvageFuncRe.ReplaceAllString(b.Text, "")
		stripped = strings.ReplaceAll(stripped, "</tool_call>", "")
		stripped = strings.ReplaceAll(stripped, "<tool_call>", "")
		if s := strings.TrimSpace(stripped); s != "" {
			out = append(out, llm.TextBlock(s))
		}
	}
	if len(salvaged) == 0 {
		return blocks, nil
	}
	return append(out, salvaged...), salvaged
}

// salvageParamsToJSON turns the <parameter=NAME>VALUE</parameter> children of a
// leaked function block into a JSON object the tool can decode. A value that is
// already valid JSON (a number, boolean, or object/array) is kept as-is so typed
// fields such as intent_id survive as numbers; anything else (a URL, a free-text
// summary, a bare word like "observed") is encoded as a JSON string. A block with no
// parameters becomes "{}".
func salvageParamsToJSON(body string) string {
	params := salvageParamRe.FindAllStringSubmatch(body, -1)
	if len(params) == 0 {
		return "{}"
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, p := range params {
		if i > 0 {
			sb.WriteByte(',')
		}
		key, _ := json.Marshal(p[1])
		sb.Write(key)
		sb.WriteByte(':')
		val := strings.TrimSpace(p[2])
		if val != "" && json.Valid([]byte(val)) {
			sb.WriteString(val)
		} else {
			qv, _ := json.Marshal(val)
			sb.Write(qv)
		}
	}
	sb.WriteByte('}')
	if s := sb.String(); json.Valid([]byte(s)) {
		return s
	}
	return "{}"
}

package harness

import (
	"encoding/json"
	"testing"

	"artemis/engine/llm"
)

// Samples are verbatim from live captures (DB activity.detail) of a Qwen worker run
// whose <function=…> tool calls leaked into assistant text and were dropped.

func TestSalvage_FunctionWithParam(t *testing.T) {
	text := "I need to perform a JWT forgery check on the OWASP Juice Shop target. " +
		"Let me start by using the jwt_verify tool which should handle it.\n\n" +
		"<function=jwt_verify>\n<parameter=url>\nhttp://juice-shop:3000\n</parameter>\n</function>\n</tool_call>"
	out, salvaged := salvageTextToolCalls([]llm.ContentBlock{llm.TextBlock(text)})
	if len(salvaged) != 1 {
		t.Fatalf("want 1 salvaged call, got %d", len(salvaged))
	}
	if salvaged[0].Name != "jwt_verify" {
		t.Fatalf("want jwt_verify, got %q", salvaged[0].Name)
	}
	var got map[string]any
	if err := json.Unmarshal(salvaged[0].Input, &got); err != nil {
		t.Fatalf("input not valid JSON: %v (%s)", err, salvaged[0].Input)
	}
	if got["url"] != "http://juice-shop:3000" {
		t.Fatalf("want url arg, got %v", got["url"])
	}
	// The leaked span must be stripped; the prose before it kept as a text block.
	if len(out) != 2 || out[0].Type != llm.BlockText || out[1].Type != llm.BlockToolUse {
		t.Fatalf("unexpected rewritten blocks: %+v", out)
	}
	if contains(out[0].Text, "<function=") || contains(out[0].Text, "</tool_call>") {
		t.Fatalf("leaked markup not stripped: %q", out[0].Text)
	}
}

func TestSalvage_NoParams(t *testing.T) {
	out, salvaged := salvageTextToolCalls([]llm.ContentBlock{
		llm.TextBlock("<function=list_findings>\n</function>\n</tool_call>"),
	})
	if len(salvaged) != 1 || salvaged[0].Name != "list_findings" {
		t.Fatalf("want 1 list_findings call, got %+v", salvaged)
	}
	if string(salvaged[0].Input) != "{}" {
		t.Fatalf("want empty args {}, got %s", salvaged[0].Input)
	}
	// Text block was only markup, so it is dropped: only the tool_use remains.
	if len(out) != 1 || out[0].Type != llm.BlockToolUse {
		t.Fatalf("want only the tool_use block, got %+v", out)
	}
}

func TestSalvage_TypedParamStaysNumber(t *testing.T) {
	text := "<function=record_fact>\n<parameter=intent_id>\n8174\n</parameter>\n" +
		"<parameter=confidence>\nobserved\n</parameter>\n</function>\n</tool_call>"
	_, salvaged := salvageTextToolCalls([]llm.ContentBlock{llm.TextBlock(text)})
	if len(salvaged) != 1 {
		t.Fatalf("want 1 call, got %d", len(salvaged))
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(salvaged[0].Input, &got); err != nil {
		t.Fatalf("bad JSON: %v (%s)", err, salvaged[0].Input)
	}
	if string(got["intent_id"]) != "8174" {
		t.Fatalf("intent_id should stay a JSON number, got %s", got["intent_id"])
	}
	if string(got["confidence"]) != `"observed"` {
		t.Fatalf("confidence should be a JSON string, got %s", got["confidence"])
	}
}

func TestSalvage_LeftUntouchedWhenRealToolUse(t *testing.T) {
	in := []llm.ContentBlock{
		llm.TextBlock("some text with <function=foo></function> markup"),
		{Type: llm.BlockToolUse, ID: "x", Name: "real_tool", Input: json.RawMessage(`{}`)},
	}
	out, salvaged := salvageTextToolCalls(in)
	if salvaged != nil {
		t.Fatalf("must not salvage when a structured tool_use is present, got %+v", salvaged)
	}
	if len(out) != 2 {
		t.Fatalf("content must be returned unchanged, got %+v", out)
	}
}

func TestSalvage_NoFunctionTag(t *testing.T) {
	in := []llm.ContentBlock{llm.TextBlock("just prose, no tool calls here")}
	out, salvaged := salvageTextToolCalls(in)
	if salvaged != nil || len(out) != 1 {
		t.Fatalf("plain text must pass through unchanged, got out=%+v salvaged=%+v", out, salvaged)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

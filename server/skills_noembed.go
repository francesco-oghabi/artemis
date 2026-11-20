//go:build !embedui

package server

// Dev builds (no `embedui` tag) read skills directly from disk (ARTEMIS_SKILL_DIR /
// repo skills/), so there is nothing to materialize from the binary.
func materializeEmbeddedSkills(string) {}

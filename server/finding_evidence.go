package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif" // register the gif decoder
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"artemis/report"
)

// Vulnerability evidence screenshots: upload/display/management. Files are stored under dataDir/report_assets/evidence/<node_id>/ (backed up with report_assets);
// the findings page <img> fetches images via /api/findings/{id}/evidence/{file} (cookie auth, same as logo); the report/MD side embeds them by disk path.
//
// Security baseline (this is itself a security platform, so the upload point must not become an entry for malicious files):
//   - do not trust the extension/client MIME: determine the type from content + verify it is a real image by decoding + re-encode (stripping appended/embedded payloads,
//     EXIF, polyglot), writing a clean png/jpg uniformly to disk;
//   - decompression-bomb protection: read DecodeConfig to check the size cap before fully decoding;
//   - the image response forces X-Content-Type-Options: nosniff + a fixed image Content-Type + inline, eliminating stored XSS.

const (
	evidenceMaxBytes  = 16 << 20   // 16MB per image
	evidenceMaxPixels = 50_000_000 // 50-million-pixel cap (decompression-bomb guard)
	evidenceMaxDim    = 20000
)

// sanitizeImage validates and re-encodes an image by content; accepts only png/jpeg/gif and outputs png (or jpg) uniformly.
func sanitizeImage(raw []byte) (out []byte, ext string, err error) {
	ct := http.DetectContentType(raw)
	switch ct {
	case "image/png", "image/jpeg", "image/gif":
	default:
		return nil, "", fmt.Errorf("sono supportate solo immagini png/jpg/gif (rilevato %s)", ct)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, "", fmt.Errorf("immagine non valida")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > evidenceMaxDim || cfg.Height > evidenceMaxDim ||
		cfg.Width*cfg.Height > evidenceMaxPixels {
		return nil, "", fmt.Errorf("dimensioni immagine oltre il limite")
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, "", fmt.Errorf("decodifica immagine fallita")
	}
	var buf bytes.Buffer
	if ct == "image/jpeg" {
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
			return nil, "", fmt.Errorf("elaborazione immagine fallita")
		}
		return buf.Bytes(), ".jpg", nil
	}
	if err := png.Encode(&buf, img); err != nil {
		return nil, "", fmt.Errorf("elaborazione immagine fallita")
	}
	return buf.Bytes(), ".png", nil
}

// evidenceDir returns a vulnerability's evidence-file directory (absolute path).
func (s *Server) evidenceDir(nodeID int64) string {
	return filepath.Join(s.dataDir, "report_assets", "evidence", strconv.FormatInt(nodeID, 10))
}

// evidenceURL builds the frontend image-fetch URL.
func evidenceURL(nodeID int64, filename string) string {
	return fmt.Sprintf("/api/findings/%d/evidence/%s", nodeID, filename)
}

// POST /api/findings/{id}/evidence: multipart "file" + optional caption / step_index.
func (s *Server) uploadFindingEvidence(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	nodeID, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "id vulnerabilità non valido")
		return
	}
	if err := r.ParseMultipartForm(16 << 20); err != nil { // 16 MB
		writeErr(w, 400, "parsing dell'upload fallito")
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, 400, "file mancante")
		return
	}
	defer file.Close()
	// read into memory (16MB limit) -> content-level validation + re-encode, not trusting the extension/client MIME.
	raw, err := io.ReadAll(io.LimitReader(file, evidenceMaxBytes+1))
	if err != nil {
		writeErr(w, 400, "lettura del file fallita")
		return
	}
	if len(raw) > evidenceMaxBytes {
		writeErr(w, 400, "immagine troppo grande (limite 16MB)")
		return
	}
	clean, ext, err := sanitizeImage(raw)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	dir := s.evidenceDir(nodeID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeErr(w, 500, "creazione della directory fallita")
		return
	}
	name := fmt.Sprintf("ev-%d%s", time.Now().UnixNano(), ext)
	if err := os.WriteFile(filepath.Join(dir, name), clean, 0o644); err != nil {
		writeErr(w, 500, "scrittura fallita")
		return
	}
	caption := strings.TrimSpace(r.FormValue("caption"))
	stepIndex, _ := strconv.Atoi(r.FormValue("step_index"))
	if caption == "" {
		// auto-fill the caption: if none was entered manually, derive one from the reproduction text the agent recorded in place for that step (editable, no extra LLM call).
		caption = s.deriveEvidenceCaption(nodeID, stepIndex)
	}
	ev, err := pg.CreateFindingEvidence(nodeID, name, caption, stepIndex)
	if err != nil {
		_ = os.Remove(filepath.Join(dir, name)) // roll back the on-disk write
		writeErr(w, 500, "salvataggio fallito: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"evidence": ev, "url": evidenceURL(nodeID, name)})
}

// deriveEvidenceCaption builds a default figure caption for an evidence shot from the
// agent-written reproduction step it belongs to (step N: what that step proved): the caption is generated automatically from the
// reproduction text the agent already recorded, with no extra LLM call, and can still be edited manually. Returns "" for step 0 (overview) or when the vulnerability has no such step.
func (s *Server) deriveEvidenceCaption(nodeID int64, stepIndex int) string {
	if stepIndex <= 0 || s.m == nil || s.m.pg == nil {
		return ""
	}
	f, err := s.m.pg.GetFindingByNodeID(nodeID)
	if err != nil || f == nil || len(f.Reproduction) == 0 {
		return ""
	}
	var rp report.Reproduction
	if json.Unmarshal(f.Reproduction, &rp) != nil || stepIndex > len(rp.Steps) {
		return ""
	}
	st := rp.Steps[stepIndex-1]
	text := strings.TrimSpace(st.Proves)
	if text == "" {
		text = strings.TrimSpace(st.Expected)
	}
	if text == "" {
		return ""
	}
	text = strings.SplitN(text, "\n", 2)[0] // collapse to a single line, suitable for the caption under the thumbnail
	return clipUTF8(fmt.Sprintf("passo %d: %s", stepIndex, text), 120)
}

// GET /api/findings/{id}/evidence: list all of a vulnerability's evidence (with image-fetch urls).
func (s *Server) listFindingEvidence(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	nodeID, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "id vulnerabilità non valido")
		return
	}
	list, err := pg.ListFindingEvidence(nodeID)
	if err != nil {
		writeErr(w, 500, "recupero fallito")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, e := range list {
		out = append(out, map[string]any{"evidence": e, "url": evidenceURL(e.NodeID, e.Filename)})
	}
	writeJSON(w, 200, map[string]any{"items": out})
}

// PATCH /api/findings/{id}/evidence/{eid}: edit the caption / associated step / ordering.
func (s *Server) updateFindingEvidence(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	eid, ok := pathInt(r, "eid")
	if !ok {
		writeErr(w, 400, "id prova non valido")
		return
	}
	var req struct {
		Caption   string `json:"caption"`
		StepIndex int    `json:"step_index"`
		SortOrder int    `json:"sort_order"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "formato della richiesta errato")
		return
	}
	if err := pg.UpdateFindingEvidence(eid, req.Caption, req.StepIndex, req.SortOrder); err != nil {
		writeErr(w, 500, "salvataggio fallito: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// DELETE /api/findings/{id}/evidence/{eid}: delete the record + the disk file.
func (s *Server) deleteFindingEvidence(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	eid, ok := pathInt(r, "eid")
	if !ok {
		writeErr(w, 400, "id prova non valido")
		return
	}
	ev, err := pg.GetFindingEvidence(eid)
	if err != nil {
		writeErr(w, 404, "prova non trovata")
		return
	}
	if err := pg.DeleteFindingEvidence(eid); err != nil {
		writeErr(w, 500, "eliminazione fallita: "+err.Error())
		return
	}
	_ = os.Remove(filepath.Join(s.evidenceDir(ev.NodeID), filepath.Base(ev.Filename)))
	writeJSON(w, 200, map[string]any{"deleted": eid})
}

// GET /api/findings/{id}/evidence/{file}: fetch an evidence image (base name, path-traversal guard; cookie auth same as logo).
func (s *Server) serveFindingEvidence(w http.ResponseWriter, r *http.Request) {
	nodeID, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "id vulnerabilità non valido")
		return
	}
	file := filepath.Base(r.PathValue("file"))
	// fixed image Content-Type + no-sniff + inline: even if the file on disk is tampered with, the browser won't execute it as HTML/script.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch strings.ToLower(filepath.Ext(file)) {
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".jpg", ".jpeg":
		w.Header().Set("Content-Type", "image/jpeg")
	default:
		writeErr(w, 404, "not found")
		return
	}
	w.Header().Set("Content-Disposition", "inline")
	http.ServeFile(w, r, filepath.Join(s.evidenceDir(nodeID), file))
}

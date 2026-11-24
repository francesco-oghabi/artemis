package server

import (
	"net/http"

	"artemis/traffic"
)

// Vulnerability<->traffic association API. Associations live in PG; packet metadata is resolved by id from the traffic store (SQLite).
// Manual associations go through here (source=manual); in future the task engine can call pg.LinkFindingTraffic(..., "auto") directly to record them automatically.

// POST /api/findings/{id}/traffic: body {exchange_ids:[]} associates traffic with a vulnerability.
func (s *Server) linkFindingTraffic(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	nodeID, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "id vulnerabilità non valido")
		return
	}
	var req struct {
		ExchangeIDs []string `json:"exchange_ids"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "formato della richiesta errato")
		return
	}
	if err := pg.LinkFindingTraffic(nodeID, req.ExchangeIDs, "manual"); err != nil {
		writeErr(w, 500, "associazione fallita: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "linked": len(req.ExchangeIDs)})
}

// GET /api/findings/{id}/traffic: list the traffic associated with this vulnerability (with metadata; packet bodies fetched separately on demand).
func (s *Server) listFindingTraffic(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	nodeID, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "id vulnerabilità non valido")
		return
	}
	ids, err := pg.ListFindingTrafficIDs(nodeID)
	if err != nil {
		writeErr(w, 500, "recupero fallito")
		return
	}
	var metas []traffic.ExchangeMeta
	if tr := s.m.Traffic(); tr != nil && len(ids) > 0 {
		metas, _ = tr.MetaByIDs(ids)
	}
	writeJSON(w, 200, map[string]any{"exchanges": trafficDTOs(metas)})
}

// DELETE /api/findings/{id}/traffic/{eid}: remove the association.
func (s *Server) unlinkFindingTraffic(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	nodeID, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "id vulnerabilità non valido")
		return
	}
	if err := pg.UnlinkFindingTraffic(nodeID, r.PathValue("eid")); err != nil {
		writeErr(w, 500, "dissociazione fallita: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

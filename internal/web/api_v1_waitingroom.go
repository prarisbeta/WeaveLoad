package web

import (
	"net/http"
	"strconv"
	"time"

	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/waitingroom"
)

const (
	defaultWaitingMinutes = 10
	maxWaitingMinutes     = 60
	waitingLogLines       = 20000
)

// APIV1WaitingRoomHandler handles GET /api/v1/waiting-room?minutes=N: how many
// visitors are held on the waiting page (HTTP 429) right now, how many were let
// through, and how many gave up, estimated from the access log. It is what the
// MCP tool get_waiting_room reads.
type APIV1WaitingRoomHandler struct {
	LogPath string
	Now     func() time.Time
}

func (h *APIV1WaitingRoomHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	minutes := defaultWaitingMinutes
	if v := r.URL.Query().Get("minutes"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			writeAPIJSON(w, http.StatusBadRequest, APIResponse{Error: "minutes must be a positive integer"})
			return
		}
		minutes = n
	}
	if minutes > maxWaitingMinutes {
		minutes = maxWaitingMinutes
	}

	now := time.Now()
	if h.Now != nil {
		now = h.Now()
	}
	lines, err := haproxylog.Read(h.LogPath, haproxylog.Filter{Date: now, Limit: waitingLogLines})
	if err != nil {
		writeAPIJSON(w, http.StatusServiceUnavailable, APIResponse{Error: "access log is not readable: " + err.Error()})
		return
	}
	snap := waitingroom.Compute(lines, now, time.Duration(minutes)*time.Minute)
	writeAPIJSON(w, http.StatusOK, APIResponse{Success: true, Data: snap})
}

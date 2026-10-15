package web

import (
	"html/template"
	"net/http"

	"haproxy-gui/internal/haproxylog"
	"haproxy-gui/internal/traffic"
)

// TrafficHandler serves the /traffic page displaying live metrics, SVG charts, and top statistics.
type TrafficHandler struct {
	LogPath   string
	Templates *template.Template
}

func (h *TrafficHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	lines, _ := haproxylog.TailRecent(h.LogPath, 1000)
	summary := traffic.AggregateLines(lines)

	// Build sample SVG charts
	var reqPoints []traffic.DataPoint
	var errPoints []traffic.DataPoint

	if len(lines) > 0 {
		step := len(lines) / 10
		if step < 1 {
			step = 1
		}
		for i := 0; i < len(lines); i += step {
			l := lines[i]
			timeLabel := l.Time.Format("15:04:05")
			if timeLabel == "00:00:00" {
				timeLabel = "T"
			}
			reqPoints = append(reqPoints, traffic.DataPoint{Label: timeLabel, Value: float64(summary.TotalRequests) / 10.0})
			errPoints = append(errPoints, traffic.DataPoint{Label: timeLabel, Value: float64(summary.Total5xx)})
		}
	}

	chartReqSVG := traffic.RenderSVGChart("Permintaan Per Detik", "#0e7c86", reqPoints, "req/s")
	chartErrSVG := traffic.RenderSVGChart("Tingkat Error 5xx", "#b91c1c", errPoints, "count")

	data := struct {
		Chrome
		Summary     traffic.Summary
		ChartReqSVG template.HTML
		ChartErrSVG template.HTML
	}{
		Chrome:      NewChrome(r, "traffic"),
		Summary:     summary,
		ChartReqSVG: template.HTML(chartReqSVG),
		ChartErrSVG: template.HTML(chartErrSVG),
	}

	renderTemplate(w, h.Templates, "traffic.html", data)
}

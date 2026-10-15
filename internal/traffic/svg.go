package traffic

import (
	"fmt"
	"math"
	"strings"
)

// DataPoint represents a time-series metric value.
type DataPoint struct {
	Label string  // e.g. "10:00"
	Value float64 // e.g. 150.5
}

// RenderSVGChart generates a self-contained SVG chart with clean dark/light compatible styling.
func RenderSVGChart(title, color string, points []DataPoint, unit string) string {
	if len(points) == 0 {
		return `<svg viewBox="0 0 500 150" xmlns="http://www.w3.org/2000/svg" style="width:100%;height:150px;background:var(--surface);border-radius:8px;"><text x="250" y="75" text-anchor="middle" fill="var(--ink-muted)" font-size="12">Belum ada data metrik</text></svg>`
	}

	width := 500.0
	height := 160.0
	paddingLeft := 40.0
	paddingBottom := 30.0
	paddingTop := 25.0
	paddingRight := 15.0

	chartWidth := width - paddingLeft - paddingRight
	chartHeight := height - paddingTop - paddingBottom

	maxVal := 0.0
	for _, p := range points {
		if p.Value > maxVal {
			maxVal = p.Value
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	stepX := chartWidth / float64(math.Max(1, float64(len(points)-1)))
	if len(points) == 1 {
		stepX = chartWidth / 2
	}

	var pathPoints []string
	var areaPoints []string

	areaPoints = append(areaPoints, fmt.Sprintf("%.1f,%.1f", paddingLeft, height-paddingBottom))

	for i, p := range points {
		x := paddingLeft + float64(i)*stepX
		y := height - paddingBottom - (p.Value/maxVal)*chartHeight

		ptStr := fmt.Sprintf("%.1f,%.1f", x, y)
		pathPoints = append(pathPoints, ptStr)
		areaPoints = append(areaPoints, ptStr)
	}

	lastX := paddingLeft + float64(len(points)-1)*stepX
	if len(points) == 1 {
		lastX = paddingLeft + stepX
	}
	areaPoints = append(areaPoints, fmt.Sprintf("%.1f,%.1f", lastX, height-paddingBottom))

	pathData := strings.Join(pathPoints, " L ")
	if len(pathPoints) > 0 {
		pathData = "M " + pathData
	}
	areaData := strings.Join(areaPoints, " L ") + " Z"

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg viewBox="0 0 %.0f %.0f" xmlns="http://www.w3.org/2000/svg" style="width:100%%;height:100%%;background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:8px;">`, width, height))

	// Title
	sb.WriteString(fmt.Sprintf(`<text x="%.0f" y="16" fill="var(--ink)" font-size="12" font-weight="600">%s (%s)</text>`, paddingLeft, title, unit))

	// Grid lines
	gridCount := 3
	for i := 0; i <= gridCount; i++ {
		y := paddingTop + float64(i)*(chartHeight/float64(gridCount))
		val := maxVal * (1.0 - float64(i)/float64(gridCount))
		sb.WriteString(fmt.Sprintf(`<line x1="%.0f" y1="%.1f" x2="%.0f" y2="%.1f" stroke="var(--border)" stroke-dasharray="3,3" stroke-width="1"/>`, paddingLeft, y, width-paddingRight, y))
		sb.WriteString(fmt.Sprintf(`<text x="%.0f" y="%.1f" fill="var(--ink-muted)" font-size="9" text-anchor="end">%.1f</text>`, paddingLeft-6, y+3, val))
	}

	// Area fill
	sb.WriteString(fmt.Sprintf(`<path d="M %s" fill="%s" fill-opacity="0.12"/>`, areaData, color))

	// Line path
	sb.WriteString(fmt.Sprintf(`<path d="%s" fill="none" stroke="%s" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>`, pathData, color))

	// X-axis Labels (first and last)
	if len(points) > 0 {
		sb.WriteString(fmt.Sprintf(`<text x="%.0f" y="%.0f" fill="var(--ink-muted)" font-size="9" text-anchor="start">%s</text>`, paddingLeft, height-8, points[0].Label))
		sb.WriteString(fmt.Sprintf(`<text x="%.0f" y="%.0f" fill="var(--ink-muted)" font-size="9" text-anchor="end">%s</text>`, width-paddingRight, height-8, points[len(points)-1].Label))
	}

	sb.WriteString(`</svg>`)
	return sb.String()
}

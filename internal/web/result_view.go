package web

import "net/http"

// ResultView is the data for the validate_result.html and apply_result.html
// partials. They translate their headings, so they need the request's
// language alongside the outcome.
type ResultView struct {
	Language string
	OK       bool
	Output   string
}

func newResultView(r *http.Request, ok bool, output string) ResultView {
	return ResultView{Language: NewChrome(r, "").Language, OK: ok, Output: output}
}

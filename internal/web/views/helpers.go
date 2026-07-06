package views

import (
	"encoding/json"
	"strconv"

	"github.com/a-h/templ"
)

func itoa(n int) string     { return strconv.Itoa(n) }
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// alpineShareData builds the Alpine x-data object literal for ShareLink, JSON-encoding
// url so it is safe regardless of its contents (it's a generated /share/{token} URL, but
// this keeps the attribute construction honest rather than hand-quoting).
func alpineShareData(url string) string {
	b, _ := json.Marshal(url)
	return "{ url: " + string(b) + ", copied: false }"
}

// formAction is the POST target for the secret form: /secrets for a new secret (id 0),
// /secrets/{id} for an edit.
func formAction(id int64) templ.SafeURL {
	if id == 0 {
		return templ.SafeURL("/secrets")
	}
	return templ.SafeURL("/secrets/" + itoa64(id))
}

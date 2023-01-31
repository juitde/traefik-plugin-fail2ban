package traefik_plugin_fail2ban //nolint:revive,stylecheck

import (
	"net/http"
	"strconv"
)

// ResponseWriter wrapping original ResponseWriter with response check handling.
type ResponseWriter struct {
	http.ResponseWriter

	cacheEntry *CacheEntry
	rules      responseRules
}

// WriteHeader wraps original WriteHeader whilst checking for response status code.
func (rw *ResponseWriter) WriteHeader(code int) {
	// Intercept WriteHeader to check for responseCode
	defer rw.ResponseWriter.WriteHeader(code)

	if rw.rules.StatusCode != nil {
		if rw.rules.StatusCode.MatchString(strconv.Itoa(code)) {
			rw.cacheEntry.IncrementTimesSeen()
		}
	}
}

// Write wraps original Write whilst checking for response body.
func (rw *ResponseWriter) Write(data []byte) (status int, err error) {
	// Intercept Write to check for response body
	defer func() {
		status, err = rw.ResponseWriter.Write(data)
	}()

	return 0, nil
}

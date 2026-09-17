package scanner

import (
	"bufio"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
)

// Decode the captured response only; never follow a Location or fetch another URL.
func parseSearchHTTP(banner string) (string, string) {
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(banner)), nil)
	if err != nil {
		return "", ""
	}
	defer func() { _ = response.Body.Close() }()
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || response.StatusCode != http.StatusOK {
		return "", ""
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 {
		return "", ""
	}
	var root struct {
		Tagline string `json:"tagline"`
		Version struct {
			Number string `json:"number"`
			Lucene string `json:"lucene_version"`
		} `json:"version"`
	}
	if json.Unmarshal(body, &root) != nil || root.Tagline != "You Know, for Search" ||
		strings.TrimSpace(root.Version.Number) == "" || strings.TrimSpace(root.Version.Lucene) == "" {
		return "", ""
	}
	return "elasticsearch", "Elasticsearch " + sanitizeVersionString(root.Version.Number)
}

func httpBannerEvidence(banner string) string {
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(banner)), nil)
	if err != nil {
		return ""
	}
	defer func() { _ = response.Body.Close() }()
	parts := []string{response.Proto + " " + response.Status}
	for _, key := range []string{"Server", "Location"} {
		if value := response.Header.Get(key); value != "" {
			parts = append(parts, key+": "+value)
		}
	}
	if service, version := parseSearchHTTP(banner); service != "" {
		parts = append(parts, version+" (JSON version.number)")
	}
	return sanitizeVersionString(strings.Join(parts, "; "))
}

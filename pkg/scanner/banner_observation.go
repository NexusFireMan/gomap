package scanner

import (
	"bufio"
	"strings"
	"unicode"
	"unicode/utf8"
)

func binaryTextObservation(banner string) bool {
	if !utf8.ValidString(banner) {
		return true
	}
	for _, c := range banner {
		if unicode.IsControl(c) && c != '\r' && c != '\n' && c != '\t' {
			return true
		}
	}
	return false
}

// Keep legacy pure parsers useful for standalone fixture strings. Runtime
// observations must additionally prove that the disclosure itself is complete.
func observedBannerText(banner string) (string, bool) {
	if respBannerPrefix(banner) {
		r := bufio.NewReaderSize(strings.NewReader(banner), 512)
		t := &textTransactionReader{r: r, limit: respTransactionLimit}
		_, err := t.resp(0, new(int))
		return banner, err != nil || len(t.data) != len(banner)
	}
	if binaryTextObservation(banner) {
		return banner, true
	}
	if validHTTPResponseLine(banner) || strings.HasPrefix(banner, "RTSP/") || strings.HasPrefix(banner, "SIP/") {
		if strings.Contains(banner, "\r\n\r\n") || strings.Contains(banner, "\n\n") {
			return banner, false
		}
		line := strings.SplitN(banner, "\n", 2)[0]
		return line + "\r\n", true
	}
	end := strings.LastIndexByte(banner, '\n')
	if end < 0 || !textGreetingComplete([]byte(banner)) {
		return banner, true
	}
	return banner[:end+1], false
}

func parseObservedBanner(banner string) (string, string) {
	text, incomplete := observedBannerText(banner)
	if incomplete {
		if binaryTextObservation(banner) {
			return "", ""
		}
		if respBannerPrefix(banner) {
			return "", ""
		}
		service, _ := parseBanner(text)
		return service, ""
	}
	service, version := parseBanner(text)
	if service == "redis" && !strings.HasPrefix(text, "$") && !strings.HasPrefix(text, "-NOAUTH ") {
		return "", ""
	}
	return service, version
}

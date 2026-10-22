package scanner

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"testing"
)

func TestHTTPVersionRequiresCompleteUnambiguousHeaders(t *testing.T) {
	for _, banner := range []string{
		"HTTP/1.1 200 OK\r\nServer: nginx/1.",
		"HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\nContent-Length:",
		"HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\nServer: Apache/9.9\r\n\r\n",
		"HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\nnot-a-header\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-Title: <title>Apache Tomcat/9.9</title>\r\n\r\n",
	} {
		service, version := parseHTTP(banner)
		if service != "http" || version != "" {
			t.Errorf("unverified product version accepted: service=%q version=%q", service, version)
		}
	}
	for _, banner := range []string{
		"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 100\r\n\r\nshort-body",
		"HTTP/1.1 200 OK\r\nserver: nginx/1.24.0\r\n\r\n",
	} {
		if service, version := parseHTTP(banner); service != "http" || version != "Nginx 1.24.0" {
			t.Fatal("complete server disclosure lost because of body truncation/header case")
		}
	}
}

func TestHTTPTitleRequiresFramedBody(t *testing.T) {
	var wire bytes.Buffer
	wire.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
	chunks := httputil.NewChunkedWriter(&wire)
	for _, fragment := range []string{"<title>Apache ", "Tomcat/9.0.17</title>"} {
		if _, err := io.WriteString(chunks, fragment); err != nil {
			t.Fatal(err)
		}
	}
	if err := chunks.Close(); err != nil {
		t.Fatal(err)
	}
	wire.WriteString("\r\n")
	if service, version := parseHTTP(wire.String()); service != "http" || version != "Apache Tomcat 9.0.17" {
		t.Fatal("chunked HTTP body title was not decoded before parsing")
	}
	for _, banner := range []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n<title>Apache Tomcat/9.9</title>",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n<title>Apache Tomcat/9.9</title>",
	} {
		if service, version := parseHTTP(banner); service != "http" || version != "" {
			t.Fatal("truncated or out-of-body content became a product version")
		}
	}
}

func FuzzHTTPHeaderBoundaries(f *testing.F) {
	f.Add("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n")
	f.Add("HTTP/1.1 200 OK\r\nServer: nginx/1.")
	f.Add("HTTP/1.1 200 OK\r\nServer: one\r\nServer: two\r\n\r\n")
	f.Fuzz(func(t *testing.T, banner string) {
		banner = banner[:min(len(banner), 64*1024)]
		service, version := parseHTTP(banner)
		if len(version) > 64*1024 || (service != "" && service != "http" && service != "ipp") {
			t.Fatal("HTTP parser exceeded its scope/size bound")
		}
		if version == "" {
			return
		}
		response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(strings.TrimLeft(banner, " \t\r\n"))), nil)
		if err != nil {
			t.Fatal("version claimed without complete valid headers")
		}
		defer func() { _ = response.Body.Close() }()
		if len(response.Header.Values("Server")) > 1 {
			t.Fatal("ambiguous Server headers became a version")
		}
	})
}

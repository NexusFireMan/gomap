package scanner

import (
	"reflect"
	"testing"
	"time"
)

func TestMergeKeepsIdentificationEvidenceTogether(t *testing.T) {
	ssh := ScanResult{Port: 2222, IsOpen: true, ServiceName: "ssh", Version: "OpenSSH 9.6", Confidence: "high", Evidence: "SSH-2.0-OpenSSH_9.6", DetectionPath: "banner-parser"}
	for _, tc := range []struct {
		name string
		a, b ScanResult
		want ScanResult
	}{
		{"weak port hint cannot replace banner", ssh, ScanResult{ServiceName: "http", Confidence: "low", Evidence: "port map", DetectionPath: "portmap"}, ssh},
		{"unknown cannot replace known", ssh, ScanResult{ServiceName: "unknown", Version: "unparsed", Confidence: "low", Evidence: "port open"}, ssh},
		{"empty identification cannot attach new confidence", ssh, ScanResult{Confidence: "high", Evidence: "unrelated", DetectionPath: "other"}, ssh},
		{"stronger service does not inherit old version", ScanResult{Port: 2222, IsOpen: true, ServiceName: "http", Version: "Apache", Confidence: "low", Evidence: "port map"}, ScanResult{ServiceName: "ssh", Confidence: "high", Evidence: "SSH protocol response", DetectionPath: "banner-parser"}, ScanResult{Port: 2222, IsOpen: true, ServiceName: "ssh", Confidence: "high", Evidence: "SSH protocol response", DetectionPath: "banner-parser"}},
		{"equal quality retains original observation", ssh, ScanResult{ServiceName: "http", Version: "nginx/1.0", Confidence: "high", Evidence: "HTTP response", DetectionPath: "banner-parser"}, ssh},
		{"missing confidence cannot outrank low", ScanResult{ServiceName: "ssh", Confidence: "low"}, ScanResult{ServiceName: "http", Version: "Apache", Confidence: "unrecognized"}, ScanResult{ServiceName: "ssh", Confidence: "low"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mergeOpenResult(tc.a, tc.b); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("incoherent observation: got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestMergeCanSelectRicherIdentificationAtEqualConfidence(t *testing.T) {
	a := ScanResult{Port: 22, IsOpen: true, ServiceName: "ssh", Confidence: "high", Evidence: "protocol response"}
	b := ScanResult{ServiceName: "ssh", Version: "OpenSSH 9.6", Confidence: "high", Evidence: "SSH-2.0-OpenSSH_9.6", DetectionPath: "banner-parser"}
	got := mergeOpenResult(a, b)
	if got.Version != b.Version || got.Evidence != b.Evidence || got.DetectionPath != b.DetectionPath || got.Port != a.Port || !got.IsOpen {
		t.Fatalf("lost richer identification: %+v", got)
	}
}

func TestMergeIdentificationAlwaysBelongsToOneObservation(t *testing.T) {
	identification := func(r ScanResult) [5]string {
		return [5]string{r.ServiceName, r.Version, r.Confidence, r.Evidence, r.DetectionPath}
	}
	for _, ca := range []string{"", "low", "medium", "high", "invalid"} {
		for _, cb := range []string{"", "low", "medium", "high", "invalid"} {
			for _, sa := range []string{"", "unknown", "ssh", "http"} {
				for _, sb := range []string{"", "unknown", "ssh", "http"} {
					for _, version := range []string{"", "fixture version"} {
						a := ScanResult{ServiceName: sa, Confidence: ca, Evidence: "observation A", DetectionPath: "fixture-A"}
						b := ScanResult{ServiceName: sb, Version: version, Confidence: cb, Evidence: "observation B", DetectionPath: "fixture-B"}
						got := identification(mergeOpenResult(a, b))
						if got != identification(a) && got != identification(b) {
							t.Fatalf("mixed identification: %+v", got)
						}
					}
				}
			}
		}
	}
}

func TestMergeTLSMetadataIsAtomicAndPreservesCompleteHandshake(t *testing.T) {
	a := ScanResult{Port: 443, IsOpen: true, TLS: true, TLSVersion: "TLS1.3", TLSCipher: "TLS_AES_128_GCM_SHA256", TLSALPN: "h2", TLSServerName: "fixture.invalid", TLSIssuer: "Fixture CA"}
	for _, b := range []ScanResult{{TLS: true}, {TLS: true, TLSVersion: "TLS1.2"}, {TLS: true, TLSCipher: "partial"}} {
		if got := mergeOpenResult(a, b); !reflect.DeepEqual(got, a) {
			t.Fatalf("partial TLS metadata damaged handshake: %+v", got)
		}
	}
	b := ScanResult{TLS: true, TLSVersion: "TLS1.2", TLSCipher: "fixture cipher"}
	got := mergeOpenResult(a, b)
	if got.TLSVersion != b.TLSVersion || got.TLSCipher != b.TLSCipher || got.TLSALPN != "" || got.TLSServerName != "" || got.TLSIssuer != "" {
		t.Fatalf("mixed independent handshakes: %+v", got)
	}
}

func TestDedupeRetainsStrongEvidenceAndIsIdempotent(t *testing.T) {
	strong := ScanResult{Port: 22, IsOpen: true, ServiceName: "ssh", Version: "OpenSSH 9.6", Confidence: "high", Evidence: "SSH greeting", DetectionPath: "banner-parser"}
	weak := ScanResult{Port: 22, IsOpen: true, ServiceName: "ssh", Confidence: "low", Evidence: "port map", Latency: time.Millisecond, LatencyMs: 1}
	for _, inputs := range [][]ScanResult{{strong, weak}, {weak, strong}} {
		results := dedupeOpenResults(append(inputs, ScanResult{Port: 21, IsOpen: true}))
		if len(results) != 2 || results[0].Port != 21 || results[1].Version != strong.Version || results[1].Evidence != strong.Evidence || results[1].Confidence != strong.Confidence {
			t.Fatalf("deduplication lost evidence: %+v", results)
		}
		if again := dedupeOpenResults(results); !reflect.DeepEqual(results, again) {
			t.Fatal("deduplication not idempotent")
		}
	}
}

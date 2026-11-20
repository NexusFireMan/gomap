package scanner

import (
	"fmt"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestUDPBoundedQueuePreservesFullRangeAndStates(t *testing.T) {
	for _, workers := range []int{1, 16, 200} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			s := NewScanner("unused", false)
			s.NumWorkers = workers
			ports := make([]int, 65535)
			for i := range ports {
				ports[i] = i + 1
			}
			ports = append(ports, 1, 65535)
			var active, peak, calls atomic.Int32
			states := []string{"open", "closed", "open|filtered", "unknown"}
			got := s.scanUDPWithProbe(ports, true, func(port int, detect bool) ScanResult {
				if !detect {
					t.Error("detection flag lost")
				}
				n := active.Add(1)
				for old := peak.Load(); old < n && !peak.CompareAndSwap(old, n); old = peak.Load() {
				}
				runtime.Gosched()
				calls.Add(1)
				active.Add(-1)
				state := states[port%len(states)]
				return ScanResult{Port: port, State: state, IsOpen: state == "open", Evidence: "fixture", Confidence: "low"}
			})
			if len(got) != 65535 || calls.Load() != 65535 || active.Load() != 0 || peak.Load() > int32(workers) {
				t.Fatalf("lost work or concurrency exceeded: results=%d calls=%d peak=%d", len(got), calls.Load(), peak.Load())
			}
			for i, result := range got {
				if result.Port != i+1 || result.EffectiveState() != states[(i+1)%len(states)] || result.Evidence != "fixture" {
					t.Fatalf("observation lost or reordered: %+v", result)
				}
			}
		})
	}
}

func TestUDPBoundedQueueEmpty(t *testing.T) {
	s := NewScanner("unused", false)
	got := s.scanUDPWithProbe(nil, false, func(int, bool) ScanResult { t.Error("unexpected probe"); return ScanResult{} })
	if len(got) != 0 {
		t.Fatal(got)
	}
}

func BenchmarkUDPBoundedQueue(b *testing.B) {
	ports := make([]int, 65535)
	for i := range ports {
		ports[i] = i + 1
	}
	s := NewScanner("unused", false)
	s.NumWorkers = 32
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(s.scanUDPWithProbe(ports, false, func(port int, _ bool) ScanResult { return ScanResult{Port: port, State: "unknown"} })) != len(ports) {
			b.Fatal("missing results")
		}
	}
}

var benchmarkUDPResultQueue chan ScanResult

// Isolate queue storage, not total scan memory or device performance.
func BenchmarkUDPResultQueueCapacity(b *testing.B) {
	for _, capacity := range []int{32, 200, 65535} {
		b.Run(fmt.Sprint(capacity), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchmarkUDPResultQueue = make(chan ScanResult, capacity)
			}
		})
	}
}

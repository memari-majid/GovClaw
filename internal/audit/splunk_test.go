package audit

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testSplunkForwarder(t *testing.T, handler http.HandlerFunc) *SplunkForwarder {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	cfg := SplunkConfig{
		HECEndpoint: srv.URL,
		HECToken:    "test-token",
		Index:       "test",
		Source:      "test",
		SourceType:  "_json",
		VerifyTLS:   false,
		BatchSize:   5,
	}
	f := &SplunkForwarder{
		cfg:    cfg,
		client: srv.Client(),
	}
	return f
}

func makeEvent(action string) Event {
	return Event{
		ID:        "evt-" + action,
		Timestamp: time.Now().UTC(),
		Action:    action,
		Target:    "test-target",
		Actor:     "test",
		Details:   "test details",
		Severity:  "info",
	}
}

func TestSplunkForwardEventConcurrency(t *testing.T) {
	var hits atomic.Int64
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = f.ForwardEvent(makeEvent("concurrent"))
		}(i)
	}
	wg.Wait()

	_ = f.Flush()

	if hits.Load() == 0 {
		t.Error("expected at least one HEC request")
	}
}

func TestSplunkFlushConcurrency(t *testing.T) {
	var hits atomic.Int64
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 3; i++ {
		_ = f.ForwardEvent(makeEvent("pre-flush"))
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = f.Flush()
		}()
	}
	wg.Wait()
}

func TestSplunkBatchFlushesAtThreshold(t *testing.T) {
	var hits atomic.Int64
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < f.cfg.BatchSize; i++ {
		_ = f.ForwardEvent(makeEvent("batch"))
	}

	if hits.Load() < 1 {
		t.Errorf("expected flush at batch size %d, got %d HEC calls", f.cfg.BatchSize, hits.Load())
	}
}

func TestSplunkFlushRequeuesOnFailure(t *testing.T) {
	callCount := 0
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	for i := 0; i < 3; i++ {
		_ = f.ForwardEvent(makeEvent("requeue"))
	}

	err := f.Flush()
	if err == nil {
		t.Fatal("expected error on first flush (503)")
	}

	f.mu.Lock()
	batchLen := len(f.batch)
	f.mu.Unlock()
	if batchLen != 3 {
		t.Errorf("expected 3 events requeued after failure, got %d", batchLen)
	}

	err = f.Flush()
	if err != nil {
		t.Fatalf("second flush should succeed: %v", err)
	}

	f.mu.Lock()
	batchLen = len(f.batch)
	f.mu.Unlock()
	if batchLen != 0 {
		t.Errorf("batch should be empty after successful flush, got %d", batchLen)
	}
}

func TestSplunkFlushRequeuePreservesNewEvents(t *testing.T) {
	callCount := 0
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	_ = f.ForwardEvent(makeEvent("old-1"))
	_ = f.ForwardEvent(makeEvent("old-2"))

	// First flush fails
	_ = f.Flush()

	// New event added after failed flush
	_ = f.ForwardEvent(makeEvent("new-1"))

	f.mu.Lock()
	batchLen := len(f.batch)
	f.mu.Unlock()
	if batchLen != 3 {
		t.Errorf("expected 3 events (2 requeued + 1 new), got %d", batchLen)
	}

	// Second flush should succeed with all events
	err := f.Flush()
	if err != nil {
		t.Fatalf("second flush should succeed: %v", err)
	}
}

func TestSplunkFlushEmptyBatchIsNoOp(t *testing.T) {
	var hits atomic.Int64
	f := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	})

	_ = f.Flush()
	if hits.Load() != 0 {
		t.Error("flush on empty batch should not call HEC")
	}
}

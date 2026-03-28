package codex

import "testing"

func TestPendingQueueLengthCountsPendingAndProcessingOnly(t *testing.T) {
	cfg := newTestConfig(t)
	store := NewStateStore(cfg, nil)

	if got := store.PendingQueueLength(); got != 0 {
		t.Fatalf("expected empty queue length 0, got %d", got)
	}

	for _, email := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		if err := store.EnqueuePending(email, "secret", "tabmail", "", ""); err != nil {
			t.Fatalf("enqueue %s: %v", email, err)
		}
	}

	if got := store.PendingQueueLength(); got != 3 {
		t.Fatalf("expected pending length 3, got %d", got)
	}

	item := store.DequeuePending()
	if item == nil {
		t.Fatal("expected pending item after dequeue")
	}
	if got := store.PendingQueueLength(); got != 3 {
		t.Fatalf("processing item should still be counted, got %d", got)
	}

	store.MarkPendingDone(item.Email, "done")
	if got := store.PendingQueueLength(); got != 2 {
		t.Fatalf("expected done item to be excluded, got %d", got)
	}

	store.MarkPendingDone("b@example.com", "failed")
	if got := store.PendingQueueLength(); got != 1 {
		t.Fatalf("expected failed item to be excluded, got %d", got)
	}
}

package codex

import (
	"encoding/json"
	"testing"
)

func TestAnalyzeUsageStatus(t *testing.T) {
	t.Run("healthy under threshold", func(t *testing.T) {
		body := map[string]any{
			"rate_limit": map[string]any{
				"primary_window": map[string]any{"used_percent": 12.5},
				"allowed":        true,
			},
		}

		used, over, quota, healthy := AnalyzeUsageStatus(200, body, "", 90)
		if used == nil || *used != 12.5 {
			t.Fatalf("expected used percent 12.5, got %#v", used)
		}
		if over || quota || !healthy {
			t.Fatalf("expected healthy result, got over=%v quota=%v healthy=%v", over, quota, healthy)
		}
	})

	t.Run("threshold uses max window and marks quota", func(t *testing.T) {
		body := map[string]any{
			"rate_limit": map[string]any{
				"primary_window":   map[string]any{"used_percent": 64.0},
				"secondary_window": map[string]any{"used_percent": 91.0},
				"allowed":          true,
			},
		}

		used, over, quota, healthy := AnalyzeUsageStatus(200, body, "", 90)
		if used == nil || *used != 91.0 {
			t.Fatalf("expected max used percent 91, got %#v", used)
		}
		if !over || !quota || healthy {
			t.Fatalf("expected over threshold quota result, got over=%v quota=%v healthy=%v", over, quota, healthy)
		}
	})

	t.Run("402 and markers imply quota", func(t *testing.T) {
		body := map[string]any{
			"rate_limit": map[string]any{
				"allowed": false,
			},
		}

		used, over, quota, healthy := AnalyzeUsageStatus(402, body, "payment_required", 90)
		if used != nil {
			t.Fatalf("expected nil used percent, got %#v", used)
		}
		if over || !quota || healthy {
			t.Fatalf("expected quota result, got over=%v quota=%v healthy=%v", over, quota, healthy)
		}
	})
}

func TestNormalizeUsedPercent(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want float64
	}{
		{name: "negative clamped", in: -3.0, want: 0},
		{name: "json number", in: json.Number("87.5"), want: 87.5},
		{name: "over 100 clamped", in: 130, want: 100},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeUsedPercent(tc.in)
			if got == nil || *got != tc.want {
				t.Fatalf("expected %v, got %#v", tc.want, got)
			}
		})
	}
}

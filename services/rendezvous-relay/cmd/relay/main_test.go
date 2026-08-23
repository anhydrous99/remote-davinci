package main

import "testing"

func TestPairActivationsPerSourceHour(t *testing.T) {
	const name = "PAIR_ACTIVATIONS_PER_SOURCE_PER_HOUR"
	for _, test := range []struct {
		name  string
		value string
		want  int64
		valid bool
	}{
		{"beta default", "10", 10, true},
		{"shared NAT tuning", "100", 100, true},
		{"minimum", "1", 1, true},
		{"maximum", "10000", 10_000, true},
		{"unset beta default", "", 10, true},
		{"zero", "0", 0, false},
		{"too high", "10001", 0, false},
		{"not an integer", "ten", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(name, test.value)
			got, err := pairActivationsPerSourceHour()
			if (err == nil) != test.valid || got != test.want {
				t.Fatalf("limit = %d, error = %v", got, err)
			}
		})
	}
}

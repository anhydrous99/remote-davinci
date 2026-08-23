package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunSummarizesSamples(t *testing.T) {
	var output bytes.Buffer
	if err := run(
		[]string{"-segment", "Companion operation", "-unit", "ns"},
		strings.NewReader("# duration_ns\n2000000\n1000000\n4000000\n3000000\n"),
		&output,
	); err != nil {
		t.Fatal(err)
	}
	var got summary
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Segment != "Companion operation" || got.Samples != 4 || got.P50Milliseconds != 2 || got.P95Milliseconds != 4 || got.P99Milliseconds != 4 || got.MaximumMilliseconds != 4 {
		t.Fatalf("summary = %#v", got)
	}
}

func TestRunRejectsInvalidInput(t *testing.T) {
	for _, test := range []struct {
		args  []string
		input string
	}{
		{[]string{"-unit", "ms"}, "1\n"},
		{[]string{"-segment", "test", "-unit", "minutes"}, "1\n"},
		{[]string{"-segment", "test"}, "0\n"},
		{[]string{"-segment", "test"}, "NaN\n"},
		{[]string{"-segment", "test"}, "not-a-number\n"},
		{[]string{"-segment", "test", "-unit", "ns"}, "0.1\n"},
		{[]string{"-segment", "test", "-unit", "ns"}, "9223372036854775807\n"},
		{[]string{"-segment", "test"}, "\n# comment\n"},
	} {
		if err := run(test.args, strings.NewReader(test.input), &bytes.Buffer{}); err == nil {
			t.Fatalf("run(%v, %q) succeeded", test.args, test.input)
		}
	}
}

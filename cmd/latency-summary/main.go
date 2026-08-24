// Command latency-summary turns one duration per line into template-ready percentiles.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

type summary struct {
	Segment             string  `json:"segment"`
	Samples             int     `json:"samples"`
	P50Milliseconds     float64 `json:"p50Milliseconds"`
	P95Milliseconds     float64 `json:"p95Milliseconds"`
	P99Milliseconds     float64 `json:"p99Milliseconds"`
	MaximumMilliseconds float64 `json:"maximumMilliseconds"`
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "latency-summary:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("latency-summary", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	segment := flags.String("segment", "", "template segment name")
	unit := flags.String("unit", "ms", "input unit: ns, us, ms, or s")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *segment == "" || len(*segment) > 80 || strings.ContainsAny(*segment, "\r\n") {
		return errors.New("segment must be a non-empty single-line label of at most 80 bytes")
	}
	if flags.NArg() > 1 {
		return errors.New("provide at most one sample file")
	}
	reader := stdin
	var file *os.File
	if flags.NArg() == 1 {
		var err error
		file, err = os.Open(flags.Arg(0))
		if err != nil {
			return err
		}
		defer file.Close()
		reader = file
	}
	factor, err := unitFactor(*unit)
	if err != nil {
		return err
	}
	samples, err := readSamples(reader, factor)
	if err != nil {
		return err
	}
	if len(samples) == 0 {
		return errors.New("no duration samples")
	}
	result := summarize(*segment, samples)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func unitFactor(unit string) (float64, error) {
	switch unit {
	case "ns":
		return 1, nil
	case "us":
		return float64(time.Microsecond), nil
	case "ms":
		return float64(time.Millisecond), nil
	case "s":
		return float64(time.Second), nil
	default:
		return 0, errors.New("unit must be ns, us, ms, or s")
	}
}

func readSamples(reader io.Reader, nanosecondsPerUnit float64) ([]time.Duration, error) {
	scanner := bufio.NewScanner(reader)
	var samples []time.Duration
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		value, err := strconv.ParseFloat(line, 64)
		nanoseconds := value * nanosecondsPerUnit
		rounded := math.Round(nanoseconds)
		if err != nil || math.IsNaN(nanoseconds) || math.IsInf(nanoseconds, 0) || rounded < 1 || rounded >= float64(math.MaxInt64) {
			return nil, fmt.Errorf("line %d is not a positive finite duration", lineNumber)
		}
		samples = append(samples, time.Duration(rounded))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return samples, nil
}

func summarize(segment string, samples []time.Duration) summary {
	ordered := slices.Clone(samples)
	slices.Sort(ordered)
	value := func(percentile int) time.Duration {
		rank := (percentile*len(ordered) + 99) / 100
		return ordered[rank-1]
	}
	toMilliseconds := func(duration time.Duration) float64 {
		return float64(duration) / float64(time.Millisecond)
	}
	return summary{
		Segment: segment, Samples: len(ordered),
		P50Milliseconds:     toMilliseconds(value(50)),
		P95Milliseconds:     toMilliseconds(value(95)),
		P99Milliseconds:     toMilliseconds(value(99)),
		MaximumMilliseconds: toMilliseconds(value(100)),
	}
}

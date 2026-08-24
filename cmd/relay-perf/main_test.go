package main

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/anhydrous99/remote-davinci/internal/companion"
)

func TestParseConfigRequiresDisposableNonProductionTarget(t *testing.T) {
	valid := []string{"-relay", "wss://example.execute-api.us-east-1.amazonaws.com/v1"}
	if _, err := parseConfig(valid, func(string) string { return "" }); err == nil || !strings.Contains(err.Error(), disposableOptIn) {
		t.Fatalf("missing opt-in error = %v", err)
	}
	production, err := url.Parse(companion.DefaultRelayURL)
	if err != nil {
		t.Fatal(err)
	}
	productionTargets := []string{
		companion.DefaultRelayURL,
		"wss://" + strings.ToUpper(production.Hostname()) + ":443" + production.EscapedPath(),
	}
	for _, target := range productionTargets {
		if _, err := parseConfig(
			[]string{"-relay", target},
			func(string) string { return "1" },
		); err == nil || !strings.Contains(err.Error(), "production") {
			t.Fatalf("production target %q error = %v", target, err)
		}
	}
	config, err := parseConfig(valid, func(name string) string {
		if name == disposableOptIn {
			return "1"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.pairs != 1 || config.roundTripsPS != 10 || config.duration != 30*time.Second || config.payloadBytes != 256 {
		t.Fatalf("defaults = %#v", config)
	}
}

func TestRunConfigBounds(t *testing.T) {
	base := runConfig{
		relayURL: "wss://example.com/v1", pairs: 1, roundTripsPS: 10,
		duration: time.Second, payloadBytes: 1, setupWorkers: 1, disposableOptIn: "1",
	}
	tests := []struct {
		name   string
		mutate func(*runConfig)
		want   string
	}{
		{"pairs", func(config *runConfig) { config.pairs = 0 }, "pairs"},
		{"too many pairs", func(config *runConfig) { config.pairs = maxPairs + 1 }, "pairs"},
		{"rate", func(config *runConfig) { config.roundTripsPS = 61 }, "rps"},
		{"duration", func(config *runConfig) { config.duration = time.Millisecond }, "duration"},
		{"samples", func(config *runConfig) {
			config.pairs, config.roundTripsPS, config.duration = 60, 3_600, 3*time.Hour
		}, "samples"},
		{"payload", func(config *runConfig) { config.payloadBytes = 0 }, "payload-bytes"},
		{"workers", func(config *runConfig) { config.setupWorkers = 0 }, "setup-workers"},
		{"scheme", func(config *runConfig) { config.relayURL = "https://example.com/v1" }, "wss://"},
		{"empty query", func(config *runConfig) { config.relayURL = "wss://example.com/v1?" }, "without query"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			if err := config.validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestPairCreatePacerMatchesRelayAdmissionAndHonorsCancellation(t *testing.T) {
	if pairCreateInterval != 12*time.Second {
		t.Fatalf("pair create interval = %v", pairCreateInterval)
	}
	pacer := pairCreatePacer{interval: time.Hour}
	calls := 0
	provision := func(context.Context, string) (*loadPair, error) {
		calls++
		return &loadPair{}, nil
	}
	if _, err := pacer.provision(t.Context(), "wss://disposable.example/v1", provision); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := pacer.provision(cancelled, "wss://disposable.example/v1", provision); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled pace error = %v", err)
	}
	if calls != 1 {
		t.Fatalf("provision calls = %d", calls)
	}
}

func TestPercentileAndSummary(t *testing.T) {
	samples := []time.Duration{20, 10, 40, 30}
	for percentileValue, want := range map[int]time.Duration{50: 20, 95: 40, 99: 40, 100: 40} {
		if got := percentile(samples, percentileValue); got != want {
			t.Fatalf("p%d = %v, want %v", percentileValue, got, want)
		}
	}
	if samples[0] != 20 || percentile(nil, 50) != 0 || percentile(samples, 0) != 0 {
		t.Fatal("percentile mutated its input or accepted invalid samples")
	}
	config := runConfig{pairs: 2, roundTripsPS: 4, payloadBytes: 128}
	summary := summarize("relay.example", config, []time.Duration{time.Millisecond, 2 * time.Millisecond}, time.Second)
	if summary.Connections != 4 || summary.Samples != 2 || summary.ObservedRoundTripsPerSecond != 2 || summary.P99Milliseconds != 2 {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestValidateAchievedRate(t *testing.T) {
	config := runConfig{roundTripsPS: 100, duration: time.Second}
	if err := validateAchievedRate(config, 95); err != nil {
		t.Fatalf("threshold sample failed: %v", err)
	}
	if err := validateAchievedRate(config, 94); err == nil || !strings.Contains(err.Error(), "95%") {
		t.Fatalf("below-threshold error = %v", err)
	}
	config.roundTripsPS = 0
	if err := validateAchievedRate(config, 0); err != nil {
		t.Fatalf("socket-hold validation = %v", err)
	}
}

func TestRandomUUIDIsCanonicalV4(t *testing.T) {
	value, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(value) {
		t.Fatalf("UUID = %q", value)
	}
}

func TestZeroRateStopsAtMeasurementBoundary(t *testing.T) {
	stop := make(chan struct{})
	close(stop)
	if err := measurePair(t.Context(), stop, nil, 0, "", &sampleCollector{}); err != nil {
		t.Fatal(err)
	}
}

func TestProvisionPairRetainsUncertainActivatedIdentityForCleanup(t *testing.T) {
	uncertain := errors.New("activation response lost")
	pair, err := provisionPairWith(t.Context(), "wss://disposable.example/v1", func(
		_ context.Context,
		_ string,
		request companion.EnrollmentRequest,
		_ ...func(companion.Config) error,
	) (companion.Config, companion.EnrollmentResponse, error) {
		return companion.Config{
			LinkID: "link-id", EndpointID: "companion-id", Secret: "companion-secret",
		}, companion.EnrollmentResponse{ControllerEndpointID: request.ControllerEndpointID}, uncertain
	})
	if !errors.Is(err, uncertain) || pair == nil || pair.linkID != "link-id" || pair.companionAuth == "" || pair.controllerAuth == "" {
		t.Fatalf("pair = %#v, error = %v", pair, err)
	}
}

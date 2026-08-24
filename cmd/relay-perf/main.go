// Command relay-perf measures the opaque relay hot path against a disposable stack.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anhydrous99/remote-davinci/internal/companion"
	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/flynn/noise"
)

const (
	disposableOptIn  = "REMOTE_DAVINCI_PERF_DISPOSABLE"
	maxPairs         = 60
	maxSetupWorkers  = 32
	maxRunDuration   = 24 * time.Hour
	maxFramesPerSec  = 60
	maxSamples       = 10_000_000
	roundTripTimeout = 15 * time.Second

	pairCreatesPerSourceMinute = 5
	pairCreateInterval         = time.Minute / pairCreatesPerSourceMinute
	minimumAchievedRateRatio   = 0.95
)

type runConfig struct {
	relayURL        string
	pairs           int
	roundTripsPS    int
	duration        time.Duration
	payloadBytes    int
	setupWorkers    int
	disposableOptIn string
}

type result struct {
	RelayHost                   string  `json:"relayHost"`
	Pairs                       int     `json:"pairs"`
	Connections                 int     `json:"connections"`
	TargetRoundTripsPerSecond   int     `json:"targetRoundTripsPerSecond"`
	ObservedRoundTripsPerSecond float64 `json:"observedRoundTripsPerSecond"`
	DurationSeconds             float64 `json:"durationSeconds"`
	PayloadBytes                int     `json:"payloadBytes"`
	Samples                     int     `json:"samples"`
	P50Milliseconds             float64 `json:"p50Milliseconds,omitempty"`
	P95Milliseconds             float64 `json:"p95Milliseconds,omitempty"`
	P99Milliseconds             float64 `json:"p99Milliseconds,omitempty"`
	MaximumMilliseconds         float64 `json:"maximumMilliseconds,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "relay-perf:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	config, err := parseConfig(args, getenv)
	if err != nil {
		return err
	}
	relay, _ := url.Parse(config.relayURL)
	fmt.Fprintf(stderr, "preparing %d disposable pair(s) on %s\n", config.pairs, relay.Host)

	setupContext, cancelSetup := context.WithTimeout(ctx, 15*time.Minute)
	pairs, setupErr := preparePairs(setupContext, config)
	cancelSetup()
	if setupErr != nil {
		cleanupContext, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Minute)
		cleanupErr := cleanupPairs(cleanupContext, pairs, config.setupWorkers)
		cancelCleanup()
		return errors.Join(setupErr, cleanupErr)
	}

	samples, loadErr := measure(ctx, config, pairs)
	if loadErr == nil {
		loadErr = validateAchievedRate(config, len(samples))
	}
	cleanupContext, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Minute)
	cleanupErr := cleanupPairs(cleanupContext, pairs, config.setupWorkers)
	cancelCleanup()
	if loadErr != nil || cleanupErr != nil {
		return errors.Join(loadErr, cleanupErr)
	}

	summary := summarize(relay.Host, config, samples, config.duration)
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(summary)
}

func parseConfig(args []string, getenv func(string) string) (runConfig, error) {
	flags := flag.NewFlagSet("relay-perf", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := runConfig{}
	flags.StringVar(&config.relayURL, "relay", "", "disposable wss:// relay URL")
	flags.IntVar(&config.pairs, "pairs", 1, "active controller/companion pairs")
	flags.IntVar(&config.roundTripsPS, "rps", 10, "aggregate relay round trips per second; zero holds sockets only")
	flags.DurationVar(&config.duration, "duration", 30*time.Second, "measurement duration")
	flags.IntVar(&config.payloadBytes, "payload-bytes", 256, "opaque decoded payload size")
	flags.IntVar(&config.setupWorkers, "setup-workers", 4, "concurrent provisioning and cleanup workers")
	if err := flags.Parse(args); err != nil {
		return runConfig{}, err
	}
	if flags.NArg() != 0 {
		return runConfig{}, errors.New("unexpected positional arguments")
	}
	config.disposableOptIn = getenv(disposableOptIn)
	if err := config.validate(); err != nil {
		return runConfig{}, err
	}
	return config, nil
}

func (config runConfig) validate() error {
	if config.disposableOptIn != "1" {
		return fmt.Errorf("set %s=1 only after confirming an isolated disposable stack", disposableOptIn)
	}
	parsed, err := url.ParseRequestURI(config.relayURL)
	if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.User != nil || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.String() != config.relayURL {
		return errors.New("relay must be a credential-free wss:// URL without query or fragment")
	}
	production, _ := url.Parse(companion.DefaultRelayURL)
	if sameRelayAuthority(parsed, production) {
		return errors.New("relay-perf refuses the configured production relay; deploy an isolated stack")
	}
	if config.pairs < 1 || config.pairs > maxPairs {
		return fmt.Errorf("pairs must be from 1 through %d", maxPairs)
	}
	if config.roundTripsPS < 0 || config.roundTripsPS > config.pairs*maxFramesPerSec {
		return fmt.Errorf("rps must be from 0 through %d for %d pair(s)", config.pairs*maxFramesPerSec, config.pairs)
	}
	if config.duration < time.Second || config.duration > maxRunDuration {
		return fmt.Errorf("duration must be from 1s through %s", maxRunDuration)
	}
	roundedSeconds := int64((config.duration + time.Second - 1) / time.Second)
	if config.roundTripsPS > 0 && int64(config.roundTripsPS) > int64(maxSamples)/roundedSeconds {
		return fmt.Errorf("rps and duration may produce at most %d samples; shorten or shard the run", maxSamples)
	}
	if config.payloadBytes < 1 || config.payloadBytes > protocol.MaxRelayPayloadBytes {
		return fmt.Errorf("payload-bytes must be from 1 through %d", protocol.MaxRelayPayloadBytes)
	}
	if config.setupWorkers < 1 || config.setupWorkers > maxSetupWorkers {
		return fmt.Errorf("setup-workers must be from 1 through %d", maxSetupWorkers)
	}
	return nil
}

func sameRelayAuthority(left, right *url.URL) bool {
	leftHost := strings.TrimSuffix(strings.ToLower(left.Hostname()), ".")
	rightHost := strings.TrimSuffix(strings.ToLower(right.Hostname()), ".")
	return leftHost == rightHost && effectiveRelayPort(left) == effectiveRelayPort(right)
}

func effectiveRelayPort(relay *url.URL) string {
	port := relay.Port()
	if port == "" {
		return "443"
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return port
	}
	return strconv.FormatUint(value, 10)
}

type loadPair struct {
	relayURL       string
	linkID         string
	controllerID   string
	companionID    string
	controllerAuth string
	companionAuth  string
	sessionID      string
	controller     *relayPeer
	companion      *relayPeer
}

type loadPairProvisioner func(context.Context, string) (*loadPair, error)

type pairCreatePacer struct {
	interval time.Duration
	mu       sync.Mutex
	next     time.Time
}

func (pacer *pairCreatePacer) provision(ctx context.Context, relayURL string, provision loadPairProvisioner) (*loadPair, error) {
	pacer.mu.Lock()
	defer pacer.mu.Unlock()
	if delay := time.Until(pacer.next); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pair, err := provision(ctx, relayURL)
	pacer.next = time.Now().Add(pacer.interval)
	return pair, err
}

func preparePairs(ctx context.Context, config runConfig) ([]*loadPair, error) {
	pairs := make([]*loadPair, config.pairs)
	jobs := make(chan int)
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()
	var firstErr error
	var errOnce sync.Once
	var workers sync.WaitGroup
	pacer := pairCreatePacer{interval: pairCreateInterval}
	workerCount := min(config.setupWorkers, config.pairs)
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for index := range jobs {
				pair, err := pacer.provision(workerContext, config.relayURL, provisionPair)
				if pair != nil {
					pairs[index] = pair
				}
				if err == nil {
					err = pair.connect(workerContext, config.relayURL)
				}
				if err != nil {
					errOnce.Do(func() {
						firstErr = fmt.Errorf("prepare pair %d: %w", index+1, err)
						cancel()
					})
					return
				}
			}
		}()
	}
	for index := range config.pairs {
		select {
		case jobs <- index:
		case <-workerContext.Done():
			close(jobs)
			workers.Wait()
			return compactPairs(pairs), firstError(firstErr, workerContext.Err())
		}
	}
	close(jobs)
	workers.Wait()
	return compactPairs(pairs), firstErr
}

func compactPairs(pairs []*loadPair) []*loadPair {
	result := pairs[:0]
	for _, pair := range pairs {
		if pair != nil {
			result = append(result, pair)
		}
	}
	return result
}

func firstError(first, contextErr error) error {
	if first != nil {
		return first
	}
	return contextErr
}

func provisionPair(ctx context.Context, relayURL string) (*loadPair, error) {
	return provisionPairWith(ctx, relayURL, companion.Provision)
}

type provisioner func(context.Context, string, companion.EnrollmentRequest, ...func(companion.Config) error) (companion.Config, companion.EnrollmentResponse, error)

func provisionPairWith(ctx context.Context, relayURL string, provision provisioner) (*loadPair, error) {
	controllerID, err := randomUUID()
	if err != nil {
		return nil, err
	}
	controllerSecret := make([]byte, 32)
	if _, err := rand.Read(controllerSecret); err != nil {
		return nil, err
	}
	controllerKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	credentialHash := sha256.Sum256(controllerSecret)
	config, enrollment, err := provision(ctx, relayURL, companion.EnrollmentRequest{
		V:                        1,
		ControllerEndpointID:     controllerID,
		ControllerCredentialHash: base64.RawURLEncoding.EncodeToString(credentialHash[:]),
		ControllerNoiseKey:       base64.RawURLEncoding.EncodeToString(controllerKey.Public),
		DeviceLabel:              "Disposable relay performance probe",
	})
	pair := &loadPair{
		relayURL:       relayURL,
		linkID:         config.LinkID,
		controllerID:   controllerID,
		companionID:    config.EndpointID,
		controllerAuth: bearerAuthorization(controllerID, base64.RawURLEncoding.EncodeToString(controllerSecret)),
		companionAuth:  bearerAuthorization(config.EndpointID, config.Secret),
	}
	if err != nil {
		if config.LinkID != "" && config.EndpointID != "" && config.Secret != "" {
			return pair, err
		}
		return nil, err
	}
	return pair, validateProvisionedPair(config, enrollment, controllerID)
}

func validateProvisionedPair(config companion.Config, enrollment companion.EnrollmentResponse, controllerID string) error {
	if config.LinkID == "" || config.EndpointID == "" || config.Secret == "" ||
		enrollment.LinkID != config.LinkID || enrollment.ControllerEndpointID != controllerID ||
		enrollment.CompanionEndpointID != config.EndpointID {
		return errors.New("relay provisioned inconsistent performance identities")
	}
	return nil
}

func (pair *loadPair) connect(ctx context.Context, relayURL string) error {
	controller, err := dialRelay(ctx, relayURL, pair.controllerAuth)
	if err != nil {
		return err
	}
	pair.controller = controller
	companionPeer, err := dialRelay(ctx, relayURL, pair.companionAuth)
	if err != nil {
		return err
	}
	pair.companion = companionPeer
	var opened struct {
		SessionID string `json:"sessionId"`
	}
	if err := controller.request(ctx, "session.open", protocol.LinkBody{LinkID: pair.linkID}, &opened); err != nil {
		return err
	}
	if opened.SessionID == "" {
		return errors.New("relay returned an empty session ID")
	}
	for _, expected := range []struct {
		peer   *relayPeer
		peerID string
	}{{controller, pair.companionID}, {companionPeer, pair.controllerID}} {
		envelope, err := expected.peer.event(ctx, "session.opened")
		if err != nil {
			return err
		}
		var event struct {
			SessionID      string `json:"sessionId"`
			LinkID         string `json:"linkId"`
			PeerEndpointID string `json:"peerEndpointId"`
		}
		if envelope.DecodeBody(&event) != nil || event.SessionID != opened.SessionID || event.LinkID != pair.linkID || event.PeerEndpointID != expected.peerID {
			return errors.New("relay opened an inconsistent performance session")
		}
	}
	pair.sessionID = opened.SessionID
	return nil
}

func measure(ctx context.Context, config runConfig, pairs []*loadPair) ([]time.Duration, error) {
	if len(pairs) != config.pairs {
		return nil, errors.New("not all requested pairs are connected")
	}
	payload := make([]byte, config.payloadBytes)
	for index := range payload {
		payload[index] = byte(index)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	workContext, cancel := context.WithCancel(ctx)
	defer cancel()
	stopScheduling := make(chan struct{})
	stopTimer := time.AfterFunc(config.duration, func() { close(stopScheduling) })
	defer stopTimer.Stop()
	collector := &sampleCollector{}
	var firstErr error
	var errOnce sync.Once
	var workers sync.WaitGroup
	workers.Add(len(pairs))
	for index, pair := range pairs {
		pairRate := config.roundTripsPS / len(pairs)
		if index < config.roundTripsPS%len(pairs) {
			pairRate++
		}
		go func(pair *loadPair, rate int) {
			defer workers.Done()
			if err := measurePair(workContext, stopScheduling, pair, rate, encodedPayload, collector); err != nil {
				errOnce.Do(func() {
					firstErr = err
					cancel()
				})
			}
		}(pair, pairRate)
	}
	workers.Wait()
	if ctx.Err() != nil {
		return collector.snapshot(), ctx.Err()
	}
	return collector.snapshot(), firstErr
}

func measurePair(ctx context.Context, stopScheduling <-chan struct{}, pair *loadPair, rate int, payload string, collector *sampleCollector) error {
	if rate == 0 {
		select {
		case <-stopScheduling:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ticker := time.NewTicker(time.Second / time.Duration(rate))
	defer ticker.Stop()
	var sequence int64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stopScheduling:
			return nil
		case <-ticker.C:
			select {
			case <-stopScheduling:
				return nil
			default:
			}
			sequence++
			started := time.Now()
			operationContext, cancel := context.WithTimeout(ctx, roundTripTimeout)
			err := pair.roundTrip(operationContext, sequence, payload)
			cancel()
			if err != nil {
				return fmt.Errorf("relay round trip failed: %w", err)
			}
			collector.add(time.Since(started))
		}
	}
}

func (pair *loadPair) roundTrip(ctx context.Context, sequence int64, payload string) error {
	body := protocol.SessionFrameBody{SessionID: pair.sessionID, Seq: sequence, Payload: payload}
	if err := pair.controller.send(ctx, "session.frame", body); err != nil {
		return err
	}
	if err := requireFrame(ctx, pair.companion, body); err != nil {
		return err
	}
	if err := pair.companion.send(ctx, "session.frame", body); err != nil {
		return err
	}
	return requireFrame(ctx, pair.controller, body)
}

func requireFrame(ctx context.Context, peer *relayPeer, want protocol.SessionFrameBody) error {
	envelope, err := peer.event(ctx, "session.frame")
	if err != nil {
		return err
	}
	var got protocol.SessionFrameBody
	if envelope.DecodeBody(&got) != nil || got != want {
		return errors.New("relay forwarded an inconsistent performance frame")
	}
	return nil
}

type sampleCollector struct {
	mu      sync.Mutex
	samples []time.Duration
}

func (collector *sampleCollector) add(sample time.Duration) {
	collector.mu.Lock()
	collector.samples = append(collector.samples, sample)
	collector.mu.Unlock()
}

func (collector *sampleCollector) snapshot() []time.Duration {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	return slices.Clone(collector.samples)
}

func summarize(host string, config runConfig, samples []time.Duration, elapsed time.Duration) result {
	summary := result{
		RelayHost: host, Pairs: config.pairs, Connections: config.pairs * 2,
		TargetRoundTripsPerSecond: config.roundTripsPS,
		DurationSeconds:           elapsed.Seconds(),
		PayloadBytes:              config.payloadBytes,
		Samples:                   len(samples),
	}
	if elapsed > 0 {
		summary.ObservedRoundTripsPerSecond = float64(len(samples)) / elapsed.Seconds()
	}
	if len(samples) > 0 {
		summary.P50Milliseconds = milliseconds(percentile(samples, 50))
		summary.P95Milliseconds = milliseconds(percentile(samples, 95))
		summary.P99Milliseconds = milliseconds(percentile(samples, 99))
		summary.MaximumMilliseconds = milliseconds(percentile(samples, 100))
	}
	return summary
}

func validateAchievedRate(config runConfig, samples int) error {
	if config.roundTripsPS == 0 {
		return nil
	}
	observed := float64(samples) / config.duration.Seconds()
	minimum := float64(config.roundTripsPS) * minimumAchievedRateRatio
	if observed < minimum {
		return fmt.Errorf(
			"observed %.2f round trips/s is below %.0f%% of the %d round trips/s target; closed-loop latency samples are not valid at this load",
			observed, minimumAchievedRateRatio*100, config.roundTripsPS,
		)
	}
	return nil
}

func percentile(samples []time.Duration, value int) time.Duration {
	if len(samples) == 0 || value < 1 || value > 100 {
		return 0
	}
	ordered := slices.Clone(samples)
	slices.Sort(ordered)
	rank := (value*len(ordered) + 99) / 100
	return ordered[rank-1]
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}

func cleanupPairs(ctx context.Context, pairs []*loadPair, concurrency int) error {
	for _, pair := range pairs {
		pair.closeNow()
	}
	jobs := make(chan *loadPair)
	var workers sync.WaitGroup
	var failuresMu sync.Mutex
	var failures []error
	workerCount := min(concurrency, len(pairs))
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for pair := range jobs {
				if err := cleanupPair(ctx, pair); err != nil {
					failuresMu.Lock()
					failures = append(failures, err)
					failuresMu.Unlock()
				}
			}
		}()
	}
	for _, pair := range pairs {
		select {
		case jobs <- pair:
		case <-ctx.Done():
			close(jobs)
			workers.Wait()
			return errors.Join(append(failures, ctx.Err())...)
		}
	}
	close(jobs)
	workers.Wait()
	return errors.Join(failures...)
}

func cleanupPair(ctx context.Context, pair *loadPair) error {
	var failures []error
	linkRevoked := false
	for _, authorization := range []string{pair.controllerAuth, pair.companionAuth} {
		peer, err := dialRelay(ctx, pair.relayURL, authorization)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !linkRevoked {
			var result struct {
				Revoked bool `json:"revoked"`
			}
			if err := peer.request(ctx, "link.revoke", protocol.LinkBody{LinkID: pair.linkID}, &result); err == nil && result.Revoked {
				linkRevoked = true
			} else if err != nil {
				failures = append(failures, err)
			}
		}
		var endpoint struct {
			Revoked bool `json:"revoked"`
		}
		if err := peer.request(ctx, "endpoint.revoke", map[string]any{}, &endpoint); err != nil || !endpoint.Revoked {
			failures = append(failures, firstError(err, errors.New("relay did not acknowledge endpoint revocation")))
		}
		peer.closeNow()
	}
	if !linkRevoked {
		failures = append(failures, errors.New("relay did not acknowledge link revocation"))
	}
	return errors.Join(failures...)
}

func (pair *loadPair) closeNow() {
	if pair.controller != nil {
		pair.controller.closeNow()
		pair.controller = nil
	}
	if pair.companion != nil {
		pair.companion.closeNow()
		pair.companion = nil
	}
}

type wireEnvelope struct {
	Protocol string `json:"protocol"`
	V        int64  `json:"v"`
	Type     string `json:"type"`
	ID       string `json:"id"`
	Body     any    `json:"body"`
}

type relayPeer struct {
	connection *websocket.Conn
	events     []protocol.ServerEnvelope
}

func dialRelay(ctx context.Context, relayURL, authorization string) (*relayPeer, error) {
	header := http.Header{}
	header.Set("Authorization", authorization)
	connection, response, err := websocket.Dial(ctx, relayURL, &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		if response != nil {
			return nil, fmt.Errorf("relay WebSocket upgrade failed with status %d", response.StatusCode)
		}
		return nil, errors.New("relay WebSocket upgrade failed")
	}
	connection.SetReadLimit(protocol.MaxWebSocketFrameBytes)
	return &relayPeer{connection: connection}, nil
}

func (peer *relayPeer) closeNow() {
	_ = peer.connection.CloseNow()
}

func (peer *relayPeer) send(ctx context.Context, messageType string, body any) error {
	id, err := randomUUID()
	if err != nil {
		return err
	}
	return wsjson.Write(ctx, peer.connection, wireEnvelope{
		Protocol: protocol.ProtocolName, V: protocol.ProtocolVersion, Type: messageType, ID: id, Body: body,
	})
}

func (peer *relayPeer) request(ctx context.Context, messageType string, body, result any) error {
	id, err := randomUUID()
	if err != nil {
		return err
	}
	if err := wsjson.Write(ctx, peer.connection, wireEnvelope{
		Protocol: protocol.ProtocolName, V: protocol.ProtocolVersion, Type: messageType, ID: id, Body: body,
	}); err != nil {
		return err
	}
	for {
		envelope, err := peer.read(ctx)
		if err != nil {
			return err
		}
		if envelope.ReplyTo != id {
			peer.events = append(peer.events, envelope)
			continue
		}
		if envelope.Type == "error" {
			var failure struct {
				Code protocol.ErrorCode `json:"code"`
			}
			_ = envelope.DecodeBody(&failure)
			return fmt.Errorf("relay rejected %s: %s", messageType, failure.Code)
		}
		var success struct {
			RequestType string          `json:"requestType"`
			Result      json.RawMessage `json:"result"`
		}
		if envelope.Type != "ok" || envelope.DecodeBody(&success) != nil || success.RequestType != messageType {
			return errors.New("relay returned an invalid correlated response")
		}
		if result == nil {
			return nil
		}
		return json.Unmarshal(success.Result, result)
	}
}

func (peer *relayPeer) event(ctx context.Context, messageType string) (protocol.ServerEnvelope, error) {
	for {
		for index, envelope := range peer.events {
			if envelope.Type == messageType {
				peer.events = append(peer.events[:index], peer.events[index+1:]...)
				return envelope, nil
			}
		}
		envelope, err := peer.read(ctx)
		if err != nil {
			return protocol.ServerEnvelope{}, err
		}
		if envelope.Type == "error" {
			return protocol.ServerEnvelope{}, errors.New("relay returned an asynchronous error")
		}
		if envelope.Type == messageType {
			return envelope, nil
		}
		peer.events = append(peer.events, envelope)
	}
}

func (peer *relayPeer) read(ctx context.Context) (protocol.ServerEnvelope, error) {
	var raw json.RawMessage
	if err := wsjson.Read(ctx, peer.connection, &raw); err != nil {
		return protocol.ServerEnvelope{}, err
	}
	envelope, err := protocol.ParseServer(raw)
	if err != nil {
		return protocol.ServerEnvelope{}, errors.New("relay returned an invalid frame")
	}
	return envelope, nil
}

func randomUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func bearerAuthorization(endpointID, secret string) string {
	return "Bearer rd1." + endpointID + "." + secret
}

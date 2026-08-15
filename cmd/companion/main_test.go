package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/anhydrous99/remote-davinci/internal/companion"
)

func TestNativeStartupFailureIsSanitized(t *testing.T) {
	parent, keepalive := io.Pipe()
	readiness, output := io.Pipe()
	defer parent.Close()
	defer keepalive.Close()
	defer readiness.Close()
	want := companion.ErrConfigStoreMismatch
	done := make(chan error, 1)
	go func() {
		done <- runServer(
			"127.0.0.1:0",
			filepath.Join(t.TempDir(), "companion.json"),
			companion.DefaultRelayURL,
			false,
			parent,
			output,
			func(context.Context, string, string) (*companion.App, error) { return nil, want },
		)
		_ = output.Close()
	}()
	line, err := bufio.NewReader(readiness).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("helper exited before startup record acknowledgment: %v", err)
	default:
	}
	if err := keepalive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, want) {
		t.Fatalf("startup error = %v", err)
	}
	var record struct {
		V     int `json:"v"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &record); err != nil {
		t.Fatal(err)
	}
	if record.V != 1 || record.Error.Code != "CONFIG_MISMATCH" || bytes.Contains(line, []byte(want.Error())) {
		t.Fatalf("unsafe startup record: %s", line)
	}
}

func TestServerParentContextCancelsActiveRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	started := make(chan struct{})
	cancelled := make(chan struct{})
	server := newHTTPServer(ctx, "127.0.0.1:0", http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(started)
		<-request.Context().Done()
		close(cancelled)
	}))
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})

	requestDone := make(chan error, 1)
	go func() {
		response, err := http.Get("http://" + listener.Addr().String())
		if response != nil {
			_ = response.Body.Close()
		}
		requestDone <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("parent cancellation did not reach the request")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveDone; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("server stopped with %v", err)
	}
	<-requestDone
}

func TestNativeReadinessAndParentEOF(t *testing.T) {
	parent, keepalive := io.Pipe()
	readiness, output := io.Pipe()
	configPath := filepath.Join(t.TempDir(), "companion.json")
	done := make(chan error, 1)
	go func() {
		done <- runServer(
			"127.0.0.1:0",
			configPath,
			"wss://example.com/v1",
			false,
			parent,
			output,
			companion.NewApp,
		)
		_ = output.Close()
	}()
	t.Cleanup(func() {
		_ = keepalive.Close()
		_ = parent.Close()
		_ = readiness.Close()
	})

	line, err := bufio.NewReader(readiness).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var ready struct {
		V       int    `json:"v"`
		Version string `json:"version"`
		URL     string `json:"url"`
	}
	if err := json.Unmarshal(line, &ready); err != nil {
		t.Fatal(err)
	}
	launchURL, err := url.Parse(ready.URL)
	if err != nil {
		t.Fatal(err)
	}
	if ready.V != 1 || ready.Version != companion.Version || launchURL.Scheme != "http" ||
		launchURL.Hostname() != "127.0.0.1" || launchURL.Port() == "" || launchURL.Query().Get("token") == "" {
		t.Fatalf("invalid readiness: %s", line)
	}

	if err := keepalive.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("companion did not stop after parent EOF")
	}
}

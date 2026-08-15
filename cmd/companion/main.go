package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/anhydrous99/remote-davinci/internal/companion"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:7314", "loopback GUI address")
	configPath := flag.String("config", companion.DefaultConfigPath(), "credential file")
	relay := flag.String("relay", companion.DefaultRelayURL, "deployed WSS relay URL")
	openBrowser := flag.Bool("open", true, "open the GUI in the default browser")
	native := flag.Bool("native", false, "run as the native app helper")
	flag.Parse()
	var err error
	if *native {
		err = runNative(*configPath, *relay)
	} else {
		err = run(*listen, *configPath, *relay, *openBrowser)
	}
	if err != nil {
		slog.Error("companion stopped", "error", err)
		os.Exit(1)
	}
}

func run(address, configPath, relay string, openBrowser bool) error {
	return runServer(address, configPath, relay, openBrowser, nil, os.Stdout, companion.NewApp)
}

func runNative(configPath, relay string) error {
	return runServer("127.0.0.1:0", configPath, relay, false, os.Stdin, os.Stdout, companion.NewNativeApp)
}

type appFactory func(context.Context, string, string) (*companion.App, error)

func runServer(
	address, configPath, relay string,
	openBrowser bool,
	parent io.Reader,
	output io.Writer,
	newApp appFactory,
) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("listen address must be a loopback IP and port")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if parent != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		go func() {
			_, _ = io.Copy(io.Discard, parent)
			cancel()
		}()
	}
	app, err := newApp(ctx, configPath, relay)
	if err != nil {
		return nativeStartupError(ctx, parent, output, err)
	}
	defer app.Close()
	server := newHTTPServer(ctx, address, app.Handler())
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nativeStartupError(ctx, parent, output, err)
	}
	defer listener.Close()
	url := app.LaunchURL("http://" + listener.Addr().String())
	if parent != nil {
		if err := json.NewEncoder(output).Encode(struct {
			V       int    `json:"v"`
			Version string `json:"version"`
			URL     string `json:"url"`
		}{1, companion.Version, url}); err != nil {
			return err
		}
	} else {
		_, _ = fmt.Fprintln(output, "Remote DaVinci companion:", url)
	}
	if openBrowser && parent == nil {
		_ = exec.Command("/usr/bin/open", url).Start()
	}
	failure := make(chan error, 1)
	go func() { failure <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	case err := <-failure:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func nativeStartupError(ctx context.Context, parent io.Reader, output io.Writer, err error) error {
	if parent == nil {
		return err
	}
	code := "STARTUP_FAILED"
	if errors.Is(err, companion.ErrConfigStoreMismatch) {
		code = "CONFIG_MISMATCH"
	} else if errors.Is(err, companion.ErrKeychainUnavailable) {
		code = "KEYCHAIN_UNAVAILABLE"
	}
	_ = json.NewEncoder(output).Encode(map[string]any{
		"v": 1, "error": map[string]string{"code": code},
	})
	// The parent's stdin close acknowledges the terminal record. This keeps
	// process exit from racing the app's stdout parser.
	<-ctx.Done()
	return err
}

func newHTTPServer(ctx context.Context, address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: address, Handler: handler, BaseContext: func(net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second,
	}
}

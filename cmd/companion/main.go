package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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
	flag.Parse()
	if err := run(*listen, *configPath, *relay, *openBrowser); err != nil {
		slog.Error("companion stopped", "error", err)
		os.Exit(1)
	}
}

func run(address, configPath, relay string, openBrowser bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("listen address must be a loopback IP and port")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app, err := companion.NewApp(ctx, configPath, relay)
	if err != nil {
		return err
	}
	defer app.Close()
	server := &http.Server{
		Addr: address, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second,
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	url := app.LaunchURL("http://" + listener.Addr().String())
	fmt.Println("Remote DaVinci companion:", url)
	if openBrowser {
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

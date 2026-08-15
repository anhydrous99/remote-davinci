package companion

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

//go:embed ui.html
var uiHTML []byte

const uiTokenHeader = "X-Remote-Davinci-Token"

type App struct {
	ctx        context.Context
	configPath string
	relayURL   string
	enrollMu   sync.Mutex
	mu         sync.RWMutex
	config     *Config
	status     RelayStatus
	cancel     context.CancelFunc
	uiToken    string
	revoke     func(context.Context, Config, func(Config) error) error
}

type State struct {
	Configured      bool   `json:"configured"`
	RelayURL        string `json:"relayUrl"`
	EndpointID      string `json:"endpointId,omitempty"`
	LinkID          string `json:"linkId,omitempty"`
	ControllerLabel string `json:"controllerLabel,omitempty"`
	Connected       bool   `json:"connected"`
	Secure          bool   `json:"secure"`
	Status          string `json:"status"`
}

func NewApp(ctx context.Context, configPath, relay string) (*App, error) {
	if _, err := relayURL(relay); err != nil {
		return nil, err
	}
	token, err := random32()
	if err != nil {
		return nil, err
	}
	app := &App{
		ctx: ctx, configPath: configPath, relayURL: relay,
		status:  RelayStatus{Message: "Not enrolled"},
		uiToken: base64.RawURLEncoding.EncodeToString(token), revoke: RevokeEnrollment,
	}
	config, err := LoadConfig(configPath)
	if err == nil {
		app.config = &config
		app.relayURL = config.RelayURL
		if config.LinkRevoked {
			app.status = RelayStatus{Message: "Link revoked; reset to remove local credentials"}
		} else {
			app.startRelay(config)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return app, nil
}

func (app *App) LaunchURL(base string) string { return base + "?token=" + app.uiToken }

func (app *App) Close() {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.cancel != nil {
		app.cancel()
	}
}

func (app *App) startRelay(config Config) {
	app.mu.Lock()
	if app.cancel != nil {
		app.cancel()
	}
	ctx, cancel := context.WithCancel(app.ctx)
	app.cancel = cancel
	app.status = RelayStatus{Message: "Connecting to relay…"}
	app.mu.Unlock()
	go func() {
		_ = RunRelay(ctx, config, func(status RelayStatus) {
			if ctx.Err() != nil {
				return
			}
			app.mu.Lock()
			if app.config != nil && app.config.EndpointID == config.EndpointID {
				if status.Connected && app.config.ActivationPending {
					activated := *app.config
					activated.ActivationPending = false
					if SaveConfig(app.configPath, activated) == nil {
						app.config = &activated
					}
				}
				app.status = status
			}
			app.mu.Unlock()
		})
	}()
}

func (app *App) state() State {
	app.mu.RLock()
	defer app.mu.RUnlock()
	state := State{
		Configured: app.config != nil, RelayURL: app.relayURL,
		Connected: app.status.Connected, Secure: app.status.Secure, Status: app.status.Message,
	}
	if app.config != nil {
		state.EndpointID = app.config.EndpointID
		state.LinkID = app.config.LinkID
		state.ControllerLabel = app.config.ControllerLabel
	}
	return state
}

func (app *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", app.handleIndex)
	mux.HandleFunc("GET /api/state", app.handleState)
	mux.HandleFunc("POST /api/enroll", app.handleEnroll)
	mux.HandleFunc("POST /api/reset", app.handleReset)
	mux.HandleFunc("POST /api/forget", app.handleForget)
	mux.HandleFunc("POST /api/action", app.handleAction)
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		host, _, err := net.SplitHostPort(request.Host)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() {
			http.Error(response, "forbidden", http.StatusForbidden)
			return
		}
		if len(request.URL.Path) >= 5 && request.URL.Path[:5] == "/api/" {
			expected := sha256.Sum256([]byte(app.uiToken))
			provided := sha256.Sum256([]byte(request.Header.Get(uiTokenHeader)))
			if app.uiToken == "" || subtle.ConstantTimeCompare(expected[:], provided[:]) != 1 {
				http.Error(response, "forbidden", http.StatusForbidden)
				return
			}
		}
		if request.Method == http.MethodPost {
			origin := request.Header.Get("Origin")
			if origin != "" && origin != "http://"+request.Host {
				http.Error(response, "forbidden", http.StatusForbidden)
				return
			}
			mediaType, _, mediaErr := mime.ParseMediaType(request.Header.Get("Content-Type"))
			if mediaErr != nil || mediaType != "application/json" {
				http.Error(response, "application/json required", http.StatusUnsupportedMediaType)
				return
			}
		}
		mux.ServeHTTP(response, request)
	})
}

func (app *App) handleIndex(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = response.Write(uiHTML)
}

func (app *App) handleState(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, app.state())
}

func (app *App) handleEnroll(response http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(response, request.Body, 16*1024))
	if err != nil {
		writeError(response, http.StatusBadRequest, "enrollment request is too large")
		return
	}
	enrollment, err := ParseEnrollmentRequest(body)
	if err != nil {
		writeError(response, http.StatusBadRequest, err.Error())
		return
	}
	app.enrollMu.Lock()
	defer app.enrollMu.Unlock()
	app.mu.RLock()
	configured := app.config != nil
	app.mu.RUnlock()
	if configured {
		writeError(response, http.StatusConflict, "reset the current enrollment first")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 45*time.Second)
	defer cancel()
	config, enrollmentResponse, err := Provision(ctx, app.relayURL, enrollment, func(config Config) error {
		return SaveConfig(app.configPath, config)
	})
	if err != nil {
		if config.V == 1 {
			enrollmentResponse.Warning = "Relay activation could not be confirmed; the saved enrollment is being reconciled."
			app.mu.Lock()
			app.config = &config
			app.mu.Unlock()
			app.startRelay(config)
			writeJSON(response, http.StatusAccepted, enrollmentResponse)
			return
		}
		if errors.Is(err, errConfigPersistence) {
			writeError(response, http.StatusInternalServerError, "could not save companion credentials")
			return
		}
		writeError(response, http.StatusBadGateway, err.Error())
		return
	}
	app.mu.Lock()
	app.config = &config
	app.mu.Unlock()
	app.startRelay(config)
	writeJSON(response, http.StatusOK, enrollmentResponse)
}

func (app *App) handleReset(response http.ResponseWriter, request *http.Request) {
	var body struct {
		Confirmation string `json:"confirmation"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil {
		writeError(response, http.StatusBadRequest, "invalid reset confirmation")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(response, http.StatusBadRequest, "invalid reset confirmation")
		return
	}

	app.enrollMu.Lock()
	defer app.enrollMu.Unlock()
	app.mu.RLock()
	if app.config == nil {
		app.mu.RUnlock()
		writeError(response, http.StatusConflict, "no controller is enrolled")
		return
	}
	config := *app.config
	app.mu.RUnlock()
	if body.Confirmation != config.LinkID {
		writeError(response, http.StatusBadRequest, "reset confirmation did not match the active link")
		return
	}

	app.mu.Lock()
	if app.cancel != nil {
		app.cancel()
		app.cancel = nil
	}
	app.status = RelayStatus{Message: "Revoking controller link…"}
	app.mu.Unlock()
	ctx, cancel := context.WithTimeout(request.Context(), 30*time.Second)
	defer cancel()
	if err := app.revoke(ctx, config, func(checkpoint Config) error {
		if err := SaveConfig(app.configPath, checkpoint); err != nil {
			return err
		}
		config = checkpoint
		app.mu.Lock()
		app.config = &checkpoint
		app.mu.Unlock()
		return nil
	}); err != nil {
		app.mu.Lock()
		app.status = RelayStatus{Message: "Reset failed; enrollment retained"}
		app.mu.Unlock()
		if !config.LinkRevoked {
			app.startRelay(config)
		}
		writeError(response, http.StatusBadGateway, "could not revoke enrollment")
		return
	}

	removeErr := os.Remove(app.configPath)
	app.mu.Lock()
	if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		app.status = RelayStatus{Message: "Enrollment revoked; could not remove local credentials"}
		app.mu.Unlock()
		writeError(response, http.StatusInternalServerError, "enrollment revoked but local credentials could not be removed")
		return
	}
	app.config = nil
	app.status = RelayStatus{Message: "Not enrolled"}
	app.mu.Unlock()
	writeJSON(response, http.StatusOK, map[string]bool{"reset": true})
}

func (app *App) handleForget(response http.ResponseWriter, request *http.Request) {
	var body struct {
		Confirmation string `json:"confirmation"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil {
		writeError(response, http.StatusBadRequest, "invalid local-forget confirmation")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(response, http.StatusBadRequest, "invalid local-forget confirmation")
		return
	}

	app.enrollMu.Lock()
	defer app.enrollMu.Unlock()
	app.mu.Lock()
	if app.config == nil {
		app.mu.Unlock()
		writeError(response, http.StatusConflict, "no controller is enrolled")
		return
	}
	if body.Confirmation != app.config.LinkID {
		app.mu.Unlock()
		writeError(response, http.StatusBadRequest, "local-forget confirmation did not match the active link")
		return
	}
	if app.cancel != nil {
		app.cancel()
		app.cancel = nil
	}
	app.status = RelayStatus{Message: "Removing local enrollment…"}
	app.mu.Unlock()

	if err := os.Remove(app.configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		app.mu.Lock()
		app.status = RelayStatus{Message: "Could not remove local credentials; enrollment retained"}
		app.mu.Unlock()
		writeError(response, http.StatusInternalServerError, "local credentials could not be removed")
		return
	}
	app.mu.Lock()
	app.config = nil
	app.status = RelayStatus{Message: "Not enrolled"}
	app.mu.Unlock()
	writeJSON(response, http.StatusOK, map[string]any{
		"forgotten": true, "warning": "Remote relay identity may remain and must be revoked separately.",
	})
}

func (app *App) handleAction(response http.ResponseWriter, request *http.Request) {
	var body struct {
		Operation string `json:"operation"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&body) != nil {
		writeError(response, http.StatusBadRequest, "invalid action")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(response, http.StatusBadRequest, "invalid action")
		return
	}
	result, err := ExecuteOperation(request.Context(), body.Operation)
	if err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, message string) {
	writeJSON(response, status, map[string]string{"error": message})
}

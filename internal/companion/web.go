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

	"github.com/anhydrous99/remote-davinci/protocol"
)

//go:embed ui.html
var uiHTML []byte

const uiTokenHeader = "X-Remote-Davinci-Token"

type App struct {
	ctx            context.Context
	store          ConfigStore
	relayURL       string
	enrollMu       sync.Mutex
	bootstrapMu    sync.Mutex
	mu             sync.RWMutex
	config         *Config
	pairing        *pairingAttempt
	status         RelayStatus
	cancel         context.CancelFunc
	uiToken        string
	bootstrapToken string
	revoke         func(context.Context, Config, func(Config) error) error
}

type State struct {
	Configured         bool                `json:"configured"`
	RelayURL           string              `json:"relayUrl"`
	EndpointID         string              `json:"endpointId,omitempty"`
	LinkID             string              `json:"linkId,omitempty"`
	ControllerLabel    string              `json:"controllerLabel,omitempty"`
	Connected          bool                `json:"connected"`
	Secure             bool                `json:"secure"`
	Status             string              `json:"status"`
	Pairing            *PairingState       `json:"pairing,omitempty"`
	EnrollmentResponse *EnrollmentResponse `json:"enrollmentResponse,omitempty"`
}

func NewApp(ctx context.Context, configPath, relay string) (*App, error) {
	return NewAppWithStore(ctx, FileConfigStore{Path: configPath}, relay)
}

func NewNativeApp(ctx context.Context, legacyPath, relay string) (*App, error) {
	if _, err := relayURL(relay); err != nil {
		return nil, err
	}
	keychain := NewKeychainConfigStore()
	if err := MigrateConfigStore(FileConfigStore{Path: legacyPath}, keychain); err != nil {
		return nil, err
	}
	return NewAppWithStore(ctx, keychain, relay)
}

func NewAppWithStore(ctx context.Context, store ConfigStore, relay string) (*App, error) {
	if store == nil {
		return nil, errors.New("configuration store is required")
	}
	if _, err := relayURL(relay); err != nil {
		return nil, err
	}
	token, err := random32()
	if err != nil {
		return nil, err
	}
	bootstrap, err := random32()
	if err != nil {
		return nil, err
	}
	app := &App{
		ctx: ctx, store: store, relayURL: relay,
		status:         RelayStatus{Message: "Not enrolled"},
		uiToken:        base64.RawURLEncoding.EncodeToString(token),
		bootstrapToken: base64.RawURLEncoding.EncodeToString(bootstrap),
		revoke:         RevokeEnrollment,
	}
	config, err := store.Load()
	if err == nil {
		if err := config.validate(); err != nil {
			return nil, err
		}
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

func (app *App) NativeLaunchURL(base string) string { return base + "?token=" + app.uiToken }

func (app *App) BrowserLaunchURL(base string) string {
	return base + "/?bootstrap=" + app.bootstrapToken
}

func (app *App) Close() {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.cancel != nil {
		app.cancel()
	}
	if app.pairing != nil {
		app.pairing.cancel()
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
			app.applyRelayStatus(ctx, config, status)
		})
	}()
}

func (app *App) applyRelayStatus(ctx context.Context, config Config, status RelayStatus) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	if app.config != nil && app.config.EndpointID == config.EndpointID {
		if status.Connected && app.config.ActivationPending {
			activated := *app.config
			activated.ActivationPending = false
			if app.store.Save(activated) == nil {
				app.config = &activated
			}
		}
		app.status = status
	}
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
		state.ControllerLabel = displayDeviceLabel(app.config.ControllerLabel)
		if app.config.ControllerFingerprint == "" && !state.Secure {
			response, err := manualEnrollmentResponse(*app.config)
			if err == nil {
				state.EnrollmentResponse = &response
			}
		}
	}
	if app.pairing != nil {
		pairing := app.pairing.snapshot()
		state.Pairing = &pairing
	}
	return state
}

func (app *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", app.handleIndex)
	mux.HandleFunc("GET /api/state", app.handleState)
	mux.HandleFunc("POST /api/enroll", app.handleEnroll)
	mux.HandleFunc("POST /api/pairing/start", app.handlePairingStart)
	mux.HandleFunc("POST /api/pairing/approve", app.handlePairingApprove)
	mux.HandleFunc("POST /api/pairing/reject", app.handlePairingReject)
	mux.HandleFunc("POST /api/pairing/cancel", app.handlePairingCancel)
	mux.HandleFunc("POST /api/relay/wake", app.handleRelayWake)
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
			if !app.validUIToken(request.Header.Get(uiTokenHeader)) {
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

func (app *App) validUIToken(token string) bool {
	expected := sha256.Sum256([]byte(app.uiToken))
	provided := sha256.Sum256([]byte(token))
	return app.uiToken != "" && subtle.ConstantTimeCompare(expected[:], provided[:]) == 1
}

func (app *App) consumeBootstrap(token string) bool {
	app.bootstrapMu.Lock()
	defer app.bootstrapMu.Unlock()
	if app.bootstrapToken == "" {
		return false
	}
	expected := sha256.Sum256([]byte(app.bootstrapToken))
	provided := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(expected[:], provided[:]) != 1 {
		return false
	}
	app.bootstrapToken = ""
	return true
}

func (app *App) handleIndex(response http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		query := request.URL.Query()
		bootstrap := query["bootstrap"]
		if len(query) != 1 || len(bootstrap) != 1 || !app.consumeBootstrap(bootstrap[0]) {
			http.Error(response, "forbidden", http.StatusForbidden)
			return
		}
		token, _ := json.Marshal(app.uiToken)
		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = response.Write([]byte(`<!doctype html><meta charset="utf-8"><script>sessionStorage.setItem('remote-davinci-token', ` + string(token) + `); location.replace('/');</script>`))
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = response.Write(uiHTML)
}

func (app *App) handleState(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, app.state())
}

func (app *App) handleRelayWake(response http.ResponseWriter, request *http.Request) {
	var body map[string]json.RawMessage
	if !decodeJSONBody(response, request, &body, "invalid relay wake request") {
		return
	}
	if body == nil || len(body) != 0 {
		writeError(response, http.StatusBadRequest, "invalid relay wake request")
		return
	}

	app.enrollMu.Lock()
	defer app.enrollMu.Unlock()
	app.mu.RLock()
	if app.config == nil || app.config.LinkRevoked {
		app.mu.RUnlock()
		writeError(response, http.StatusConflict, "no active controller enrollment")
		return
	}
	config := *app.config
	app.mu.RUnlock()
	app.startRelay(config)
	writeJSON(response, http.StatusOK, map[string]bool{"woken": true})
}

func (app *App) handlePairingStart(response http.ResponseWriter, request *http.Request) {
	var body map[string]json.RawMessage
	if !decodeJSONBody(response, request, &body, "invalid pairing start request") {
		return
	}
	if body == nil || len(body) != 0 {
		writeError(response, http.StatusBadRequest, "invalid pairing start request")
		return
	}

	app.enrollMu.Lock()
	defer app.enrollMu.Unlock()
	app.mu.RLock()
	configured := app.config != nil
	current := app.pairing
	app.mu.RUnlock()
	if configured {
		writeError(response, http.StatusConflict, "reset the current enrollment first")
		return
	}
	if current != nil && (!current.finished() || !terminalPairingPhase(current.snapshot().Phase)) {
		writeError(response, http.StatusConflict, "a pairing attempt is already active")
		return
	}

	setup, cancel := context.WithTimeout(request.Context(), relayRequestTimeout)
	defer cancel()
	attempt, err := newPairingAttempt(app.ctx, setup, app.relayURL, companionDeviceLabel(), app.store.Save, app.store.Delete)
	if err != nil {
		writeError(response, http.StatusBadGateway, "could not create pairing invitation")
		return
	}
	app.mu.Lock()
	app.pairing = attempt
	app.status = RelayStatus{Message: pairingStatus(attempt.snapshot().Phase)}
	app.mu.Unlock()
	invite := attempt.invite
	go app.finishPairing(attempt)
	writeJSON(response, http.StatusOK, map[string]protocol.PairingInvite{"invite": invite})
}

func (app *App) finishPairing(attempt *pairingAttempt) {
	config, staged, err := attempt.run()
	app.reconcilePairing(attempt, config, staged, err)
}

func (app *App) reconcilePairing(attempt *pairingAttempt, config Config, staged bool, err error) {
	defer close(attempt.done)
	app.enrollMu.Lock()
	defer app.enrollMu.Unlock()
	app.mu.Lock()
	if app.pairing != attempt {
		app.mu.Unlock()
		return
	}
	if staged && config.V == 1 {
		app.config = &config
		app.pairing = nil
		if err == nil {
			app.status = RelayStatus{Message: "Controller paired; connecting to relay…"}
		} else {
			app.status = RelayStatus{Message: "Pairing activation unconfirmed; reconciling with relay…"}
		}
		app.mu.Unlock()
		app.startRelay(config)
		return
	}
	app.status = RelayStatus{Message: pairingStatus(attempt.snapshot().Phase)}
	app.mu.Unlock()
}

func (app *App) handlePairingApprove(response http.ResponseWriter, request *http.Request) {
	app.handlePairingDecision(response, request, true)
}

func (app *App) handlePairingReject(response http.ResponseWriter, request *http.Request) {
	app.handlePairingDecision(response, request, false)
}

func (app *App) handlePairingDecision(response http.ResponseWriter, request *http.Request, approve bool) {
	pairID, ok := pairingActionPairID(response, request)
	if !ok {
		return
	}
	app.mu.RLock()
	attempt := app.pairing
	app.mu.RUnlock()
	if attempt == nil || attempt.finished() || attempt.decide(approve, pairID) != nil {
		writeError(response, http.StatusConflict, "pairing is not awaiting approval")
		return
	}
	key := "rejected"
	if approve {
		key = "approved"
	}
	writeJSON(response, http.StatusOK, map[string]bool{key: true})
}

func (app *App) handlePairingCancel(response http.ResponseWriter, request *http.Request) {
	pairID, ok := pairingActionPairID(response, request)
	if !ok {
		return
	}
	app.mu.RLock()
	attempt := app.pairing
	app.mu.RUnlock()
	if attempt == nil || attempt.finished() || attempt.stop(pairID) != nil {
		writeError(response, http.StatusConflict, "pairing attempt did not match")
		return
	}
	writeJSON(response, http.StatusOK, map[string]bool{"cancelled": true})
}

func pairingActionPairID(response http.ResponseWriter, request *http.Request) (string, bool) {
	var body struct {
		PairID string `json:"pairId"`
	}
	if !decodeJSONBody(response, request, &body, "invalid pairing action") {
		return "", false
	}
	if !uuidPattern.MatchString(body.PairID) {
		writeError(response, http.StatusBadRequest, "invalid pairing action")
		return "", false
	}
	return body.PairID, true
}

func decodeJSONBody(response http.ResponseWriter, request *http.Request, destination any, message string) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		writeError(response, http.StatusBadRequest, message)
		return false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(response, http.StatusBadRequest, message)
		return false
	}
	return true
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
	pairing := app.pairing
	app.mu.RUnlock()
	if configured {
		writeError(response, http.StatusConflict, "reset the current enrollment first")
		return
	}
	if pairing != nil && (!pairing.finished() || !terminalPairingPhase(pairing.snapshot().Phase)) {
		writeError(response, http.StatusConflict, "cancel the active pairing attempt first")
		return
	}
	if pairing != nil {
		app.mu.Lock()
		if app.pairing == pairing {
			app.pairing = nil
		}
		app.mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(request.Context(), 45*time.Second)
	defer cancel()
	config, enrollmentResponse, err := Provision(ctx, app.relayURL, enrollment, func(config Config) error {
		return app.store.Save(config)
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
		if err := app.store.Save(checkpoint); err != nil {
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

	removeErr := app.store.Delete()
	app.mu.Lock()
	if removeErr != nil {
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

	if err := app.store.Delete(); err != nil {
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

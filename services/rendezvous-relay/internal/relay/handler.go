package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/anhydrous99/remote-davinci/protocol"
)

type WebSocketEvent struct {
	Body           string                  `json:"body,omitempty"`
	RequestContext WebSocketRequestContext `json:"requestContext"`
}

type WebSocketRequestContext struct {
	RouteKey     string         `json:"routeKey"`
	ConnectionID string         `json:"connectionId"`
	DomainName   string         `json:"domainName,omitempty"`
	Stage        string         `json:"stage,omitempty"`
	Identity     SocketIdentity `json:"identity,omitempty"`
	Authorizer   any            `json:"authorizer,omitempty"`
}

type SocketIdentity struct {
	SourceIP string `json:"sourceIp,omitempty"`
}

type WebSocketResponse struct {
	StatusCode int `json:"statusCode"`
}

type Message struct {
	Protocol string `json:"protocol"`
	V        int64  `json:"v"`
	Type     string `json:"type"`
	ID       string `json:"id"`
	ReplyTo  string `json:"replyTo,omitempty"`
	Body     any    `json:"body"`
}

type Post func(context.Context, string, Message, WebSocketEvent) error

type HandlerDependencies struct {
	Store   Store
	Post    Post
	Now     func() int64
	ID      func() string
	Locator func() string
	Logger  *slog.Logger
}

type Handler struct {
	store   Store
	post    Post
	now     func() int64
	id      func() string
	locator func() string
	logger  *slog.Logger
}

var (
	pairingActions = map[string]bool{
		"system.hello": true, "system.ping": true, "pair.create": true, "pair.join": true,
		"pair.commit": true, "pair.cancel": true,
	}
	endpointActions = map[string]bool{
		"system.hello": true, "system.ping": true, "link.get": true, "link.revoke": true,
		"endpoint.rotate": true, "endpoint.revoke": true, "session.open": true, "session.close": true,
	}
	knownErrors = func() map[protocol.ErrorCode]bool {
		result := make(map[protocol.ErrorCode]bool, len(protocol.ErrorCodes))
		for _, code := range protocol.ErrorCodes {
			result[code] = true
		}
		return result
	}()
)

func NewHandler(dependencies HandlerDependencies) *Handler {
	if dependencies.Now == nil {
		dependencies.Now = func() int64 { return time.Now().Unix() }
	}
	if dependencies.ID == nil {
		dependencies.ID = randomUUID
	}
	if dependencies.Locator == nil {
		dependencies.Locator = randomLocator
	}
	if dependencies.Logger == nil {
		dependencies.Logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	return &Handler{
		store: dependencies.Store, post: dependencies.Post, now: dependencies.Now,
		id: dependencies.ID, locator: dependencies.Locator, logger: dependencies.Logger,
	}
}

func response(messageType string, body any, id, replyTo string) Message {
	return Message{Protocol: protocol.ProtocolName, V: protocol.ProtocolVersion, Type: messageType, ID: id, ReplyTo: replyTo, Body: body}
}

func ok(request protocol.ClientEnvelope, result map[string]any, id string) Message {
	return response("ok", map[string]any{"requestType": request.Type, "result": result}, id, request.ID)
}

func failure(replyTo string, failure error, id string) Message {
	code, retryable := protocol.Internal, true
	var validation *protocol.ValidationError
	var service *ServiceError
	var retryAfter *int64
	switch {
	case errors.As(failure, &validation):
		code, retryable = validation.Code, false
	case errors.As(failure, &service):
		code, retryable, retryAfter = service.Code, service.Retryable, service.RetryAfterMS
	}
	if !knownErrors[code] {
		code, retryable = protocol.Internal, true
	}
	body := map[string]any{"code": code, "retryable": retryable}
	if retryAfter != nil {
		body["retryAfterMs"] = *retryAfter
	}
	return response("error", body, id, replyTo)
}

func peerConnection(pair Pair, connectionID string) (string, error) {
	if pair.SideA.ConnectionID == connectionID {
		if pair.SideB == nil {
			return "", nil
		}
		return pair.SideB.ConnectionID, nil
	}
	if pair.SideB != nil && pair.SideB.ConnectionID == connectionID {
		return pair.SideA.ConnectionID, nil
	}
	return "", serviceError(protocol.Forbidden)
}

func sessionPeer(session Session, connectionID string) (string, error) {
	if session.ControllerConnectionID == connectionID {
		return session.CompanionConnectionID, nil
	}
	if session.CompanionConnectionID == connectionID {
		return session.ControllerConnectionID, nil
	}
	return "", serviceError(protocol.Forbidden)
}

func SourceKey(sourceIP string) string {
	digest := sha256.Sum256([]byte(sourceIP))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func (h *Handler) notify(ctx context.Context, connectionID string, message Message, event WebSocketEvent) (bool, error) {
	if connectionID == "" {
		return false, nil
	}
	if err := h.post(ctx, connectionID, message, event); err != nil {
		if !gone(err) {
			return false, err
		}
		if err := h.cleanup(ctx, connectionID, "peer-disconnected", event, false); err != nil {
			return false, err
		}
		return false, nil
	}
	return true, nil
}

func (h *Handler) notifyEndpoint(ctx context.Context, endpointID string, message Message, event WebSocketEvent) error {
	endpoint, err := h.store.GetEndpoint(ctx, endpointID)
	if err != nil {
		return err
	}
	if endpoint != nil && endpoint.ConnectionID != "" && endpoint.RevokedAt == 0 {
		_, err = h.notify(ctx, endpoint.ConnectionID, message, event)
	}
	return err
}

func (h *Handler) closeAndNotify(ctx context.Context, sessionID, endpointID, reason string, event WebSocketEvent, skipConnectionID string) (*CloseSessionResult, error) {
	result, err := h.store.CloseSession(ctx, sessionID, endpointID, h.now())
	if err != nil || result == nil {
		return result, err
	}
	if result.ClosedNow {
		message := response("session.closed", map[string]any{"sessionId": sessionID, "reason": reason}, h.id(), "")
		for _, connectionID := range []string{result.Session.ControllerConnectionID, result.Session.CompanionConnectionID} {
			if connectionID != skipConnectionID {
				if _, err := h.notify(ctx, connectionID, message, event); err != nil {
					return nil, err
				}
			}
		}
	}
	return result, nil
}

func (h *Handler) cleanup(ctx context.Context, connectionID, reason string, event WebSocketEvent, sendEvents bool) error {
	connection, err := h.store.Disconnect(ctx, connectionID)
	if err != nil || connection == nil {
		return err
	}
	if connection.PairingID != "" {
		pair, err := h.store.CancelPair(ctx, connection.PairingID, connectionID, h.now())
		var service *ServiceError
		if err != nil && (!errors.As(err, &service) || service.Code != protocol.Conflict) {
			return err
		}
		if sendEvents && pair != nil && pair.Status == "CLOSED" {
			peer, err := peerConnection(*pair, connectionID)
			if err != nil {
				return err
			}
			_, err = h.notify(ctx, peer, response("pair.closed", map[string]any{
				"pairId": pair.PairID, "reason": reason,
			}, h.id(), ""), event)
			if err != nil {
				return err
			}
		}
	}
	if connection.SessionID != "" {
		_, err := h.closeAndNotify(ctx, connection.SessionID, "", reason, event, connectionID)
		return err
	}
	return nil
}

func (h *Handler) dispatch(ctx context.Context, message protocol.ClientEnvelope, connection Connection, event WebSocketEvent) (map[string]any, error) {
	timestamp := h.now()
	if message.Type == "relay.frame" {
		var frame protocol.RelayFrameBody
		if err := message.DecodeBody(&frame); err != nil {
			return nil, err
		}
		if frame.Channel == protocol.PairChannel {
			if connection.AuthMode != "pairing" || connection.PairingID != frame.ChannelID {
				return nil, serviceError(protocol.Forbidden)
			}
			pair, err := h.store.PairByID(ctx, frame.ChannelID, timestamp)
			if err != nil {
				return nil, err
			}
			if pair.Status != "READY" && pair.Status != "HALF_COMMITTED" {
				return nil, serviceError(protocol.PairUnavailable)
			}
			peer, err := peerConnection(pair, connection.ConnectionID)
			if err != nil {
				return nil, err
			}
			delivered, err := h.notify(ctx, peer, response("relay.frame", message.Body, h.id(), ""), event)
			if err != nil {
				return nil, err
			}
			if !delivered {
				return nil, retryableError(protocol.PeerOffline)
			}
			return map[string]any{"delivered": true}, nil
		}
		if connection.AuthMode != "endpoint" || connection.EndpointID == "" {
			return nil, serviceError(protocol.Forbidden)
		}
		session, err := h.store.Session(ctx, frame.ChannelID, timestamp)
		if err != nil {
			return nil, err
		}
		expectedEndpoint := ""
		if session.ControllerConnectionID == connection.ConnectionID {
			expectedEndpoint = session.ControllerID
		} else if session.CompanionConnectionID == connection.ConnectionID {
			expectedEndpoint = session.CompanionID
		}
		if expectedEndpoint != connection.EndpointID {
			return nil, serviceError(protocol.Forbidden)
		}
		controller, err := h.store.GetEndpoint(ctx, session.ControllerID)
		if err != nil {
			return nil, err
		}
		companion, err := h.store.GetEndpoint(ctx, session.CompanionID)
		if err != nil {
			return nil, err
		}
		link, err := h.store.Link(ctx, session.LinkID)
		if err != nil {
			return nil, err
		}
		valid := link != nil && link.Status == "ACTIVE" && link.ActiveSessionID == session.SessionID &&
			link.ControllerID == session.ControllerID && link.CompanionID == session.CompanionID &&
			controller != nil && controller.RevokedAt == 0 && controller.ConnectionID == session.ControllerConnectionID &&
			companion != nil && companion.RevokedAt == 0 && companion.ConnectionID == session.CompanionConnectionID
		if !valid {
			reason, code, retryable := "peer-disconnected", protocol.PeerOffline, true
			if link != nil && link.Status == "REVOKED" {
				reason, code, retryable = "revoked", protocol.Forbidden, false
			}
			if _, err := h.closeAndNotify(ctx, session.SessionID, "", reason, event, connection.ConnectionID); err != nil {
				return nil, err
			}
			if retryable {
				return nil, retryableError(code)
			}
			return nil, serviceError(code)
		}
		peer, err := sessionPeer(session, connection.ConnectionID)
		if err != nil {
			return nil, err
		}
		delivered, err := h.notify(ctx, peer, response("relay.frame", message.Body, h.id(), ""), event)
		if err != nil {
			return nil, err
		}
		if !delivered {
			return nil, retryableError(protocol.PeerOffline)
		}
		return map[string]any{"delivered": true}, nil
	}
	if connection.AuthMode == "pairing" && !pairingActions[message.Type] ||
		connection.AuthMode == "endpoint" && !endpointActions[message.Type] {
		return nil, serviceError(protocol.Forbidden)
	}

	switch message.Type {
	case "system.hello":
		return map[string]any{"serverTime": timestamp, "protocolVersion": protocol.ProtocolVersion}, nil
	case "system.ping":
		return map[string]any{"receivedAt": timestamp}, nil
	case "pair.create":
		if err := h.store.RateLimit(ctx, connection.SourceKey, message.Type, 5, timestamp); err != nil {
			return nil, err
		}
		for attempt := 0; attempt < 5; attempt++ {
			pair := Pair{
				PairID: h.id(), Locator: h.locator(), Status: "OPEN",
				SideA:   PairSide{ConnectionID: connection.ConnectionID, SideID: h.id()},
				Version: 1, ExpiresAt: timestamp + protocol.PairingTTLSeconds,
			}
			err := h.store.CreatePair(ctx, pair)
			if err == nil {
				return map[string]any{"pairId": pair.PairID, "sideId": pair.SideA.SideID, "locator": pair.Locator, "expiresAt": pair.ExpiresAt}, nil
			}
			var service *ServiceError
			if !errors.As(err, &service) || service.Code != protocol.Conflict || attempt == 4 {
				return nil, err
			}
		}
		return nil, retryableError(protocol.Conflict)
	case "pair.join":
		var body protocol.PairJoinBody
		if err := message.DecodeBody(&body); err != nil {
			return nil, err
		}
		if err := h.store.RateLimit(ctx, connection.SourceKey, message.Type, 20, timestamp); err != nil {
			return nil, err
		}
		side := PairSide{ConnectionID: connection.ConnectionID, SideID: h.id()}
		pair, err := h.store.JoinPair(ctx, body.Locator, side, timestamp)
		if err != nil {
			return nil, err
		}
		readyForA := response("pair.ready", map[string]any{"pairId": pair.PairID, "peerSideId": side.SideID, "expiresAt": pair.ExpiresAt}, h.id(), "")
		readyForB := response("pair.ready", map[string]any{"pairId": pair.PairID, "peerSideId": pair.SideA.SideID, "expiresAt": pair.ExpiresAt}, h.id(), "")
		if delivered, err := h.notify(ctx, pair.SideA.ConnectionID, readyForA, event); err != nil || !delivered {
			if err != nil {
				return nil, err
			}
			return nil, retryableError(protocol.PeerOffline)
		}
		if delivered, err := h.notify(ctx, side.ConnectionID, readyForB, event); err != nil || !delivered {
			if err != nil {
				return nil, err
			}
			return nil, retryableError(protocol.PeerOffline)
		}
		return map[string]any{"pairId": pair.PairID, "sideId": side.SideID, "expiresAt": pair.ExpiresAt}, nil
	case "pair.commit":
		var body protocol.PairCommitBody
		if err := message.DecodeBody(&body); err != nil {
			return nil, err
		}
		commit := PairCommit{
			ConnectionID: connection.ConnectionID, SideID: body.SideID, LinkID: body.LinkID,
			Self: PairEndpointCommit{EndpointID: body.Self.EndpointID, Role: body.Self.Role, CredentialHash: body.Self.CredentialHash},
			Peer: PairIdentity{EndpointID: body.Peer.EndpointID, Role: body.Peer.Role},
		}
		result, err := h.store.CommitPair(ctx, body.PairID, commit, timestamp)
		if err != nil {
			return nil, err
		}
		if result.Link == nil {
			return map[string]any{"pending": true}, nil
		}
		for _, value := range []*PairCommit{result.Pair.CommitA, result.Pair.CommitB} {
			if value == nil {
				continue
			}
			if _, err := h.notify(ctx, value.ConnectionID, response("pair.completed", map[string]any{
				"pairId": result.Pair.PairID, "linkId": result.Link.LinkID,
				"peerEndpointId": value.Peer.EndpointID, "peerRole": value.Peer.Role,
			}, h.id(), ""), event); err != nil {
				return nil, err
			}
		}
		return map[string]any{"linkId": result.Link.LinkID, "active": true}, nil
	case "pair.cancel":
		var body protocol.PairCancelBody
		if err := message.DecodeBody(&body); err != nil {
			return nil, err
		}
		pair, err := h.store.CancelPair(ctx, body.PairID, connection.ConnectionID, timestamp)
		if err != nil {
			return nil, err
		}
		if pair != nil && pair.Status == "CLOSED" {
			peer, err := peerConnection(*pair, connection.ConnectionID)
			if err != nil {
				return nil, err
			}
			if _, err := h.notify(ctx, peer, response("pair.closed", map[string]any{"pairId": pair.PairID, "reason": "cancelled"}, h.id(), ""), event); err != nil {
				return nil, err
			}
		}
		return map[string]any{"cancelled": true}, nil
	case "link.get":
		var body protocol.LinkBody
		if err := message.DecodeBody(&body); err != nil {
			return nil, err
		}
		link, err := h.store.Link(ctx, body.LinkID)
		if err != nil {
			return nil, err
		}
		if link == nil || connection.EndpointID == "" || link.ControllerID != connection.EndpointID && link.CompanionID != connection.EndpointID {
			return nil, serviceError(protocol.Forbidden)
		}
		peerEndpointID, peerRole := link.ControllerID, protocol.Controller
		if link.ControllerID == connection.EndpointID {
			peerEndpointID, peerRole = link.CompanionID, protocol.Companion
		}
		result := map[string]any{
			"linkId": link.LinkID, "peerEndpointId": peerEndpointID, "peerRole": peerRole, "status": strings.ToLower(link.Status),
		}
		if link.RevokedAt != 0 {
			result["revokedAt"] = link.RevokedAt
		}
		return result, nil
	case "link.revoke":
		if connection.EndpointID == "" {
			return nil, serviceError(protocol.Forbidden)
		}
		var body protocol.LinkBody
		if err := message.DecodeBody(&body); err != nil {
			return nil, err
		}
		current, err := h.store.Link(ctx, body.LinkID)
		if err != nil {
			return nil, err
		}
		revoked, err := h.store.RevokeLink(ctx, body.LinkID, connection.EndpointID, timestamp)
		if err != nil {
			return nil, err
		}
		if current != nil && current.ActiveSessionID != "" {
			if _, err := h.closeAndNotify(ctx, current.ActiveSessionID, connection.EndpointID, "revoked", event, ""); err != nil {
				return nil, err
			}
		}
		peerEndpointID := revoked.ControllerID
		if revoked.ControllerID == connection.EndpointID {
			peerEndpointID = revoked.CompanionID
		}
		if err := h.notifyEndpoint(ctx, peerEndpointID, response("link.revoked", map[string]any{"linkId": revoked.LinkID}, h.id(), ""), event); err != nil {
			return nil, err
		}
		return map[string]any{"revoked": true}, nil
	case "endpoint.rotate":
		if connection.EndpointID == "" {
			return nil, serviceError(protocol.Forbidden)
		}
		var body protocol.EndpointRotateBody
		if err := message.DecodeBody(&body); err != nil {
			return nil, err
		}
		if err := h.store.RotateEndpoint(ctx, connection.EndpointID, body.CredentialHash, timestamp); err != nil {
			return nil, err
		}
		return map[string]any{"rotated": true}, nil
	case "endpoint.revoke":
		if connection.EndpointID == "" {
			return nil, serviceError(protocol.Forbidden)
		}
		revoked, err := h.store.RevokeEndpoint(ctx, connection.EndpointID, timestamp)
		if err != nil {
			return nil, err
		}
		for _, session := range revoked.Sessions {
			closed := response("session.closed", map[string]any{"sessionId": session.SessionID, "reason": "revoked"}, h.id(), "")
			if _, err := h.notify(ctx, session.ControllerConnectionID, closed, event); err != nil {
				return nil, err
			}
			if _, err := h.notify(ctx, session.CompanionConnectionID, closed, event); err != nil {
				return nil, err
			}
		}
		for _, link := range revoked.Links {
			peerEndpointID := link.ControllerID
			if link.ControllerID == connection.EndpointID {
				peerEndpointID = link.CompanionID
			}
			if err := h.notifyEndpoint(ctx, peerEndpointID, response("link.revoked", map[string]any{"linkId": link.LinkID}, h.id(), ""), event); err != nil {
				return nil, err
			}
		}
		return map[string]any{"revoked": true, "linksRevoked": len(revoked.Links)}, nil
	case "session.open":
		if connection.EndpointID == "" {
			return nil, serviceError(protocol.Forbidden)
		}
		var body protocol.LinkBody
		if err := message.DecodeBody(&body); err != nil {
			return nil, err
		}
		session, err := h.store.OpenSession(ctx, body.LinkID, connection.EndpointID, connection.ConnectionID, h.id(), timestamp)
		if err != nil {
			return nil, err
		}
		controllerNotified, err := h.notify(ctx, session.ControllerConnectionID, response("session.opened", map[string]any{
			"sessionId": session.SessionID, "linkId": session.LinkID, "peerEndpointId": session.CompanionID,
		}, h.id(), ""), event)
		if err != nil {
			return nil, err
		}
		if !controllerNotified {
			_, _ = h.closeAndNotify(ctx, session.SessionID, "", "peer-disconnected", event, "")
			return nil, retryableError(protocol.PeerOffline)
		}
		companionNotified, err := h.notify(ctx, session.CompanionConnectionID, response("session.opened", map[string]any{
			"sessionId": session.SessionID, "linkId": session.LinkID, "peerEndpointId": session.ControllerID,
		}, h.id(), ""), event)
		if err != nil {
			return nil, err
		}
		if !companionNotified {
			_, _ = h.closeAndNotify(ctx, session.SessionID, "", "peer-disconnected", event, "")
			return nil, retryableError(protocol.PeerOffline)
		}
		return map[string]any{"sessionId": session.SessionID}, nil
	case "session.close":
		if connection.EndpointID == "" {
			return nil, serviceError(protocol.Forbidden)
		}
		var body protocol.SessionCloseBody
		if err := message.DecodeBody(&body); err != nil {
			return nil, err
		}
		if _, err := h.closeAndNotify(ctx, body.SessionID, connection.EndpointID, "requested", event, ""); err != nil {
			return nil, err
		}
		return map[string]any{"closed": true}, nil
	default:
		return nil, serviceError(protocol.InvalidMessage)
	}
}

func (h *Handler) Handle(ctx context.Context, event WebSocketEvent) (WebSocketResponse, error) {
	routeKey, connectionID := event.RequestContext.RouteKey, event.RequestContext.ConnectionID
	if routeKey == "$connect" {
		authMode := authorizerValue(event.RequestContext.Authorizer, "authMode")
		endpointID := authorizerValue(event.RequestContext.Authorizer, "endpointId")
		credentialHash := authorizerValue(event.RequestContext.Authorizer, "credentialHash")
		if authMode != "pairing" && authMode != "endpoint" || authMode == "endpoint" && (endpointID == "" || credentialHash == "") {
			return WebSocketResponse{StatusCode: 401}, nil
		}
		timestamp := h.now()
		connection := Connection{
			ConnectionID: connectionID, AuthMode: authMode, EndpointID: endpointID,
			SourceKey:   SourceKey(sourceIP(event.RequestContext.Identity.SourceIP)),
			ConnectedAt: timestamp, ExpiresAt: timestamp + 2*60*60 + 5*60,
		}
		if err := h.store.Connect(ctx, connection, credentialHash); err != nil {
			var service *ServiceError
			code := protocol.Internal
			status := 500
			if errors.As(err, &service) {
				code, status = service.Code, 401
			}
			h.logger.WarnContext(ctx, "connect-rejected", "connectionId", connectionID, "error", code)
			return WebSocketResponse{StatusCode: status}, nil
		}
		return WebSocketResponse{StatusCode: 200}, nil
	}
	if routeKey == "$disconnect" {
		if err := h.cleanup(ctx, connectionID, "peer-disconnected", event, true); err != nil {
			return WebSocketResponse{}, err
		}
		return WebSocketResponse{StatusCode: 200}, nil
	}
	if routeKey != "$default" {
		return WebSocketResponse{StatusCode: 400}, nil
	}
	requestID := h.id()
	connection, err := h.store.Connection(ctx, connectionID, h.now())
	if err == nil {
		var message protocol.ClientEnvelope
		message, err = protocol.ParseClient(event.Body)
		if err == nil {
			requestID = message.ID
			h.logger.InfoContext(ctx, "message", "connectionId", connectionID, "messageType", message.Type)
			var result map[string]any
			result, err = h.dispatch(ctx, message, connection, event)
			if err == nil {
				_, err = h.notify(ctx, connectionID, ok(message, result, h.id()), event)
			}
		}
	}
	if err != nil {
		code := protocol.Internal
		var validation *protocol.ValidationError
		var service *ServiceError
		if errors.As(err, &validation) {
			code = validation.Code
		} else if errors.As(err, &service) {
			code = service.Code
		}
		h.logger.WarnContext(ctx, "message-rejected", "connectionId", connectionID, "error", code)
		if _, notifyErr := h.notify(ctx, connectionID, failure(requestID, err, h.id()), event); notifyErr != nil {
			return WebSocketResponse{}, notifyErr
		}
	}
	return WebSocketResponse{StatusCode: 200}, nil
}

func authorizerValue(authorizer any, key string) string {
	switch value := authorizer.(type) {
	case map[string]any:
		result, _ := value[key].(string)
		return result
	case map[string]string:
		return value[key]
	default:
		return ""
	}
}

func sourceIP(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func gone(err error) bool {
	var apiError interface{ ErrorCode() string }
	return errors.As(err, &apiError) && apiError.ErrorCode() == "GoneException"
}

func randomUUID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	bytes[6] = bytes[6]&0x0f | 0x40
	bytes[8] = bytes[8]&0x3f | 0x80
	value := hex.EncodeToString(bytes)
	return fmt.Sprintf("%s-%s-%s-%s-%s", value[:8], value[8:12], value[12:16], value[16:20], value[20:])
}

func randomLocator() string {
	value, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%06d", value.Int64())
}

func MarshalMessage(message Message) ([]byte, error) { return json.Marshal(message) }

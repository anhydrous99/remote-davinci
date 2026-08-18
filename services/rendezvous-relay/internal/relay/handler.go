package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/anhydrous99/remote-davinci/protocol"
	"github.com/aws/aws-lambda-go/events"
)

type WebSocketEvent = events.APIGatewayWebsocketProxyRequest
type WebSocketResponse = events.APIGatewayProxyResponse

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
	Drop    func(context.Context, string, WebSocketEvent) error
	Now     func() int64
	ID      func() string
	Locator func() string
	Logger  *slog.Logger
}

type Handler struct {
	store   Store
	post    Post
	drop    func(context.Context, string, WebSocketEvent) error
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
	requestIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

const (
	pairingConnectsPerMinute  = int64(30)
	sessionFramesPerMinute    = int64(3_600)
	endpointMessagesPerMinute = int64(600)
)

func NewHandler(dependencies HandlerDependencies) *Handler {
	if dependencies.Now == nil {
		dependencies.Now = func() int64 { return time.Now().Unix() }
	}
	if dependencies.Drop == nil {
		dependencies.Drop = func(context.Context, string, WebSocketEvent) error { return nil }
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
		store: dependencies.Store, post: dependencies.Post, drop: dependencies.Drop, now: dependencies.Now,
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
	if !slices.Contains(protocol.ErrorCodes, code) {
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
	if address, err := netip.ParseAddr(sourceIP); err == nil {
		address = address.Unmap()
		if address.Is6() {
			sourceIP = netip.PrefixFrom(address, 64).Masked().String()
		} else {
			sourceIP = address.String()
		}
	}
	digest := sha256.Sum256([]byte(sourceIP))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func credentialDigest(secret string) string {
	decoded, _ := base64.RawURLEncoding.DecodeString(secret)
	digest := sha256.Sum256(decoded)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func constantTimeEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
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

func (h *Handler) notifyClosedSession(ctx context.Context, result *CloseSessionResult, reason string, event WebSocketEvent, skipConnectionID string) error {
	if result == nil || !result.ClosedNow {
		return nil
	}
	message := response("session.closed", map[string]any{"sessionId": result.Session.SessionID, "reason": reason}, h.id(), "")
	for _, connectionID := range []string{result.Session.ControllerConnectionID, result.Session.CompanionConnectionID} {
		if connectionID != skipConnectionID {
			if _, err := h.notify(ctx, connectionID, message, event); err != nil {
				return err
			}
		}
	}
	return nil
}

func (h *Handler) notifyOpenedSession(ctx context.Context, session Session, event WebSocketEvent) error {
	for _, target := range []struct {
		connectionID   string
		peerEndpointID string
	}{
		{session.CompanionConnectionID, session.ControllerID},
		{session.ControllerConnectionID, session.CompanionID},
	} {
		delivered, err := h.notify(ctx, target.connectionID, response("session.opened", map[string]any{
			"sessionId": session.SessionID, "linkId": session.LinkID, "peerEndpointId": target.peerEndpointID,
		}, h.id(), ""), event)
		if err != nil {
			return err
		}
		if !delivered {
			return retryableError(protocol.PeerOffline)
		}
	}
	return nil
}

func serviceCode(err error) protocol.ErrorCode {
	var service *ServiceError
	if errors.As(err, &service) {
		return service.Code
	}
	return ""
}

func validationFailure(err error) bool {
	var validation *protocol.ValidationError
	return errors.As(err, &validation)
}

func shouldDropFrame(route string, err error) bool {
	frameRoute := route == "pair.frame" || route == "session.frame"
	if frameRoute && validationFailure(err) {
		return true
	}
	code := serviceCode(err)
	return code == protocol.RateLimited || frameRoute && code == protocol.InvalidMessage ||
		route == "session.frame" && (code == protocol.Unauthenticated || code == protocol.Forbidden)
}

func shouldDropDefault(err error) bool {
	code := serviceCode(err)
	return validationFailure(err) || code == protocol.RateLimited || code == protocol.Unauthenticated
}

func (h *Handler) dropAndCleanup(ctx context.Context, event WebSocketEvent) error {
	dropErr := h.drop(ctx, event.RequestContext.ConnectionID, event)
	if gone(dropErr) {
		dropErr = nil
	}
	return errors.Join(dropErr, h.cleanup(ctx, event.RequestContext.ConnectionID, "peer-disconnected", event, true))
}

func (h *Handler) rejectAndDrop(ctx context.Context, requestID string, rejection error, event WebSocketEvent) error {
	_, notifyErr := h.notify(ctx, event.RequestContext.ConnectionID, failure(requestID, rejection, h.id()), event)
	return errors.Join(notifyErr, h.dropAndCleanup(ctx, event))
}

func (h *Handler) closeAndNotify(ctx context.Context, sessionID, endpointID, connectionID, reason string, event WebSocketEvent, skipConnectionID string) (*CloseSessionResult, error) {
	result, err := h.store.CloseSession(ctx, sessionID, endpointID, connectionID, h.now())
	if err != nil {
		return result, err
	}
	if err := h.notifyClosedSession(ctx, result, reason, event, skipConnectionID); err != nil {
		return nil, err
	}
	return result, nil
}

func (h *Handler) cleanup(ctx context.Context, connectionID, reason string, event WebSocketEvent, sendPairEvent bool) error {
	result, err := h.store.Disconnect(ctx, connectionID, h.now())
	if err != nil || result == nil {
		return err
	}
	connection := result.Connection
	if connection.PairingID != "" {
		pair, err := h.store.CancelPair(ctx, connection.PairingID, connectionID, h.now())
		var service *ServiceError
		if err != nil && (!errors.As(err, &service) || service.Code != protocol.Conflict) {
			return err
		}
		if sendPairEvent && pair != nil && pair.Status == "CLOSED" {
			peer, err := peerConnection(*pair, connectionID)
			if err != nil {
				return err
			}
			if _, err := h.notify(ctx, peer, response("pair.closed", map[string]any{
				"pairId": pair.PairID, "reason": reason,
			}, h.id(), ""), event); err != nil {
				return err
			}
		}
	}
	return h.notifyClosedSession(ctx, result.Session, reason, event, connectionID)
}

func (h *Handler) relayPairFrame(ctx context.Context, message protocol.ClientEnvelope, event WebSocketEvent) error {
	var frame protocol.PairFrameBody
	if err := message.DecodeBody(&frame); err != nil {
		return err
	}
	if err := h.store.RateLimit(ctx, SourceKey(sourceIP(event.RequestContext.Identity.SourceIP)), message.Type, 120, h.now()); err != nil {
		return err
	}
	pair, err := h.store.PairByID(ctx, frame.PairID, h.now())
	if err != nil {
		return err
	}
	if pair.Status != "READY" && pair.Status != "HALF_COMMITTED" {
		return serviceError(protocol.PairUnavailable)
	}
	peer, err := peerConnection(pair, event.RequestContext.ConnectionID)
	if err != nil {
		return err
	}
	delivered, err := h.notify(ctx, peer, response("pair.frame", message.Body, h.id(), ""), event)
	if err != nil {
		return err
	}
	if !delivered {
		return retryableError(protocol.PeerOffline)
	}
	return nil
}

func (h *Handler) relaySessionFrame(ctx context.Context, message protocol.ClientEnvelope, event WebSocketEvent) error {
	var frame protocol.SessionFrameBody
	if err := message.DecodeBody(&frame); err != nil {
		return err
	}
	timestamp := h.now()
	connection, err := h.store.Connection(ctx, event.RequestContext.ConnectionID, timestamp)
	if err != nil {
		return err
	}
	if connection.AuthMode != "endpoint" || connection.EndpointID == "" {
		return serviceError(protocol.Forbidden)
	}
	if err := h.store.RateLimit(ctx, connection.EndpointID, message.Type, sessionFramesPerMinute, timestamp); err != nil {
		return err
	}
	session, err := h.store.Session(ctx, frame.SessionID, timestamp)
	if err != nil {
		return err
	}
	peer, err := sessionPeer(session, event.RequestContext.ConnectionID)
	if err != nil {
		return err
	}
	delivered, err := h.notify(ctx, peer, response("session.frame", message.Body, h.id(), ""), event)
	if err != nil {
		return err
	}
	if !delivered {
		return retryableError(protocol.PeerOffline)
	}
	return nil
}

func (h *Handler) dispatch(ctx context.Context, message protocol.ClientEnvelope, connection Connection, event WebSocketEvent) (map[string]any, error) {
	timestamp := h.now()
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
				SideA:     PairSide{ConnectionID: connection.ConnectionID, SideID: h.id()},
				ExpiresAt: timestamp + protocol.PairingTTLSeconds,
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
		peerEndpoint, err := h.store.GetEndpoint(ctx, peerEndpointID)
		if err != nil {
			return nil, err
		}
		status, revokedAt := link.Status, link.RevokedAt
		if peerEndpoint == nil || peerEndpoint.RevokedAt != 0 {
			status = "REVOKED"
			if peerEndpoint != nil && (revokedAt == 0 || peerEndpoint.RevokedAt < revokedAt) {
				revokedAt = peerEndpoint.RevokedAt
			}
		}
		result := map[string]any{
			"linkId": link.LinkID, "peerEndpointId": peerEndpointID, "peerRole": peerRole, "status": strings.ToLower(status),
		}
		if revokedAt != 0 {
			result["revokedAt"] = revokedAt
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
		revoked, err := h.store.RevokeLink(ctx, body.LinkID, connection.EndpointID, connection.ConnectionID, timestamp)
		if err != nil {
			return nil, err
		}
		if err := h.notifyClosedSession(ctx, revoked.Session, "revoked", event, ""); err != nil {
			return nil, err
		}
		peerEndpointID := revoked.Link.ControllerID
		if revoked.Link.ControllerID == connection.EndpointID {
			peerEndpointID = revoked.Link.CompanionID
		}
		if err := h.notifyEndpoint(ctx, peerEndpointID, response("link.revoked", map[string]any{"linkId": revoked.Link.LinkID}, h.id(), ""), event); err != nil {
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
		if err := h.store.RotateEndpoint(ctx, connection.EndpointID, connection.ConnectionID, body.CredentialHash, timestamp); err != nil {
			return nil, err
		}
		return map[string]any{"rotated": true}, nil
	case "endpoint.revoke":
		if connection.EndpointID == "" {
			return nil, serviceError(protocol.Forbidden)
		}
		revoked, err := h.store.RevokeEndpoint(ctx, connection.EndpointID, connection.ConnectionID, timestamp)
		if err != nil {
			return nil, err
		}
		if err := h.notifyClosedSession(ctx, revoked.Session, "revoked", event, ""); err != nil {
			return nil, err
		}
		if revoked.Session != nil && revoked.Session.ClosedNow {
			session := revoked.Session.Session
			peerConnectionID := session.ControllerConnectionID
			if session.ControllerID == connection.EndpointID {
				peerConnectionID = session.CompanionConnectionID
			}
			if _, err := h.notify(ctx, peerConnectionID, response("link.revoked", map[string]any{"linkId": session.LinkID}, h.id(), ""), event); err != nil {
				return nil, err
			}
		}
		return map[string]any{"revoked": true}, nil
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
		if notifyErr := h.notifyOpenedSession(ctx, session, event); notifyErr != nil {
			_, closeErr := h.closeAndNotify(ctx, session.SessionID, "", "", "peer-disconnected", event, "")
			return nil, errors.Join(notifyErr, closeErr)
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
		if _, err := h.closeAndNotify(ctx, body.SessionID, connection.EndpointID, connection.ConnectionID, "requested", event, ""); err != nil {
			return nil, err
		}
		return map[string]any{"closed": true}, nil
	default:
		return nil, serviceError(protocol.InvalidMessage)
	}
}

func (h *Handler) handleConnect(ctx context.Context, event WebSocketEvent) (WebSocketResponse, error) {
	authorization, err := protocol.ParseAuthorization(header(event.Headers, "authorization"))
	if err != nil {
		h.logger.WarnContext(ctx, "connect-rejected", "connectionId", event.RequestContext.ConnectionID, "error", protocol.Unauthenticated)
		return WebSocketResponse{StatusCode: 401}, nil
	}
	authMode, endpointID, credentialHash := "pairing", "", ""
	if authorization.Scheme == "bearer" {
		endpoint, readErr := h.store.GetEndpoint(ctx, authorization.EndpointID)
		if readErr != nil {
			return WebSocketResponse{}, readErr
		}
		credentialHash = credentialDigest(authorization.Secret)
		if endpoint == nil || endpoint.RevokedAt != 0 || !constantTimeEqual(endpoint.CredentialHash, credentialHash) {
			h.logger.WarnContext(ctx, "connect-rejected", "connectionId", event.RequestContext.ConnectionID, "error", protocol.Unauthenticated)
			return WebSocketResponse{StatusCode: 401}, nil
		}
		authMode, endpointID = "endpoint", authorization.EndpointID
	}
	timestamp := h.now()
	connection := Connection{
		ConnectionID: event.RequestContext.ConnectionID, AuthMode: authMode, EndpointID: endpointID,
		SourceKey:   SourceKey(sourceIP(event.RequestContext.Identity.SourceIP)),
		ConnectedAt: timestamp, ExpiresAt: timestamp + 2*60*60 + 5*60,
	}
	var closed *CloseSessionResult
	if authMode == "pairing" {
		err = h.store.RateLimit(ctx, connection.SourceKey, "pairing.connect", pairingConnectsPerMinute, timestamp)
	}
	if err == nil {
		closed, err = h.store.Connect(ctx, connection, credentialHash)
	}
	if err != nil {
		var service *ServiceError
		code, status := protocol.Internal, 500
		if errors.As(err, &service) {
			code = service.Code
			if service.Code == protocol.Unauthenticated || service.Code == protocol.Forbidden {
				status = 401
			} else if service.Retryable {
				status = 503
			}
		}
		h.logger.WarnContext(ctx, "connect-rejected", "connectionId", event.RequestContext.ConnectionID, "error", code)
		return WebSocketResponse{StatusCode: status}, nil
	}
	if closed != nil {
		skip := closed.Session.ControllerConnectionID
		if closed.Session.ControllerID != endpointID {
			skip = closed.Session.CompanionConnectionID
		}
		if err := h.notifyClosedSession(ctx, closed, "replaced", event, skip); err != nil {
			h.logger.WarnContext(ctx, "replacement-notification-failed", "connectionId", event.RequestContext.ConnectionID)
		}
	}
	return WebSocketResponse{StatusCode: 200}, nil
}

func (h *Handler) handleFrame(ctx context.Context, event WebSocketEvent) (WebSocketResponse, error) {
	message, err := protocol.ParseClient(event.Body)
	requestID := message.ID
	if err == nil {
		if message.Type != event.RequestContext.RouteKey {
			err = serviceError(protocol.InvalidMessage)
		} else if message.Type == "pair.frame" {
			err = h.relayPairFrame(ctx, message, event)
		} else {
			err = h.relaySessionFrame(ctx, message, event)
		}
	} else {
		requestID = requestIDFromBody(event.Body, h.id())
	}
	if err != nil {
		h.logRejected(ctx, event, err)
		if shouldDropFrame(event.RequestContext.RouteKey, err) {
			if dropErr := h.rejectAndDrop(ctx, requestID, err, event); dropErr != nil {
				return WebSocketResponse{}, dropErr
			}
		} else if _, notifyErr := h.notify(ctx, event.RequestContext.ConnectionID, failure(requestID, err, h.id()), event); notifyErr != nil {
			return WebSocketResponse{}, notifyErr
		}
	}
	return WebSocketResponse{StatusCode: 200}, nil
}

func (h *Handler) handleDefault(ctx context.Context, event WebSocketEvent) (WebSocketResponse, error) {
	message, err := protocol.ParseClient(event.Body)
	requestID := message.ID
	var reply Message
	if err == nil {
		var connection Connection
		connection, err = h.store.Connection(ctx, event.RequestContext.ConnectionID, h.now())
		if err == nil {
			switch connection.AuthMode {
			case "pairing":
				err = h.store.RateLimit(ctx, connection.SourceKey, "pairing.message", 120, h.now())
			case "endpoint":
				if connection.EndpointID == "" {
					err = serviceError(protocol.Unauthenticated)
				} else {
					err = h.store.RateLimit(ctx, connection.EndpointID, "endpoint.message", endpointMessagesPerMinute, h.now())
				}
			default:
				err = serviceError(protocol.Unauthenticated)
			}
		}
		if err == nil {
			var result map[string]any
			result, err = h.dispatch(ctx, message, connection, event)
			if err == nil {
				reply = ok(message, result, h.id())
			}
		}
	} else {
		requestID = requestIDFromBody(event.Body, h.id())
	}
	if err != nil {
		h.logRejected(ctx, event, err)
		if shouldDropDefault(err) {
			return WebSocketResponse{StatusCode: 200}, h.rejectAndDrop(ctx, requestID, err, event)
		}
		reply = failure(requestID, err, h.id())
	}
	body, err := MarshalMessage(reply)
	if err != nil {
		return WebSocketResponse{}, err
	}
	return WebSocketResponse{StatusCode: 200, Body: string(body)}, nil
}

func (h *Handler) logRejected(ctx context.Context, event WebSocketEvent, err error) {
	code := protocol.Internal
	var validation *protocol.ValidationError
	var service *ServiceError
	if errors.As(err, &validation) {
		code = validation.Code
	} else if errors.As(err, &service) {
		code = service.Code
	}
	h.logger.WarnContext(ctx, "message-rejected", "connectionId", event.RequestContext.ConnectionID, "routeKey", event.RequestContext.RouteKey, "error", code)
}

func (h *Handler) Handle(ctx context.Context, event WebSocketEvent) (WebSocketResponse, error) {
	switch event.RequestContext.RouteKey {
	case "$connect":
		return h.handleConnect(ctx, event)
	case "$disconnect":
		if err := h.cleanup(ctx, event.RequestContext.ConnectionID, "peer-disconnected", event, true); err != nil {
			return WebSocketResponse{}, err
		}
		return WebSocketResponse{StatusCode: 200}, nil
	case "pair.frame", "session.frame":
		return h.handleFrame(ctx, event)
	case "$default":
		return h.handleDefault(ctx, event)
	default:
		return WebSocketResponse{StatusCode: 400}, nil
	}
}

func header(headers map[string]string, name string) string {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value
		}
	}
	return ""
}

func requestIDFromBody(body, fallback string) string {
	var envelope struct {
		ID string `json:"id"`
	}
	if json.Unmarshal([]byte(body), &envelope) == nil && requestIDPattern.MatchString(envelope.ID) {
		return envelope.ID
	}
	return fallback
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

package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type conformanceFixtures struct {
	Authorization struct {
		Pairing string `json:"pairing"`
		Bearer  string `json:"bearer"`
	} `json:"authorization"`
	Client          []json.RawMessage `json:"client"`
	Server          []json.RawMessage `json:"server"`
	PairingIdentity json.RawMessage   `json:"pairingIdentity"`
	Wormhole        []json.RawMessage `json:"wormhole"`
	Control         []json.RawMessage `json:"control"`
	InvalidClient   []struct {
		Name  string          `json:"name"`
		Frame json.RawMessage `json:"frame"`
	} `json:"invalidClient"`
}

func fixtures(t *testing.T) conformanceFixtures {
	t.Helper()
	data, err := os.ReadFile("fixtures/conformance-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var result conformanceFixtures
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func requireCode(t *testing.T, code ErrorCode, err error) {
	t.Helper()
	var validation *ValidationError
	if !errors.As(err, &validation) || validation.Code != code {
		t.Fatalf("got error %v, want validation code %s", err, code)
	}
}

func rawObject(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRendezvousFixturesAndMessageTypes(t *testing.T) {
	values := fixtures(t)
	clientTypes := make([]string, 0, len(values.Client))
	for _, frame := range values.Client {
		envelope, err := ParseClient(frame)
		if err != nil {
			t.Fatal(err)
		}
		switch envelope.Type {
		case "pair.frame":
			var body PairFrameBody
			if err := envelope.DecodeBody(&body); err != nil || body.PairID == "" {
				t.Fatalf("pair frame body = %#v, error = %v", body, err)
			}
		case "session.frame":
			var body SessionFrameBody
			if err := envelope.DecodeBody(&body); err != nil || body.SessionID == "" {
				t.Fatalf("session frame body = %#v, error = %v", body, err)
			}
		}
		clientTypes = append(clientTypes, envelope.Type)
	}
	if !reflect.DeepEqual(clientTypes, ClientMessageTypes) {
		t.Fatalf("client types = %v", clientTypes)
	}
	serverTypes := make([]string, 0, len(values.Server))
	for _, frame := range values.Server {
		envelope, err := ParseServer(string(frame))
		if err != nil {
			t.Fatal(err)
		}
		serverTypes = append(serverTypes, envelope.Type)
	}
	if !reflect.DeepEqual(serverTypes, ServerMessageTypes) {
		t.Fatalf("server types = %v", serverTypes)
	}
	extended := rawObject(t, values.Client[2])
	extended["futureField"] = map[string]any{"safely": "ignored"}
	if _, err := ParseClient(extended); err != nil {
		t.Fatal(err)
	}
	frameCount := 0
	for _, frame := range values.Client {
		extended = rawObject(t, frame)
		messageType, _ := extended["type"].(string)
		if messageType != "pair.frame" && messageType != "session.frame" {
			continue
		}
		extended["body"].(map[string]any)["futureField"] = true
		if _, err := ParseClient(extended); err != nil {
			t.Fatalf("%s with future body field: %v", messageType, err)
		}
		frameCount++
	}
	if frameCount != 2 {
		t.Fatalf("got %d frame fixtures, want 2", frameCount)
	}
}

func TestSchemaValidIntegerSpellings(t *testing.T) {
	for _, spelling := range []string{"1.0", "1e0"} {
		clientJSON := strings.ReplaceAll(`{"protocol":"remote-davinci.rendezvous","v":NUMBER,"type":"pair.frame","id":"00000000-0000-4000-8000-000000000007","body":{"pairId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","seq":NUMBER,"payload":"AQ"}}`, "NUMBER", spelling)
		client, err := ParseClient(clientJSON)
		if err != nil {
			t.Fatalf("%s client: %v", spelling, err)
		}
		var frame PairFrameBody
		if err := client.DecodeBody(&frame); err != nil || client.V != 1 || frame.Seq != 1 {
			t.Fatalf("%s client = %#v, body = %#v, error = %v", spelling, client, frame, err)
		}

		controlJSON := strings.ReplaceAll(`{"protocol":"remote-davinci.control","v":NUMBER,"type":"request","id":"20000000-0000-4000-8000-000000000002","body":{"operation":"resolve.page.edit","args":{},"sentAt":NUMBER,"expiresAt":NUMBER}}`, "NUMBER", spelling)
		control, err := ParseControl(controlJSON)
		if err != nil || control.V != 1 {
			t.Fatalf("%s control = %#v, error = %v", spelling, control, err)
		}
	}
}

func TestQRPairingInviteAndTokenAdmission(t *testing.T) {
	joinToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	psk := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	pairID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	creatorSideID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	joinerSideID := "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	linkID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	invite := map[string]any{
		"protocol": PairingInviteProtocolName, "v": 1,
		"relayUrl": "wss://relay.example/v1", "pairId": pairID,
		"creatorSideId": creatorSideID, "linkId": linkID,
		"joinToken": joinToken, "psk": psk, "expiresAt": int64(300),
	}
	parsed, err := ParsePairingInvite(invite)
	if err != nil || parsed.JoinToken != joinToken {
		t.Fatalf("invite = %#v, error = %v", parsed, err)
	}
	if err := ValidatePairingInviteAt(parsed, 1); err != nil {
		t.Fatal(err)
	}
	requireCode(t, PairExpired, ValidatePairingInviteAt(parsed, 300))
	withClockLag := parsed
	withClockLag.ExpiresAt = 361
	if err := ValidatePairingInviteAt(withClockLag, 1); err != nil {
		t.Fatalf("invite within clock-skew tolerance: %v", err)
	}
	tooFar := parsed
	tooFar.ExpiresAt = 362
	requireCode(t, PairExpired, ValidatePairingInviteAt(tooFar, 1))
	prologue, err := PairingNoisePrologue(parsed.RelayURL, pairID, creatorSideID, joinerSideID, linkID, parsed.ExpiresAt)
	if err != nil || string(prologue) != "remote-davinci/pair-qr/v1\nwss://relay.example/v1\n"+pairID+"\n"+creatorSideID+"\n"+joinerSideID+"\n"+linkID+"\n300" {
		t.Fatalf("prologue = %q, error = %v", prologue, err)
	}
	hash, err := JoinTokenHash(joinToken)
	wantHash := sha256.Sum256(bytes.Repeat([]byte{1}, 32))
	if err != nil || hash != base64.RawURLEncoding.EncodeToString(wantHash[:]) {
		t.Fatalf("hash = %q, error = %v", hash, err)
	}

	for _, test := range []struct {
		name   string
		change func(map[string]any)
		code   ErrorCode
	}{
		{"unknown field", func(value map[string]any) { value["future"] = true }, InvalidMessage},
		{"insecure relay", func(value map[string]any) { value["relayUrl"] = "https://relay.example/v1" }, InvalidMessage},
		{"reused token as psk", func(value map[string]any) { value["psk"] = joinToken }, InvalidMessage},
		{"unsupported version", func(value map[string]any) { value["v"] = 2 }, UnsupportedVersion},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := make(map[string]any, len(invite))
			for key, value := range invite {
				copy[key] = value
			}
			test.change(copy)
			_, err := ParsePairingInvite(copy)
			requireCode(t, test.code, err)
		})
	}

	validHash := base64.RawURLEncoding.EncodeToString(wantHash[:])
	for _, body := range []map[string]any{{}, {"locator": "482901", "joinToken": joinToken}} {
		_, err := ParseClient(map[string]any{
			"protocol": ProtocolName, "v": 1, "type": "pair.join", "id": pairID, "body": body,
		})
		requireCode(t, InvalidMessage, err)
	}
	for messageType, body := range map[string]map[string]any{
		"pair.create": {"joinTokenHash": validHash},
		"pair.join":   {"joinToken": joinToken},
	} {
		if _, err := ParseClient(map[string]any{
			"protocol": ProtocolName, "v": 1, "type": messageType, "id": pairID, "body": body,
		}); err != nil {
			t.Fatalf("%s: %v", messageType, err)
		}
	}
	if _, err := ParseServer(map[string]any{
		"protocol": ProtocolName, "v": 1, "type": "ok", "id": pairID, "replyTo": creatorSideID,
		"body": map[string]any{"requestType": "pair.create", "result": map[string]any{
			"pairId": pairID, "sideId": creatorSideID, "expiresAt": 300,
		}},
	}); err != nil {
		t.Fatalf("token pair.create response: %v", err)
	}
}

func TestOKResponsesCorrelateRequiredResults(t *testing.T) {
	results := map[string]any{
		"system.hello":    map[string]any{"serverTime": 1786723200, "protocolVersion": 1},
		"system.ping":     map[string]any{"receivedAt": 1786723200},
		"pair.create":     map[string]any{"pairId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "sideId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "locator": "482901", "expiresAt": 1786723500},
		"pair.join":       map[string]any{"pairId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "sideId": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "expiresAt": 1786723500},
		"pair.commit":     map[string]any{"pending": true},
		"pair.cancel":     map[string]any{"cancelled": true},
		"link.get":        map[string]any{"linkId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "peerEndpointId": "22222222-2222-4222-8222-222222222222", "peerRole": "companion", "status": "active"},
		"link.revoke":     map[string]any{"revoked": true},
		"endpoint.rotate": map[string]any{"rotated": true},
		"endpoint.revoke": map[string]any{"revoked": true},
		"session.open":    map[string]any{"sessionId": "dddddddd-dddd-4ddd-8ddd-dddddddddddd"},
		"session.close":   map[string]any{"closed": true},
	}
	if len(results) != len(ClientMessageTypes)-2 {
		t.Fatalf("results cover %d of %d request types with responses", len(results), len(ClientMessageTypes)-2)
	}
	for _, requestType := range ClientMessageTypes {
		if requestType == "pair.frame" || requestType == "session.frame" {
			continue
		}
		result, expectsOK := results[requestType].(map[string]any)
		if !expectsOK {
			t.Fatalf("missing ok result for %s", requestType)
		}
		result["futureField"] = true
		_, err := ParseServer(map[string]any{
			"protocol": ProtocolName, "v": 1, "type": "ok",
			"id":      "10000000-0000-4000-8000-000000000010",
			"replyTo": "00000000-0000-4000-8000-000000000001",
			"body":    map[string]any{"requestType": requestType, "result": result},
		})
		if err != nil {
			t.Fatalf("%s: %v", requestType, err)
		}
	}
	for _, requestType := range []string{"pair.frame", "session.frame"} {
		_, err := ParseServer(map[string]any{
			"protocol": ProtocolName, "v": 1, "type": "ok",
			"id":      "10000000-0000-4000-8000-000000000010",
			"replyTo": "00000000-0000-4000-8000-000000000001",
			"body":    map[string]any{"requestType": requestType, "result": map[string]any{"delivered": true}},
		})
		requireCode(t, InvalidMessage, err)
	}
	malformed := rawObject(t, fixtures(t).Server[0])
	malformed["body"].(map[string]any)["result"] = map[string]any{}
	_, err := ParseServer(malformed)
	requireCode(t, InvalidMessage, err)
}

func TestPairingWormholeAndControlFixtures(t *testing.T) {
	values := fixtures(t)
	identity, err := ParsePairing(values.PairingIdentity)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := base64.RawURLEncoding.DecodeString(identity.Body.NoiseKey)
	if hex.EncodeToString(key) != "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" {
		t.Fatal("noise key changed")
	}
	phases := make([]string, 0, len(values.Wormhole))
	for _, frame := range values.Wormhole {
		message, err := ParseWormhole(frame)
		if err != nil {
			t.Fatal(err)
		}
		phases = append(phases, message.Phase)
	}
	if !reflect.DeepEqual(phases, []string{"pake", "version", "0"}) {
		t.Fatalf("phases = %v", phases)
	}
	controlTypes := make([]string, 0, len(values.Control))
	var hello ControlHelloBody
	var requests []string
	var response ControlSuccessBody
	var event ControlEventBody
	for _, frame := range values.Control {
		envelope, err := ParseControl(frame)
		if err != nil {
			t.Fatal(err)
		}
		switch envelope.Type {
		case "hello":
			err = envelope.DecodeBody(&hello)
		case "request":
			var request ControlRequestBody
			err = envelope.DecodeBody(&request)
			requests = append(requests, request.Operation)
		case "response":
			err = envelope.DecodeBody(&response)
		case "event":
			err = envelope.DecodeBody(&event)
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(controlTypes) == 0 || controlTypes[len(controlTypes)-1] != envelope.Type {
			controlTypes = append(controlTypes, envelope.Type)
		}
	}
	if !reflect.DeepEqual(controlTypes, ControlMessageTypes) {
		t.Fatalf("control types = %v", controlTypes)
	}
	pageOperations := []string{"resolve.page.media", "resolve.page.cut", "resolve.page.edit", "resolve.page.fusion", "resolve.page.color", "resolve.page.fairlight", "resolve.page.deliver"}
	if !reflect.DeepEqual(hello.Capabilities, pageOperations) || !reflect.DeepEqual(requests, pageOperations) {
		t.Fatalf("page capabilities = %v, requests = %v", hello.Capabilities, requests)
	}
	if result, ok := response.Result.(map[string]any); !ok || result["page"] != "color" {
		t.Fatalf("page response = %#v", response.Result)
	}
	if data, ok := event.Data.(map[string]any); !ok || event.Name != "resolve.page.changed" || data["page"] != "cut" {
		t.Fatalf("page event = %s %#v", event.Name, event.Data)
	}
	expired := rawObject(t, values.Control[1])
	body := expired["body"].(map[string]any)
	body["expiresAt"] = body["sentAt"].(float64) - 1
	_, err = ParseControl(expired)
	requireCode(t, InvalidMessage, err)
	for _, frame := range []any{
		map[string]any{"phase": "00", "body": "aa"},
		map[string]any{"phase": "0", "body": "abc"},
		map[string]any{"phase": "version", "body": strings.Repeat("00", 39)},
		map[string]any{"phase": "pake", "body": hex.EncodeToString([]byte("{}"))},
	} {
		_, err := ParseWormhole(frame)
		requireCode(t, InvalidMessage, err)
	}
	wrong := rawObject(t, values.PairingIdentity)
	wrong["body"].(map[string]any)["noiseFingerprint"] = "sha256:" + strings.Repeat("A", 43)
	_, err = ParsePairing(wrong)
	requireCode(t, InvalidMessage, err)
}

func TestAuthorizationGrammarAndSecrecy(t *testing.T) {
	values := fixtures(t)
	pairing, err := ParseAuthorization(values.Authorization.Pairing)
	if err != nil || pairing.Scheme != "pairing" {
		t.Fatalf("pairing auth = %#v, %v", pairing, err)
	}
	authorization, err := ParseAuthorization(values.Authorization.Bearer)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := base64.RawURLEncoding.DecodeString(authorization.Secret)
	digest := sha256.Sum256(secret)
	commit := rawObject(t, values.Client[4])["body"].(map[string]any)["self"].(map[string]any)
	if commit["credentialHash"] != base64.RawURLEncoding.EncodeToString(digest[:]) {
		t.Fatal("credential hash changed")
	}
	bad := values.Authorization.Bearer + "="
	_, err = ParseAuthorization(bad)
	requireCode(t, Unauthenticated, err)
	if strings.Contains(err.Error(), bad) {
		t.Fatal("authorization error echoed credential")
	}
	_, err = ParseAuthorization("Bearer rd1.11111111-1111-4111-8111-111111111111." + strings.Repeat("A", 42) + "B")
	requireCode(t, Unauthenticated, err)
}

func TestMalformedFramesAndPayloadLimits(t *testing.T) {
	values := fixtures(t)
	for _, invalid := range values.InvalidClient {
		_, err := ParseClient(invalid.Frame)
		code := InvalidMessage
		if invalid.Name == "unsupported version" {
			code = UnsupportedVersion
		}
		requireCode(t, code, err)
	}
	_, err := ParseClient("not json")
	requireCode(t, InvalidMessage, err)
	oversized := rawObject(t, values.Client[6])
	oversized["body"].(map[string]any)["payload"] = base64.RawURLEncoding.EncodeToString(make([]byte, MaxRelayPayloadBytes+1))
	_, err = ParseClient(oversized)
	requireCode(t, PayloadTooLarge, err)
	nonCanonical := rawObject(t, values.Client[6])
	nonCanonical["body"].(map[string]any)["payload"] = "AB"
	_, err = ParseClient(nonCanonical)
	requireCode(t, InvalidMessage, err)
	legacy := map[string]any{
		"protocol": ProtocolName,
		"v":        1,
		"type":     "relay.frame",
		"id":       "00000000-0000-4000-8000-000000000007",
		"body": map[string]any{
			"channel": "pair", "channelId": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			"seq": 1, "payload": "AQ",
		},
	}
	_, err = ParseClient(legacy)
	requireCode(t, InvalidMessage, err)
	metadataLeak := rawObject(t, values.Client[4])
	metadataLeak["body"].(map[string]any)["peer"].(map[string]any)["noiseKey"] = strings.Repeat("A", 43)
	_, err = ParseClient(metadataLeak)
	requireCode(t, InvalidMessage, err)
	sameRole := rawObject(t, values.Client[4])
	commitBody := sameRole["body"].(map[string]any)
	commitBody["peer"].(map[string]any)["role"] = commitBody["self"].(map[string]any)["role"]
	_, err = ParseRendezvous(sameRole)
	requireCode(t, InvalidMessage, err)
	milliseconds := rawObject(t, values.Client[1])
	milliseconds["body"].(map[string]any)["sentAt"] = 1786723200000
	_, err = ParseClient(milliseconds)
	requireCode(t, InvalidMessage, err)
	huge := rawObject(t, values.Control[len(values.Control)-1])
	huge["body"].(map[string]any)["data"] = strings.Repeat("x", MaxControlPlaintextBytes)
	_, err = ParseControl(huge)
	requireCode(t, PayloadTooLarge, err)
}

func TestNoisePrologue(t *testing.T) {
	prologue, err := SessionNoisePrologue(
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"dddddddd-dddd-4ddd-8ddd-dddddddddddd",
	)
	if err != nil {
		t.Fatal(err)
	}
	want := "remote-davinci/session/v1\ncccccccc-cccc-4ccc-8ccc-cccccccccccc\ndddddddd-dddd-4ddd-8ddd-dddddddddddd"
	if string(prologue) != want {
		t.Fatalf("prologue = %q", prologue)
	}
	_, err = SessionNoisePrologue("not-a-link", "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
	requireCode(t, InvalidMessage, err)
}

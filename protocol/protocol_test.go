package protocol

import (
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
}

func TestSchemaValidIntegerSpellings(t *testing.T) {
	for _, spelling := range []string{"1.0", "1e0"} {
		clientJSON := strings.ReplaceAll(`{"protocol":"remote-davinci.rendezvous","v":NUMBER,"type":"relay.frame","id":"00000000-0000-4000-8000-000000000007","body":{"channel":"pair","channelId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa","seq":NUMBER,"payload":"AQ"}}`, "NUMBER", spelling)
		client, err := ParseClient(clientJSON)
		if err != nil {
			t.Fatalf("%s client: %v", spelling, err)
		}
		var frame RelayFrameBody
		if err := client.DecodeBody(&frame); err != nil || client.V != 1 || frame.Seq != 1 {
			t.Fatalf("%s client = %#v, body = %#v, error = %v", spelling, client, frame, err)
		}

		controlJSON := strings.ReplaceAll(`{"protocol":"remote-davinci.control","v":NUMBER,"type":"request","id":"20000000-0000-4000-8000-000000000002","body":{"operation":"resolve.transport.play","args":{},"sentAt":NUMBER,"expiresAt":NUMBER}}`, "NUMBER", spelling)
		control, err := ParseControl(controlJSON)
		if err != nil || control.V != 1 {
			t.Fatalf("%s control = %#v, error = %v", spelling, control, err)
		}
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
		"relay.frame":     map[string]any{"delivered": true},
		"link.get":        map[string]any{"linkId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc", "peerEndpointId": "22222222-2222-4222-8222-222222222222", "peerRole": "companion", "status": "active"},
		"link.revoke":     map[string]any{"revoked": true},
		"endpoint.rotate": map[string]any{"rotated": true},
		"endpoint.revoke": map[string]any{"revoked": true, "linksRevoked": 1},
		"session.open":    map[string]any{"sessionId": "dddddddd-dddd-4ddd-8ddd-dddddddddddd"},
		"session.close":   map[string]any{"closed": true},
	}
	if len(results) != len(ClientMessageTypes) {
		t.Fatalf("results cover %d of %d request types", len(results), len(ClientMessageTypes))
	}
	for _, requestType := range ClientMessageTypes {
		result := results[requestType].(map[string]any)
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
	for _, frame := range values.Control {
		envelope, err := ParseControl(frame)
		if err != nil {
			t.Fatal(err)
		}
		controlTypes = append(controlTypes, envelope.Type)
	}
	if !reflect.DeepEqual(controlTypes, ControlMessageTypes) {
		t.Fatalf("control types = %v", controlTypes)
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
	huge := rawObject(t, values.Control[3])
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

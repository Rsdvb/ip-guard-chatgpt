package main

import (
	"encoding/json"
	"testing"
)

func TestIndependentPolicyAndInputBoundary(t *testing.T) {
	p := Policy{Format: 1, UID: 1000, Targets: []Target{
		{ID: "00000000-0000-4000-8000-000000000001", Service: "claude", Executable: "/opt/Claude/claude", Allowed: true, KeepRunning: true},
		{ID: "00000000-0000-4000-8000-000000000002", Service: "chatgpt", Executable: "/opt/ChatGPT/chatgpt", Allowed: false, KeepRunning: true},
	}}
	data, _ := json.Marshal(Request{Action: "policy", Policy: &p})
	r, err := decodeRequest(data, 1000)
	if err != nil || !r.Policy.Targets[0].Allowed || r.Policy.Targets[1].Allowed {
		t.Fatal("independent policies lost", err)
	}
	if _, err := decodeRequest(data, 1001); err == nil {
		t.Fatal("another user's policy accepted")
	}
	for _, bad := range []string{`{"action":"status","shell":"rm"}`, `{"action":"stop"}`, `{"action":"stop","service":"both"}`, `{"action":"disable"} {"action":"status"}`} {
		if _, err := decodeRequest([]byte(bad), 1000); err == nil {
			t.Fatal("invalid command accepted", bad)
		}
	}
	if _, err := decodeRequest([]byte(`{"action":"stop","id":"00000000-0000-4000-8000-000000000001","service":"chatgpt"}`), 1000); err == nil {
		t.Fatal("ambiguous stop scope accepted")
	}
	p.Targets[1].Executable = p.Targets[0].Executable
	if validatePolicy(p, 1000) == nil {
		t.Fatal("same executable authorized by two services")
	}
}

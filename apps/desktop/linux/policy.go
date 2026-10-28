package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
)

type Target struct {
	ID          string  `json:"id"`
	Service     string  `json:"service"`
	Executable  string  `json:"executable"`
	BundleRoot  *string `json:"bundleRoot"`
	Allowed     bool    `json:"allowed"`
	KeepRunning bool    `json:"keepRunning"`
}
type Policy struct {
	Format  int      `json:"format"`
	UID     uint32   `json:"uid"`
	Targets []Target `json:"targets"`
}
type Request struct {
	Action   string  `json:"action"`
	Policy   *Policy `json:"policy,omitempty"`
	Service  string  `json:"service,omitempty"`
	ID       string  `json:"id,omitempty"`
	Sequence uint64  `json:"sequence,omitempty"`
}

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func decodeRequest(data []byte, uid uint32) (Request, error) {
	var r Request
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if len(data) > 524288 {
		return r, errors.New("policy exceeds 512 KiB")
	}
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	var extra interface{}
	if d.Decode(&extra) != io.EOF {
		return r, errors.New("unexpected trailing JSON")
	}
	switch r.Action {
	case "status", "disable":
		if r.Policy != nil || r.Service != "" || r.ID != "" {
			return r, errors.New("unexpected command fields")
		}
	case "stop":
		if r.Policy != nil || (r.ID != "" && (r.Service != "" || !uuid.MatchString(r.ID))) || (r.ID == "" && r.Service != "claude" && r.Service != "chatgpt") {
			return r, errors.New("invalid stop scope")
		}
	case "policy":
		if r.Policy == nil || r.Service != "" || r.ID != "" {
			return r, errors.New("missing policy")
		}
		if err := validatePolicy(*r.Policy, uid); err != nil {
			return r, err
		}
	default:
		return r, errors.New("unknown command")
	}
	return r, nil
}
func validatePolicy(p Policy, uid uint32) error {
	if p.Format != 1 || p.UID != uid || uid < 1000 || len(p.Targets) > 256 {
		return errors.New("invalid user or format")
	}
	ids := map[string]bool{}
	paths := map[string]bool{}
	for _, t := range p.Targets {
		if !uuid.MatchString(t.ID) || ids[t.ID] || paths[t.Executable] || (t.Service != "claude" && t.Service != "chatgpt") {
			return errors.New("invalid or duplicate target")
		}
		if len(t.Executable) > 4096 || !path.IsAbs(t.Executable) || path.Clean(t.Executable) != t.Executable || strings.ContainsAny(t.Executable, "\x00\r\n") {
			return errors.New("invalid executable path")
		}
		if t.BundleRoot != nil || t.Allowed && !t.KeepRunning {
			return errors.New("invalid target policy")
		}
		ids[t.ID] = true
		paths[t.Executable] = true
	}
	return nil
}

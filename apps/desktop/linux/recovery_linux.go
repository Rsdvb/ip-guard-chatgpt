package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func recoverUser(uid uint32) error {
	root := fmt.Sprintf("/sys/fs/bpf/ip_guard/%d", uid)
	entries, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, entry := range entries {
		if !uuid.MatchString(entry.Name()) || !entry.IsDir() {
			return errors.New("unexpected entry in IP Guard BPF directory")
		}
		pins := filepath.Join(root, entry.Name())
		groupPath := fmt.Sprintf("/sys/fs/cgroup/ipguard-%d/%s", uid, entry.Name())
		if err = os.WriteFile(filepath.Join(groupPath, "cgroup.kill"), []byte("1"), 0600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, name := range []string{"ingress", "egress"} {
			attached, err := link.LoadPinnedLink(filepath.Join(pins, name), nil)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			err = attached.Unpin()
			attached.Close()
			if err != nil {
				return err
			}
		}
		policy, err := ebpf.LoadPinnedMap(filepath.Join(pins, "policy"), nil)
		if err == nil {
			err = policy.Unpin()
			policy.Close()
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err = os.Remove(pins); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		_ = os.Remove(groupPath)
	}
	_ = os.Remove(root)
	_ = os.Remove(fmt.Sprintf("/sys/fs/cgroup/ipguard-%d", uid))
	if data, err := os.ReadFile(policyFile(uid)); err == nil {
		var saved diskState
		if json.Unmarshal(data, &saved) == nil {
			saved.Enabled = false
			if err = saveState(policyFile(uid), saved); err != nil {
				return err
			}
		}
	}
	return nil
}
func recoverAll() error {
	users := map[uint32]bool{}
	for _, directory := range []string{"/var/lib/ipguard", "/sys/fs/bpf/ip_guard"} {
		entries, err := os.ReadDir(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			value, err := strconv.ParseUint(strings.TrimSuffix(entry.Name(), ".json"), 10, 32)
			if err == nil && value >= 1000 {
				users[uint32(value)] = true
			}
		}
	}
	for uid := range users {
		unit := fmt.Sprintf("ipguard@%d.service", uid)
		result, err := exec.Command("/usr/bin/systemctl", "disable", "--now", unit).CombinedOutput()
		if err != nil {
			return fmt.Errorf("stop %s: %s: %w", unit, result, err)
		}
		if err = recoverUser(uid); err != nil {
			return err
		}
	}
	return nil
}

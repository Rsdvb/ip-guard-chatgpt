package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type diskState struct {
	Enabled bool   `json:"enabled"`
	Policy  Policy `json:"policy"`
}
type Running struct {
	ID      string `json:"id"`
	Service string `json:"service"`
	PID     int    `json:"pid"`
}
type Response struct {
	Phase   string    `json:"phase"`
	Message string    `json:"message"`
	Running []Running `json:"running"`
}
type engine struct {
	mu         sync.Mutex
	uid        uint32
	file       string
	enabled    bool
	policy     Policy
	groups     map[string]*group
	marked     map[string]string
	fan        int
	lastLease  uint64
	expired    bool
	controller bool
	bindings   []byte
	closed     chan struct{}
}

func binding(p Policy) Policy {
	p.Targets = append([]Target{}, p.Targets...)
	for i := range p.Targets {
		p.Targets[i].Allowed = false
		p.Targets[i].KeepRunning = false
	}
	return p
}
func saveState(file string, s diskState) error {
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err = os.WriteFile(file+".tmp", data, 0600); err != nil {
		return err
	}
	return os.Rename(file+".tmp", file)
}
func newEngine(uid uint32, file string) (*engine, error) {
	e := &engine{uid: uid, file: file, policy: Policy{Format: 1, UID: uid, Targets: []Target{}}, groups: map[string]*group{}, marked: map[string]string{}, fan: -1, closed: make(chan struct{})}
	data, err := os.ReadFile(file)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		var saved diskState
		if err = json.Unmarshal(data, &saved); err != nil {
			return nil, err
		}
		if err = validatePolicy(saved.Policy, uid); err != nil {
			return nil, err
		}
		if saved.Enabled {
			if err = e.configure(saved.Policy, false); err != nil {
				e.close(false)
				return nil, err
			}
			e.lastLease = bootTime()
		}
	}
	go e.events()
	go func() {
		timer := time.NewTicker(500 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				e.expire()
			case <-e.closed:
				return
			}
		}
	}()
	return e, nil
}
func validateExecutable(t Target, uid uint32) error {
	real, err := filepath.EvalSymlinks(t.Executable)
	if err != nil {
		return err
	}
	info, err := os.Stat(real)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("ordinary executable required")
	}
	var st unix.Stat_t
	if err = unix.Stat(real, &st); err != nil {
		return err
	}
	if st.Uid != 0 && st.Uid != uid {
		return errors.New("executable belongs to another user")
	}
	own, err := os.Executable()
	if err != nil {
		return err
	}
	if real == own || strings.HasPrefix(real, "/usr/lib/ipguard/") || strings.HasPrefix(real, "/usr/lib/systemd/") {
		return errors.New("system controller cannot be protected")
	}
	switch filepath.Base(real) {
	case "bash", "sh", "dash", "sudo", "su", "pkexec", "systemd", "systemctl", "login", "sshd", "ip-guard":
		return errors.New("system and recovery tools cannot be protected")
	}
	return nil
}

// The caller holds mu. Changes are denied first and persisted before any grant is published.
func (e *engine) configure(p Policy, save bool) error {
	if err := validatePolicy(p, e.uid); err != nil {
		return err
	}
	bound := binding(p)
	data, _ := json.Marshal(bound)
	changed := !bytes.Equal(data, e.bindings)
	if changed {
		for _, t := range p.Targets {
			if err := validateExecutable(t, e.uid); err != nil {
				return fmt.Errorf("%s: %w", t.Executable, err)
			}
		}
		if err := ensureBPFFS(); err != nil {
			return fmt.Errorf("BPF filesystem: %w", err)
		}
		if e.fan < 0 {
			fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_LARGEFILE|unix.O_CLOEXEC)
			if err != nil {
				return fmt.Errorf("fanotify exec permissions: %w", err)
			}
			e.fan = fd
		}
		wanted := map[string]bool{}
		directories := map[string]string{}
		for _, t := range p.Targets {
			wanted[t.ID] = true
			for _, name := range []string{t.Executable, filepath.Dir(t.Executable)} {
				var st unix.Stat_t
				if err := unix.Stat(name, &st); err != nil {
					return err
				}
				directories[strconv.FormatUint(uint64(st.Dev), 10)] = name
			}
			if e.groups[t.ID] == nil {
				g, err := newGroup(e.uid, t.ID)
				if err != nil {
					return err
				}
				e.groups[t.ID] = g
			}
		}
		for device, directory := range directories {
			if _, ok := e.marked[device]; ok {
				e.marked[device] = directory
				continue
			}
			if err := unix.FanotifyMark(e.fan, unix.FAN_MARK_ADD|unix.FAN_MARK_FILESYSTEM, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, directory); err != nil {
				return err
			}
			e.marked[device] = directory
		}
		if save {
			if err := saveState(e.file, diskState{Enabled: true, Policy: bound}); err != nil {
				return err
			}
		}
		for id, g := range e.groups {
			if !wanted[id] {
				g.close(true)
				delete(e.groups, id)
			}
		}
		for device, directory := range e.marked {
			if _, ok := directories[device]; !ok {
				_ = unix.FanotifyMark(e.fan, unix.FAN_MARK_REMOVE|unix.FAN_MARK_FILESYSTEM, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, directory)
				delete(e.marked, device)
			}
		}
		e.policy = bound
		e.bindings = data
		e.enabled = true
		if err := e.adopt(); err != nil {
			return err
		}
	}
	deadline := bootTime() + uint64(3500*time.Millisecond)
	for _, t := range p.Targets {
		if err := e.groups[t.ID].update(t.Allowed, deadline); err != nil {
			return err
		}
		if !t.KeepRunning && save {
			if err := e.groups[t.ID].kill(); err != nil {
				return err
			}
		}
	}
	e.policy = p
	e.enabled = true
	e.lastLease = bootTime()
	e.expired = false
	return nil
}
func (e *engine) adopt() error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	processes := map[int]process{}
	selected := map[int]string{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid < 2 {
			continue
		}
		p, err := readProcess(pid)
		if err != nil || p.uid != e.uid {
			continue
		}
		processes[pid] = p
		for _, t := range e.policy.Targets {
			real, _ := filepath.EvalSymlinks(t.Executable)
			if p.executable == real {
				selected[pid] = t.ID
			}
		}
	}
	// A socket keeps its creation cgroup when its process moves. Existing external instances
	// must therefore close before activation; moving them would leave old connections unfiltered.
	for pid := range selected {
		id := selected[pid]
		data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		expected := strings.TrimPrefix(e.groups[id].path, "/sys/fs/cgroup")
		if !strings.Contains(string(data), "0::"+expected+"\n") {
			return errors.New("请先关闭已有受保护程序，再开启系统防护；已有套接字不能安全接管")
		}
	}
	for pid := range processes {
		cursor := pid
		seen := map[int]bool{}
		for cursor > 1 && !seen[cursor] {
			seen[cursor] = true
			if id, ok := selected[cursor]; ok {
				if err := e.groups[id].enroll(pid, e.uid); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.ESRCH) {
					return err
				}
				break
			}
			p, ok := processes[cursor]
			if !ok {
				break
			}
			cursor = p.parent
		}
	}
	return nil
}
func (e *engine) expire() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.enabled || e.expired || bootTime()-e.lastLease <= uint64(3500*time.Millisecond) {
		return
	}
	e.expired = true
	for _, g := range e.groups {
		_ = g.update(false, 0)
		if err := g.kill(); err != nil {
			log.Print("expired protected cgroup: ", err)
		}
	}
}
func (e *engine) response() Response {
	r := Response{Phase: "disabled", Message: "系统防护未启用", Running: []Running{}}
	if e.enabled {
		r.Phase = "enabled"
		r.Message = "系统启动拦截和内核网络过滤已就绪"
		if e.expired {
			r.Phase = "error"
			r.Message = "策略通道已失联，已登记程序保持阻断"
		}
		for _, t := range e.policy.Targets {
			if g := e.groups[t.ID]; g != nil {
				for _, pid := range g.pids() {
					r.Running = append(r.Running, Running{ID: t.ID, Service: t.Service, PID: pid})
				}
			}
		}
	}
	return r
}
func (e *engine) request(r Request) (Response, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch r.Action {
	case "policy":
		if err := e.configure(*r.Policy, true); err != nil {
			e.deny()
			return e.response(), err
		}
	case "disable":
		if err := saveState(e.file, diskState{Enabled: false, Policy: binding(e.policy)}); err != nil {
			return e.response(), err
		}
		e.detach()
	case "stop":
		for _, t := range e.policy.Targets {
			if t.ID == r.ID || r.ID == "" && t.Service == r.Service {
				if err := e.groups[t.ID].kill(); err != nil {
					return e.response(), err
				}
			}
		}
	}
	return e.response(), nil
}
func (e *engine) deny() {
	e.expired = true
	for _, g := range e.groups {
		_ = g.update(false, 0)
		_ = g.kill()
	}
}
func (e *engine) detach() {
	e.enabled = false
	if e.fan >= 0 {
		_ = unix.Close(e.fan)
		e.fan = -1
	}
	for _, g := range e.groups {
		g.close(true)
	}
	e.groups = map[string]*group{}
	e.marked = map[string]string{}
	e.bindings = nil
}
func (e *engine) close(detach bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	select {
	case <-e.closed:
		return
	default:
		close(e.closed)
	}
	if detach {
		e.detach()
	} else {
		e.deny()
		if e.fan >= 0 {
			_ = unix.Close(e.fan)
			e.fan = -1
		}
		for _, g := range e.groups {
			g.close(false)
		}
	}
}
func (e *engine) permission(fd, pid int) uint32 {
	if !e.enabled {
		return unix.FAN_ALLOW
	}
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return unix.FAN_DENY
	}
	var target *Target
	for i := range e.policy.Targets {
		var selected unix.Stat_t
		if unix.Stat(e.policy.Targets[i].Executable, &selected) == nil && selected.Dev == opened.Dev && selected.Ino == opened.Ino {
			target = &e.policy.Targets[i]
			break
		}
	}
	if target == nil {
		return unix.FAN_ALLOW
	}
	p, err := readProcess(pid)
	if err != nil {
		return unix.FAN_DENY
	}
	if p.uid != e.uid {
		return unix.FAN_ALLOW
	}
	if e.expired || !target.Allowed || bootTime()-e.lastLease > uint64(3500*time.Millisecond) {
		return unix.FAN_DENY
	}
	if err = e.groups[target.ID].enroll(pid, e.uid); err != nil {
		log.Print("exec cgroup enrollment: ", err)
		return unix.FAN_DENY
	}
	return unix.FAN_ALLOW
}
func (e *engine) events() {
	data := make([]byte, 65536)
	for {
		select {
		case <-e.closed:
			return
		default:
		}
		e.mu.Lock()
		fd := e.fan
		e.mu.Unlock()
		if fd < 0 {
			select {
			case <-time.After(500 * time.Millisecond):
			case <-e.closed:
				return
			}
			continue
		}
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(poll, 500); err != nil {
			if err != unix.EINTR {
				log.Print("fanotify poll: ", err)
			}
			continue
		}
		e.mu.Lock()
		if e.fan != fd {
			e.mu.Unlock()
			continue
		}
		n, err := unix.Read(fd, data)
		if err != nil {
			e.mu.Unlock()
			if err != unix.EAGAIN && err != unix.EINTR {
				log.Print("fanotify read: ", err)
			}
			continue
		}
		input := data[:n]
		for len(input) > 0 {
			mask, eventFD, pid, size, err := readEvent(input)
			if err != nil {
				e.deny()
				log.Print(err)
				break
			}
			input = input[size:]
			if mask&unix.FAN_Q_OVERFLOW != 0 {
				e.deny()
				log.Print("fanotify event overflow; policy revoked")
			}
			if eventFD < 0 {
				continue
			}
			if mask&unix.FAN_OPEN_EXEC_PERM != 0 {
				response := make([]byte, 8)
				binary.NativeEndian.PutUint32(response, uint32(eventFD))
				binary.NativeEndian.PutUint32(response[4:], e.permission(eventFD, pid))
				if _, err = unix.Write(fd, response); err != nil && err != io.EOF {
					e.deny()
					log.Print("fanotify response: ", err)
				}
			}
			_ = unix.Close(eventFD)
		}
		e.mu.Unlock()
	}
}

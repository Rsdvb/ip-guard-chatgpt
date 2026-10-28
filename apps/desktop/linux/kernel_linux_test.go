package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestNetworkFixture(t *testing.T) {
	if os.Getenv("IP_GUARD_NETWORK_FIXTURE") != "1" {
		t.Skip("child application entry")
	}
	var connection net.Conn
	for {
		if connection == nil {
			var err error
			connection, err = net.DialTimeout("tcp4", os.Getenv("IP_GUARD_FIXTURE_ENDPOINT"), 200*time.Millisecond)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		_ = connection.SetDeadline(time.Now().Add(300 * time.Millisecond))
		_, err := fmt.Fprintln(connection, os.Getenv("IP_GUARD_FIXTURE_NAME"))
		var ack [1]byte
		if err == nil {
			_, err = connection.Read(ack[:])
		}
		if err != nil {
			connection.Close()
			connection = nil
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func TestKernelLaunchAndNetworkIsolation(t *testing.T) {
	if os.Getenv("IP_GUARD_KERNEL_TEST") != "1" {
		t.Skip("real privileged kernel test runs only in the isolated Ubuntu VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel test requires root")
	}
	uid64, err := strconv.ParseUint(os.Getenv("IP_GUARD_TEST_UID"), 10, 32)
	if err != nil || uid64 < 1000 {
		t.Fatal("invalid fixture UID")
	}
	gid64, err := strconv.ParseUint(os.Getenv("IP_GUARD_TEST_GID"), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(uid64)
	root := t.TempDir()
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	// Go's test temp parent is private too; selected fixtures must be executable by the ordinary test user.
	if err = os.Chmod(filepath.Dir(root), 0755); err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"claude", "chatgpt", "outside"} {
		if err = os.WriteFile(filepath.Join(root, name), image, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"claude", "chatgpt"} {
		if err = os.Symlink(filepath.Join(root, name), filepath.Join(root, name+"-alias")); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var countsMu sync.Mutex
	counts := map[string]int{}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				scanner := bufio.NewScanner(connection)
				for scanner.Scan() {
					name := scanner.Text()
					countsMu.Lock()
					counts[name]++
					countsMu.Unlock()
					_, _ = connection.Write([]byte{1})
				}
			}()
		}
	}()
	count := func(name string) int { countsMu.Lock(); defer countsMu.Unlock(); return counts[name] }
	until := func(check func() bool, why string) {
		t.Helper()
		deadline := time.Now().Add(12 * time.Second)
		for time.Now().Before(deadline) {
			if check() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal(why)
	}
	e, err := newEngine(uid, filepath.Join(root, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.close(true)
	policy := Policy{Format: 1, UID: uid, Targets: []Target{
		{ID: "00000000-0000-4000-8000-000000000071", Service: "claude", Executable: filepath.Join(root, "claude-alias"), Allowed: true, KeepRunning: true},
		{ID: "00000000-0000-4000-8000-000000000072", Service: "chatgpt", Executable: filepath.Join(root, "chatgpt-alias"), Allowed: true, KeepRunning: true},
	}}
	var policyMu sync.Mutex
	publish := func() error {
		policyMu.Lock()
		p := policy
		p.Targets = append([]Target{}, policy.Targets...)
		policyMu.Unlock()
		_, err := e.request(Request{Action: "policy", Policy: &p})
		return err
	}
	if err = publish(); err != nil {
		t.Fatal(err)
	}
	leaseStop := make(chan struct{})
	defer func() {
		select {
		case <-leaseStop:
		default:
			close(leaseStop)
		}
	}()
	go func() {
		timer := time.NewTicker(500 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				if err := publish(); err != nil {
					t.Error(err)
					return
				}
			case <-leaseStop:
				return
			}
		}
	}()
	start := func(name string) (*exec.Cmd, error) {
		command := exec.Command(filepath.Join(root, name), "-test.run=^TestNetworkFixture$")
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uint32(gid64)}}
		command.Env = append(os.Environ(), "IP_GUARD_NETWORK_FIXTURE=1", "IP_GUARD_FIXTURE_ENDPOINT="+listener.Addr().String(), "IP_GUARD_FIXTURE_NAME="+name)
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		return command, command.Start()
	}
	var children []*exec.Cmd
	defer func() {
		for _, command := range children {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	for _, name := range []string{"claude", "chatgpt", "outside"} {
		command, err := start(name)
		if err != nil {
			t.Fatal(err)
		}
		children = append(children, command)
	}
	until(func() bool { return count("claude") > 5 && count("chatgpt") > 5 && count("outside") > 5 }, "original executable launches must be enrolled and pass traffic")
	policyMu.Lock()
	policy.Targets[1].Allowed = false
	policyMu.Unlock()
	if err = publish(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	gptBefore, claudeBefore, outsideBefore := count("chatgpt"), count("claude"), count("outside")
	time.Sleep(900 * time.Millisecond)
	if count("chatgpt") != gptBefore {
		t.Fatal("revoked ChatGPT existing socket still sent data")
	}
	if count("claude") <= claudeBefore || count("outside") <= outsideBefore {
		t.Fatal("ChatGPT block affected another service or unrelated process")
	}
	if err = children[1].Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("keep-running policy must retain the blocked process")
	}
	denied, err := start("chatgpt")
	if err == nil {
		children = append(children, denied)
		t.Fatal("an original shortcut bypassed exec permission denial")
	}
	policyMu.Lock()
	policy.Targets[1].KeepRunning = false
	policyMu.Unlock()
	if err = publish(); err != nil {
		t.Fatal(err)
	}
	until(func() bool { return len(e.groups[policy.Targets[1].ID].pids()) == 0 }, "stop preference must terminate the selected kernel cgroup")
	close(leaseStop)
	until(func() bool { return len(e.groups[policy.Targets[0].ID].pids()) == 0 }, "loss of the GUI lease must terminate protected processes")
	if err = children[2].Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("lease loss terminated the unrelated process")
	}
	t.Log("PASS real fanotify exec permission, cgroup BPF existing-socket revoke, independent services, keep-running preference, scoped kill and guardian-loss fail closed")
}

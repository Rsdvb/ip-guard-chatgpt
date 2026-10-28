package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var buildVersion = "development"

func policyFile(uid uint32) string { return fmt.Sprintf("/var/lib/ipguard/%d.json", uid) }
func socketPath(uid uint32) string { return fmt.Sprintf("/run/ipguard/%d.sock", uid) }
func rootDirectory(directory string, mode os.FileMode) error {
	if err := os.MkdirAll(directory, mode); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if err = unix.Lstat(directory, &st); err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("unsafe system directory: " + directory)
	}
	return nil
}
func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var readErr error
	err = raw.Control(func(fd uintptr) { cred, readErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil {
		return 0, err
	}
	if readErr != nil {
		return 0, readErr
	}
	return cred.Uid, nil
}
func serve(e *engine, listener *net.UnixListener) error {
	var connections atomic.Int32
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			return err
		}
		uid, err := peerUID(connection)
		if err != nil || uid != e.uid || connections.Add(1) > 16 {
			connection.Close()
			if err == nil && uid == e.uid {
				connections.Add(-1)
			}
			continue
		}
		go func() {
			defer connections.Add(-1)
			defer connection.Close()
			scanner := bufio.NewScanner(connection)
			scanner.Buffer(make([]byte, 4096), 524288)
			encoder := json.NewEncoder(connection)
			owned := false
			var sequence uint64
			defer func() {
				if owned {
					e.mu.Lock()
					e.lastLease = 0
					e.controller = false
					e.mu.Unlock()
					e.expire()
				}
			}()
			for {
				_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
				if !scanner.Scan() {
					return
				}
				request, err := decodeRequest(scanner.Bytes(), e.uid)
				if err != nil {
					_ = encoder.Encode(Response{Phase: "error", Message: err.Error(), Running: []Running{}})
					return
				}
				if request.Action == "policy" {
					if request.Sequence == 0 || request.Sequence <= sequence {
						_ = encoder.Encode(Response{Phase: "error", Message: "策略版本无效或重复", Running: []Running{}})
						return
					}
					sequence = request.Sequence
					e.mu.Lock()
					if !owned && e.controller {
						e.mu.Unlock()
						_ = encoder.Encode(Response{Phase: "error", Message: "已有策略通道，请先退出旧版 IP Guard", Running: []Running{}})
						return
					}
					if !owned {
						e.controller = true
						owned = true
					}
					e.mu.Unlock()
				}
				response, err := e.request(request)
				response.Sequence = request.Sequence
				if err != nil {
					response.Phase = "error"
					response.Message = err.Error()
				}
				_ = connection.SetWriteDeadline(time.Now().Add(3 * time.Second))
				if err = encoder.Encode(response); err != nil {
					return
				}
			}
		}()
	}
}
func runDaemon(uid uint32) error {
	if err := rootDirectory("/run/ipguard", 0755); err != nil {
		return err
	}
	if err := rootDirectory("/var/lib/ipguard", 0700); err != nil {
		return err
	}
	endpoint := socketPath(uid)
	if info, err := os.Lstat(endpoint); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("system socket path is occupied")
		}
		old, dialErr := net.DialTimeout("unix", endpoint, 500*time.Millisecond)
		if dialErr == nil {
			old.Close()
			return errors.New("system guardian is already running")
		}
		if err = os.Remove(endpoint); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	e, err := newEngine(uid, policyFile(uid))
	if err != nil {
		return err
	}
	defer e.close(false)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(endpoint)
	if err = os.Chown(endpoint, int(uid), -1); err != nil {
		return err
	}
	if err = os.Chmod(endpoint, 0600); err != nil {
		return err
	}
	if notify := os.Getenv("NOTIFY_SOCKET"); notify != "" {
		conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: notify, Net: "unixgram"})
		if err != nil {
			return err
		}
		_, err = conn.Write([]byte("READY=1"))
		conn.Close()
		if err != nil {
			return err
		}
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-signals; e.mu.Lock(); e.detach(); e.mu.Unlock(); listener.Close() }()
	return serve(e, listener)
}
func enable(uid uint32) error {
	requester, err := strconv.ParseUint(os.Getenv("PKEXEC_UID"), 10, 32)
	if err != nil || uint32(requester) != uid {
		return errors.New("start the system guardian through the signed-in user's authorization dialog")
	}
	own, err := os.Executable()
	if err != nil {
		return err
	}
	own, err = filepath.EvalSymlinks(own)
	if err != nil || own != "/usr/lib/ipguard/ipguard-system" {
		return errors.New("install the DEB before enabling system protection")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 524289))
	if err != nil {
		return err
	}
	request, err := decodeRequest(data, uid)
	if err != nil {
		return err
	}
	if request.Action != "policy" {
		return errors.New("initial policy required")
	}
	for _, t := range request.Policy.Targets {
		if err = validateExecutable(t, uid); err != nil {
			return err
		}
	}
	if err = rootDirectory("/var/lib/ipguard", 0700); err != nil {
		return err
	}
	if err = ensureBPFFS(); err != nil {
		return err
	}
	if err = saveState(policyFile(uid), diskState{Enabled: true, Policy: binding(*request.Policy)}); err != nil {
		return err
	}
	command := exec.Command("/usr/bin/systemctl", "enable", "--now", fmt.Sprintf("ipguard@%d.service", uid))
	result, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("system service: %s: %w", result, err)
	}
	return json.NewEncoder(os.Stdout).Encode(Response{Phase: "enabled", Message: "系统组件已启动，等待策略确认", Running: []Running{}, Active: true, Version: buildVersion})
}
func main() {
	if os.Geteuid() != 0 {
		log.Fatal("system helper requires system authorization; run the GUI as an ordinary user")
	}
	if len(os.Args) == 2 && os.Args[1] == "recover-all" {
		if err := recoverAll(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) != 3 {
		log.Fatal("usage: ipguard-system daemon|enable UID")
	}
	id, err := strconv.ParseUint(os.Args[2], 10, 32)
	if err != nil || id < 1000 {
		log.Fatal("invalid desktop user UID")
	}
	switch os.Args[1] {
	case "daemon":
		err = runDaemon(uint32(id))
	case "enable":
		err = enable(uint32(id))
	case "recover":
		err = recoverUser(uint32(id))
	default:
		err = errors.New("unknown system operation")
	}
	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Fatal(err)
	}
}

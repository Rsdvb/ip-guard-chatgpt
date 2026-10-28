package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type lease struct {
	Deadline uint64
	Allowed  uint32
	Pad      uint32
}
type group struct {
	path   string
	pins   string
	policy *ebpf.Map
	links  []link.Link
}

func bootTime() uint64 {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &value); err != nil {
		panic(err)
	}
	return uint64(value.Nano())
}
func ensureBPFFS() error {
	var info unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &info); err != nil {
		return err
	}
	if info.Type == unix.BPF_FS_MAGIC {
		return nil
	}
	return unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, "")
}
func newGroup(uid uint32, id string) (*group, error) {
	if !uuid.MatchString(id) {
		return nil, errors.New("invalid cgroup ID")
	}
	g := &group{path: fmt.Sprintf("/sys/fs/cgroup/ipguard-%d/%s", uid, id), pins: fmt.Sprintf("/sys/fs/bpf/ip_guard/%d/%s", uid, id)}
	if err := os.MkdirAll(g.path, 0700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(g.pins, 0700); err != nil {
		return nil, err
	}
	var err error
	g.policy, err = ebpf.LoadPinnedMap(filepath.Join(g.pins, "policy"), nil)
	if errors.Is(err, os.ErrNotExist) {
		g.policy, err = ebpf.NewMap(&ebpf.MapSpec{Name: "ipguard_lease", Type: ebpf.Array, KeySize: 4, ValueSize: 16, MaxEntries: 1})
		if err == nil {
			err = g.policy.Pin(filepath.Join(g.pins, "policy"))
		}
	}
	if err != nil {
		return nil, err
	}
	if err = g.update(false, 0); err != nil {
		g.policy.Close()
		return nil, err
	}
	for _, entry := range []struct {
		name   string
		attach ebpf.AttachType
	}{{"egress", ebpf.AttachCGroupInetEgress}, {"ingress", ebpf.AttachCGroupInetIngress}} {
		pinned := filepath.Join(g.pins, entry.name)
		existing, loadErr := link.LoadPinnedLink(pinned, nil)
		if loadErr == nil {
			g.links = append(g.links, existing)
			continue
		}
		if !errors.Is(loadErr, os.ErrNotExist) {
			g.close(false)
			return nil, loadErr
		}
		program, programErr := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "ipguard_filter", Type: ebpf.CGroupSKB, AttachType: entry.attach, License: "GPL", Instructions: asm.Instructions{
			asm.StoreImm(asm.RFP, -4, 0, asm.Word), asm.LoadMapPtr(asm.R1, g.policy.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -4), asm.FnMapLookupElem.Call(),
			asm.JEq.Imm(asm.R0, 0, "deny"), asm.Mov.Reg(asm.R6, asm.R0),
			asm.LoadMem(asm.R7, asm.R6, 0, asm.DWord), asm.LoadMem(asm.R8, asm.R6, 8, asm.Word),
			asm.JEq.Imm(asm.R8, 0, "deny"), asm.FnKtimeGetBootNs.Call(), asm.JGT.Reg(asm.R0, asm.R7, "deny"),
			asm.Mov.Imm(asm.R0, 1), asm.Return(), asm.Mov.Imm(asm.R0, 0).WithSymbol("deny"), asm.Return(),
		}})
		if programErr != nil {
			g.close(false)
			return nil, programErr
		}
		attached, attachErr := link.AttachCgroup(link.CgroupOptions{Path: g.path, Attach: entry.attach, Program: program})
		program.Close()
		if attachErr != nil {
			g.close(false)
			return nil, attachErr
		}
		if pinErr := attached.Pin(pinned); pinErr != nil {
			attached.Close()
			g.close(false)
			return nil, pinErr
		}
		g.links = append(g.links, attached)
	}
	return g, nil
}
func (g *group) update(allowed bool, deadline uint64) error {
	var value uint32
	if allowed {
		value = 1
	}
	return g.policy.Put(uint32(0), lease{Deadline: deadline, Allowed: value})
}
func (g *group) pids() []int {
	data, err := os.ReadFile(filepath.Join(g.path, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var ids []int
	for _, field := range strings.Fields(string(data)) {
		if id, err := strconv.Atoi(field); err == nil && id > 1 {
			ids = append(ids, id)
		}
	}
	return ids
}
func (g *group) kill() error {
	return os.WriteFile(filepath.Join(g.path, "cgroup.kill"), []byte("1"), 0600)
}
func (g *group) close(detach bool) {
	for _, attached := range g.links {
		if detach {
			_ = attached.Unpin()
		}
		_ = attached.Close()
	}
	if g.policy != nil {
		if detach {
			_ = g.policy.Unpin()
		}
		_ = g.policy.Close()
	}
	if detach {
		_ = os.Remove(g.pins)
		_ = os.Remove(g.path)
	}
}

type process struct {
	pid, parent int
	uid         uint32
	executable  string
}

func readProcess(pid int) (process, error) {
	var p process
	p.pid = pid
	root := "/proc/" + strconv.Itoa(pid)
	data, err := os.ReadFile(root + "/status")
	if err != nil {
		return p, err
	}
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line)
			if len(f) != 5 {
				return p, errors.New("invalid UID record")
			}
			id, e := strconv.ParseUint(f[2], 10, 32)
			if e != nil {
				return p, e
			}
			p.uid = uint32(id)
			found = true
		}
		if strings.HasPrefix(line, "PPid:") {
			f := strings.Fields(line)
			if len(f) != 2 {
				return p, errors.New("invalid parent record")
			}
			p.parent, err = strconv.Atoi(f[1])
			if err != nil {
				return p, err
			}
		}
	}
	if !found {
		return p, errors.New("UID unavailable")
	}
	p.executable, err = os.Readlink(root + "/exe")
	p.executable = strings.TrimSuffix(p.executable, " (deleted)")
	return p, err
}
func (g *group) enroll(pid int, uid uint32) error {
	p, err := readProcess(pid)
	if err != nil {
		return err
	}
	if p.uid != uid {
		return errors.New("another user's process")
	}
	return os.WriteFile(filepath.Join(g.path, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0600)
}
func readEvent(data []byte) (uint64, int, int, int, error) {
	if len(data) < 24 {
		return 0, 0, 0, 0, errors.New("truncated fanotify metadata")
	}
	size := int(binary.NativeEndian.Uint32(data[0:4]))
	version := data[4]
	if version != unix.FANOTIFY_METADATA_VERSION || size < 24 || size > len(data) {
		return 0, 0, 0, 0, errors.New("invalid fanotify metadata")
	}
	return binary.NativeEndian.Uint64(data[8:16]), int(int32(binary.NativeEndian.Uint32(data[16:20]))), int(int32(binary.NativeEndian.Uint32(data[20:24]))), size, nil
}

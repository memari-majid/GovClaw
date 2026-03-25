package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	PIDFileName = "gateway.pid"
	LogFileName = "gateway.log"
	EnvDaemon   = "DEFENSECLAW_DAEMON"
)

var (
	ErrAlreadyRunning = errors.New("daemon is already running")
	ErrNotRunning     = errors.New("daemon is not running")
	ErrStopTimeout    = errors.New("daemon did not stop within timeout")
)

type Daemon struct {
	dataDir string
	pidFile string
	logFile string
}

func New(dataDir string) *Daemon {
	return &Daemon{
		dataDir: dataDir,
		pidFile: filepath.Join(dataDir, PIDFileName),
		logFile: filepath.Join(dataDir, LogFileName),
	}
}

func (d *Daemon) PIDFile() string { return d.pidFile }
func (d *Daemon) LogFile() string { return d.logFile }

type pidInfo struct {
	PID        int    `json:"pid"`
	Executable string `json:"executable"`
	StartTime  int64  `json:"start_time"`
}

func (d *Daemon) IsRunning() (bool, int) {
	info, err := d.readPIDInfo()
	if err != nil {
		return false, 0
	}
	if !processExists(info.PID) {
		_ = os.Remove(d.pidFile)
		return false, 0
	}
	if !d.verifyProcess(info) {
		_ = os.Remove(d.pidFile)
		return false, 0
	}
	return true, info.PID
}

func (d *Daemon) verifyProcess(info pidInfo) bool {
	switch runtime.GOOS {
	case "linux":
		return d.verifyProcessLinux(info)
	case "darwin":
		return d.verifyProcessDarwin(info)
	default:
		return true
	}
}

func (d *Daemon) verifyProcessLinux(info pidInfo) bool {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", info.PID))
	if err != nil {
		return true
	}
	if info.Executable != "" && exePath != info.Executable {
		return false
	}
	return true
}

func (d *Daemon) verifyProcessDarwin(info pidInfo) bool {
	comm, err := processExecutableDarwin(info.PID)
	if err != nil {
		// Match the Linux behavior: if process metadata is unavailable in the
		// current environment, fall back to the liveness check done by IsRunning.
		return processExists(info.PID)
	}
	if info.Executable != "" {
		exeBase := filepath.Base(info.Executable)
		if !strings.HasSuffix(comm, exeBase) && comm != exeBase {
			return false
		}
	}
	return true
}

func processExecutableDarwin(pid int) (string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return "", err
	}
	comm := strings.TrimSpace(string(out))
	if comm == "" {
		return "", fmt.Errorf("daemon: ps returned empty command for pid %d", pid)
	}
	return comm, nil
}

func (d *Daemon) Start(args []string) (int, error) {
	if running, pid := d.IsRunning(); running {
		return pid, ErrAlreadyRunning
	}

	if err := os.MkdirAll(d.dataDir, 0755); err != nil {
		return 0, fmt.Errorf("daemon: create data dir: %w", err)
	}

	logFile, err := os.OpenFile(d.logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return 0, fmt.Errorf("daemon: open log file: %w", err)
	}

	executable, err := os.Executable()
	if err != nil {
		logFile.Close()
		return 0, fmt.Errorf("daemon: get executable: %w", err)
	}

	// Open /dev/null for stdin
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		logFile.Close()
		return 0, fmt.Errorf("daemon: open /dev/null: %w", err)
	}

	cmd := exec.Command(executable, args...)
	cmd.Env = append(os.Environ(), EnvDaemon+"=1")
	cmd.Stdin = devNull
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = d.dataDir

	// Detach from parent process group
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if err := cmd.Start(); err != nil {
		devNull.Close()
		logFile.Close()
		return 0, fmt.Errorf("daemon: start process: %w", err)
	}

	pid := cmd.Process.Pid

	if err := d.writePIDInfo(pid, executable); err != nil {
		_ = cmd.Process.Kill()
		devNull.Close()
		logFile.Close()
		return 0, fmt.Errorf("daemon: write pid: %w", err)
	}

	// Don't wait for the child — we detached it
	go func() {
		_ = cmd.Wait()
		devNull.Close()
		logFile.Close()
	}()

	// Give the child a moment to start and verify it's running
	time.Sleep(100 * time.Millisecond)
	if !processExists(pid) {
		_ = os.Remove(d.pidFile)
		return 0, fmt.Errorf("daemon: process exited immediately (check %s for errors)", d.logFile)
	}

	return pid, nil
}

func (d *Daemon) Stop(timeout time.Duration) error {
	running, pid := d.IsRunning()
	if !running {
		return ErrNotRunning
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("daemon: find process %d: %w", pid, err)
	}

	// Send SIGTERM for graceful shutdown
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		if errors.Is(err, os.ErrProcessDone) {
			_ = os.Remove(d.pidFile)
			return nil
		}
		return fmt.Errorf("daemon: send SIGTERM: %w", err)
	}

	// Wait for process to exit
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processExists(pid) {
			_ = os.Remove(d.pidFile)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Force kill if still running
	_ = proc.Signal(syscall.SIGKILL)
	time.Sleep(100 * time.Millisecond)

	if processExists(pid) {
		return ErrStopTimeout
	}

	_ = os.Remove(d.pidFile)
	return nil
}

func (d *Daemon) Restart(args []string, timeout time.Duration) (int, error) {
	if running, _ := d.IsRunning(); running {
		if err := d.Stop(timeout); err != nil && !errors.Is(err, ErrNotRunning) {
			return 0, fmt.Errorf("daemon: stop for restart: %w", err)
		}
	}
	return d.Start(args)
}

func (d *Daemon) readPIDInfo() (pidInfo, error) {
	data, err := os.ReadFile(d.pidFile)
	if err != nil {
		return pidInfo{}, err
	}

	var info pidInfo
	if err := json.Unmarshal(data, &info); err != nil {
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(data)))
		if parseErr != nil || pid <= 0 {
			return pidInfo{}, fmt.Errorf("daemon: pid file is neither JSON nor a valid PID number: %w", err)
		}
		return pidInfo{PID: pid}, nil
	}
	return info, nil
}

func (d *Daemon) writePIDInfo(pid int, executable string) error {
	info := pidInfo{
		PID:        pid,
		Executable: executable,
		StartTime:  time.Now().Unix(),
	}
	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	return os.WriteFile(d.pidFile, data, 0644)
}

func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Send signal 0 to check if alive.
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}

func IsDaemonChild() bool {
	return os.Getenv(EnvDaemon) == "1"
}

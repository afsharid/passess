package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const execValue = "passess-fake-exec-0123456789abcdef"

var binary string // passess built once for tests that need a real process

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "passess-cli-test")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "passess")
	build := exec.Command("go", "build", "-o", binary, "github.com/afsharid/passess/cmd/passess")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// setup writes a user config and points passess at it. X may go to sh; Y has
// no allow list.
func setup(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	body := `version = 1
[secrets.X]
ref   = "env://PASSESS_TEST_X_TOKEN"
allow = ["sh"]
[secrets.Y]
ref = "env://PASSESS_TEST_Y_TOKEN"
`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PASSESS_CONFIG", cfg)
	t.Setenv("PASSESS_TEST_X_TOKEN", execValue)
	t.Setenv("PASSESS_TEST_Y_TOKEN", execValue+"-y")
	t.Setenv("UNRELATED_API_KEY", "passess-fake-unrelated-0123456789")
	t.Chdir(dir) // keep any real passess.toml out of the way
}

func run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb bytes.Buffer
	code = Main(args, strings.NewReader(""), &out, &errb)
	return out.String(), errb.String(), code
}

func TestExecRedactsWhatTheChildPrints(t *testing.T) {
	setup(t)
	out, errOut, code := run(t, "exec", "-s", "X", "--", "sh", "-c", `echo "value=$X"; printf %s "$X" | base64; echo "done"`)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	if !strings.Contains(out, "value=[REDACTED:X]") || !strings.Contains(out, "done") {
		t.Fatalf("stdout = %q", out)
	}
	if strings.Contains(out, execValue) || strings.Contains(out, base64.StdEncoding.EncodeToString([]byte(execValue))[:20]) {
		t.Fatalf("value leaked: %q", out)
	}
}

func TestExecRefusesShellWithoutAllow(t *testing.T) {
	setup(t)
	out, errOut, code := run(t, "exec", "-s", "Y", "--", "sh", "-c", "echo $Y")
	if code != ExitNoPerm {
		t.Fatalf("exit %d, want %d", code, ExitNoPerm)
	}
	if out != "" {
		t.Fatalf("the command must not run, stdout %q", out)
	}
	for _, want := range []string{"refusing to give Y", "curl --variable %Y", `add "sh" to secrets.Y.allow`} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("stderr lacks %q:\n%s", want, errOut)
		}
	}
}

func TestExecEnvironmentHygiene(t *testing.T) {
	setup(t)
	out, errOut, code := run(t, "exec", "-s", "X", "-s", "ALIAS=X", "--", "sh", "-c", "env")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
	for _, gone := range []string{"PASSESS_TEST_X_TOKEN=", "PASSESS_TEST_Y_TOKEN=", "UNRELATED_API_KEY=", "\nY="} {
		if strings.Contains(out, gone) {
			t.Fatalf("child environment still has %q", gone)
		}
	}
	for _, want := range []string{"X=[REDACTED:X]", "ALIAS=[REDACTED:X]", "PATH="} {
		if !strings.Contains(out, want) {
			t.Fatalf("child environment lacks %q", want)
		}
	}
}

func TestExecExitStatusAndErrors(t *testing.T) {
	setup(t)
	if _, _, code := run(t, "exec", "-s", "X", "--", "sh", "-c", "exit 3"); code != 3 {
		t.Fatalf("exit %d, want 3", code)
	}
	if _, _, code := run(t, "exec", "-s", "X", "--", "no-such-command-passess"); code != ExitNotFound {
		t.Fatalf("missing command: exit %d", code)
	}
	if _, errOut, code := run(t, "exec", "-s", "NOPE", "--", "ls"); code != ExitConfig || !strings.Contains(errOut, "[secrets.NOPE]") {
		t.Fatalf("undefined secret: exit %d, %q", code, errOut)
	}
	if _, _, code := run(t, "exec", "--", "ls"); code != ExitUsage {
		t.Fatalf("no -s: exit %d", code)
	}
}

// startPassess runs the real binary with a long-running child and returns it
// together with the child's pid.
func startPassess(t *testing.T, args ...string) (*exec.Cmd, int) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Env = os.Environ()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	for range 100 {
		out, _ := exec.Command("pgrep", "-P", strconv.Itoa(cmd.Process.Pid)).Output()
		if pid, err := strconv.Atoi(strings.TrimSpace(string(out))); err == nil {
			return cmd, pid
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("child never started; passess stderr: %q", stderr.String())
	return nil, 0
}

func exitCode(t *testing.T, cmd *exec.Cmd) int {
	t.Helper()
	err := cmd.Wait()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func TestExecSignals(t *testing.T) {
	setup(t)

	cmd, child := startPassess(t, "exec", "-s", "Y", "--", "sleep", "30")
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	if code := exitCode(t, cmd); code != 130 {
		t.Fatalf("SIGINT: passess exited %d, want 130", code)
	}
	time.Sleep(50 * time.Millisecond)
	if alive(child) {
		t.Fatal("SIGINT: the child survived")
	}

	cmd, child = startPassess(t, "exec", "-s", "Y", "--", "sleep", "30")
	if err := syscall.Kill(child, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if code := exitCode(t, cmd); code != 137 {
		t.Fatalf("SIGKILL of the child: passess exited %d, want 137", code)
	}
}

func TestExecValueNotInArgv(t *testing.T) {
	setup(t)
	cmd, child := startPassess(t, "exec", "-s", "Y", "--", "sleep", "30")
	for _, pid := range []int{cmd.Process.Pid, child} {
		out, err := exec.Command("ps", "-o", "args=", "-p", strconv.Itoa(pid)).Output()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), execValue) {
			t.Fatalf("pid %d shows the value in its arguments", pid)
		}
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	_ = cmd.Wait()
}

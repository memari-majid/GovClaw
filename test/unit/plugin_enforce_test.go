package unit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

func TestPluginEnforcerQuarantineAndRestore(t *testing.T) {
	tmpDir := t.TempDir()
	quarantineDir := filepath.Join(tmpDir, "quarantine")
	pluginDir := filepath.Join(tmpDir, "test-plugin")

	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.py"), []byte("# plugin code"), 0o644); err != nil {
		t.Fatal(err)
	}

	shell := sandbox.New("nonexistent-openshell", filepath.Join(tmpDir, "policies"))
	pe := enforce.NewPluginEnforcer(quarantineDir, shell)

	dest, err := pe.Quarantine(pluginDir)
	if err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	if _, err := os.Stat(pluginDir); !os.IsNotExist(err) {
		t.Fatal("expected original plugin directory to be removed after quarantine")
	}

	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("expected quarantine destination to exist: %v", err)
	}

	if !pe.IsQuarantined("test-plugin") {
		t.Fatal("expected IsQuarantined to return true")
	}

	if err := pe.Restore("test-plugin", pluginDir); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	restoredFile := filepath.Join(pluginDir, "plugin.py")
	data, err := os.ReadFile(restoredFile)
	if err != nil {
		t.Fatalf("expected restored file: %v", err)
	}
	if string(data) != "# plugin code" {
		t.Fatalf("restored content mismatch: %q", string(data))
	}

	if pe.IsQuarantined("test-plugin") {
		t.Fatal("expected IsQuarantined to return false after restore")
	}
}

func TestPluginPolicyEngineBlockAndCheck(t *testing.T) {
	store := newTestStore(t)
	pe := enforce.NewPolicyEngine(store)

	blocked, err := pe.IsBlocked("plugin", "test-plugin")
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if blocked {
		t.Fatal("expected not blocked before adding")
	}

	if err := pe.Block("plugin", "test-plugin", "malicious permissions"); err != nil {
		t.Fatalf("Block: %v", err)
	}

	blocked, err = pe.IsBlocked("plugin", "test-plugin")
	if err != nil {
		t.Fatalf("IsBlocked: %v", err)
	}
	if !blocked {
		t.Fatal("expected blocked after adding")
	}

	// Plugin block should not affect skills
	skillBlocked, err := pe.IsBlocked("skill", "test-plugin")
	if err != nil {
		t.Fatalf("IsBlocked skill: %v", err)
	}
	if skillBlocked {
		t.Fatal("plugin block should not affect skill with same name")
	}
}

func TestPluginPolicyEngineQuarantine(t *testing.T) {
	store := newTestStore(t)
	pe := enforce.NewPolicyEngine(store)

	if err := pe.Quarantine("plugin", "bad-plugin", "critical findings"); err != nil {
		t.Fatalf("Quarantine: %v", err)
	}

	quarantined, err := pe.IsQuarantined("plugin", "bad-plugin")
	if err != nil {
		t.Fatalf("IsQuarantined: %v", err)
	}
	if !quarantined {
		t.Fatal("expected quarantined after setting")
	}

	if err := pe.ClearQuarantine("plugin", "bad-plugin"); err != nil {
		t.Fatalf("ClearQuarantine: %v", err)
	}

	quarantined, err = pe.IsQuarantined("plugin", "bad-plugin")
	if err != nil {
		t.Fatalf("IsQuarantined: %v", err)
	}
	if quarantined {
		t.Fatal("expected not quarantined after clearing")
	}
}

func TestListBlockedIncludesPlugins(t *testing.T) {
	store := newTestStore(t)
	pe := enforce.NewPolicyEngine(store)

	_ = pe.Block("skill", "bad-skill", "reason 1")
	_ = pe.Block("mcp", "https://bad.example.com", "reason 2")
	_ = pe.Block("plugin", "bad-plugin", "reason 3")

	blocked, err := pe.ListBlocked()
	if err != nil {
		t.Fatalf("ListBlocked: %v", err)
	}
	if len(blocked) != 3 {
		t.Fatalf("expected 3 blocked (skill+mcp+plugin), got %d", len(blocked))
	}

	byType, err := pe.ListByType("plugin")
	if err != nil {
		t.Fatalf("ListByType: %v", err)
	}
	if len(byType) != 1 {
		t.Fatalf("expected 1 plugin entry, got %d", len(byType))
	}
	if byType[0].TargetName != "bad-plugin" {
		t.Fatalf("expected bad-plugin, got %s", byType[0].TargetName)
	}
}

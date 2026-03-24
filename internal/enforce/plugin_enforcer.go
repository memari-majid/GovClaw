package enforce

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

type PluginEnforcer struct {
	quarantineDir string
	shell         *sandbox.OpenShell
}

func NewPluginEnforcer(quarantineDir string, shell *sandbox.OpenShell) *PluginEnforcer {
	return &PluginEnforcer{quarantineDir: quarantineDir, shell: shell}
}

func (e *PluginEnforcer) Quarantine(pluginPath string) (string, error) {
	info, err := os.Stat(pluginPath)
	if err != nil {
		return "", fmt.Errorf("enforce: plugin path %q: %w", pluginPath, err)
	}

	name := filepath.Base(pluginPath)
	dest := filepath.Join(e.quarantineDir, "plugins", name)

	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return "", fmt.Errorf("enforce: create quarantine dir: %w", err)
	}

	if info.IsDir() {
		if err := copyDir(pluginPath, dest); err != nil {
			return "", fmt.Errorf("enforce: copy plugin to quarantine: %w", err)
		}
		if err := os.RemoveAll(pluginPath); err != nil {
			return dest, fmt.Errorf("enforce: remove original plugin: %w", err)
		}
	} else {
		if err := copyFile(pluginPath, dest); err != nil {
			return "", fmt.Errorf("enforce: copy plugin to quarantine: %w", err)
		}
		if err := os.Remove(pluginPath); err != nil {
			return dest, fmt.Errorf("enforce: remove original plugin: %w", err)
		}
	}

	return dest, nil
}

func (e *PluginEnforcer) Restore(pluginName, originalPath string) error {
	base := filepath.Base(pluginName)
	src := filepath.Join(e.quarantineDir, "plugins", base)
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("enforce: quarantined plugin %q not found: %w", base, err)
	}

	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("enforce: stat quarantined plugin: %w", err)
	}

	if info.IsDir() {
		if err := copyDir(src, originalPath); err != nil {
			return fmt.Errorf("enforce: restore plugin: %w", err)
		}
		return os.RemoveAll(src)
	}

	if err := copyFile(src, originalPath); err != nil {
		return fmt.Errorf("enforce: restore plugin: %w", err)
	}
	return os.Remove(src)
}

func (e *PluginEnforcer) IsQuarantined(pluginName string) bool {
	base := filepath.Base(pluginName)
	path := filepath.Join(e.quarantineDir, "plugins", base)
	_, err := os.Stat(path)
	return err == nil
}

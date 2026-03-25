package telemetry

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"runtime"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func buildResource(cfg *config.Config, version string) *resource.Resource {
	hostname, _ := os.Hostname()

	attrs := []attribute.KeyValue{
		attribute.String("service.name", "defenseclaw"),
		attribute.String("service.version", version),
		attribute.String("service.namespace", "ai-governance"),
		attribute.String("deployment.environment", cfg.Environment),
		attribute.String("host.name", hostname),
		attribute.String("host.arch", runtime.GOARCH),
		attribute.String("os.type", runtime.GOOS),
		attribute.String("defenseclaw.claw.mode", string(cfg.Claw.Mode)),
		attribute.String("defenseclaw.claw.home_dir", cfg.Claw.HomeDir),
		attribute.String("defenseclaw.gateway.host", cfg.Gateway.Host),
		attribute.Int("defenseclaw.gateway.port", cfg.Gateway.Port),
		attribute.String("defenseclaw.instance.id", uuid.New().String()),
	}

	if cfg.Gateway.DeviceKeyFile != "" {
		if fp := deviceFingerprint(cfg.Gateway.DeviceKeyFile); fp != "" {
			attrs = append(attrs, attribute.String("defenseclaw.device.id", fp))
		}
	}

	for k, v := range cfg.OTel.Resource.Attributes {
		attrs = append(attrs, attribute.String(k, v))
	}

	r, _ := resource.New(
		context.Background(),
		resource.WithAttributes(attrs...),
	)
	return r
}

// deviceFingerprint derives the public-key fingerprint from the Ed25519
// device key file, matching the DeviceID produced by gateway/device.go.
// This avoids hashing secret material and ensures the telemetry resource
// attribute matches the identity used on the wire.
func deviceFingerprint(keyFile string) string {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	seed := block.Bytes
	if len(seed) != ed25519.SeedSize {
		return ""
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type ClawMode string

const (
	ClawOpenClaw ClawMode = "openclaw"
	// Future: ClawNemoClaw, ClawOpenCode, ClawClaudeCode
)

type ClawConfig struct {
	Mode       ClawMode `mapstructure:"mode"        yaml:"mode"`
	HomeDir    string   `mapstructure:"home_dir"    yaml:"home_dir"`
	ConfigFile string   `mapstructure:"config_file" yaml:"config_file"`
}

type Config struct {
	DataDir       string             `mapstructure:"data_dir"       yaml:"data_dir"`
	AuditDB       string             `mapstructure:"audit_db"       yaml:"audit_db"`
	QuarantineDir string             `mapstructure:"quarantine_dir" yaml:"quarantine_dir"`
	PluginDir     string             `mapstructure:"plugin_dir"     yaml:"plugin_dir"`
	PolicyDir     string             `mapstructure:"policy_dir"     yaml:"policy_dir"`
	Environment   string             `mapstructure:"environment"    yaml:"environment"`
	Claw          ClawConfig         `mapstructure:"claw"           yaml:"claw"`
	Scanners      ScannersConfig     `mapstructure:"scanners"       yaml:"scanners"`
	OpenShell     OpenShellConfig    `mapstructure:"openshell"      yaml:"openshell"`
	Watch         WatchConfig        `mapstructure:"watch"          yaml:"watch"`
	Firewall      FirewallConfig     `mapstructure:"firewall"       yaml:"firewall"`
	Guardrail     GuardrailConfig    `mapstructure:"guardrail"      yaml:"guardrail"`
	Splunk        SplunkConfig       `mapstructure:"splunk"         yaml:"splunk"`
	Gateway       GatewayConfig      `mapstructure:"gateway"        yaml:"gateway"`
	SkillActions  SkillActionsConfig `mapstructure:"skill_actions"  yaml:"skill_actions"`
	OTel          OTelConfig         `mapstructure:"otel"           yaml:"otel"`
}

type OTelConfig struct {
	Enabled  bool              `mapstructure:"enabled"  yaml:"enabled"`
	Protocol string            `mapstructure:"protocol" yaml:"protocol"`
	Endpoint string            `mapstructure:"endpoint" yaml:"endpoint"`
	Headers  map[string]string `mapstructure:"headers"  yaml:"headers"`
	TLS      OTelTLSConfig     `mapstructure:"tls"      yaml:"tls"`
	Traces   OTelTracesConfig  `mapstructure:"traces"   yaml:"traces"`
	Logs     OTelLogsConfig    `mapstructure:"logs"     yaml:"logs"`
	Metrics  OTelMetricsConfig `mapstructure:"metrics"  yaml:"metrics"`
	Batch    OTelBatchConfig   `mapstructure:"batch"    yaml:"batch"`
	Resource OTelResourceConfig `mapstructure:"resource" yaml:"resource"`
}

type OTelTLSConfig struct {
	Insecure bool   `mapstructure:"insecure" yaml:"insecure"`
	CACert   string `mapstructure:"ca_cert"  yaml:"ca_cert"`
}

type OTelTracesConfig struct {
	Enabled    bool   `mapstructure:"enabled"     yaml:"enabled"`
	Sampler    string `mapstructure:"sampler"      yaml:"sampler"`
	SamplerArg string `mapstructure:"sampler_arg"  yaml:"sampler_arg"`
}

type OTelLogsConfig struct {
	Enabled                bool `mapstructure:"enabled"                  yaml:"enabled"`
	EmitIndividualFindings bool `mapstructure:"emit_individual_findings" yaml:"emit_individual_findings"`
}

type OTelMetricsConfig struct {
	Enabled         bool `mapstructure:"enabled"            yaml:"enabled"`
	ExportIntervalS int  `mapstructure:"export_interval_s"  yaml:"export_interval_s"`
}

type OTelBatchConfig struct {
	MaxExportBatchSize int `mapstructure:"max_export_batch_size" yaml:"max_export_batch_size"`
	ScheduledDelayMs   int `mapstructure:"scheduled_delay_ms"    yaml:"scheduled_delay_ms"`
	MaxQueueSize       int `mapstructure:"max_queue_size"         yaml:"max_queue_size"`
}

type OTelResourceConfig struct {
	Attributes map[string]string `mapstructure:"attributes" yaml:"attributes"`
}

type FirewallConfig struct {
	ConfigFile string `mapstructure:"config_file" yaml:"config_file"`
	RulesFile  string `mapstructure:"rules_file"  yaml:"rules_file"`
	AnchorName string `mapstructure:"anchor_name" yaml:"anchor_name"`
}

type SplunkConfig struct {
	HECEndpoint   string `mapstructure:"hec_endpoint"    yaml:"hec_endpoint"`
	HECToken      string `mapstructure:"hec_token"       yaml:"hec_token"`
	Index         string `mapstructure:"index"            yaml:"index"`
	Source        string `mapstructure:"source"           yaml:"source"`
	SourceType    string `mapstructure:"sourcetype"       yaml:"sourcetype"`
	VerifyTLS     bool   `mapstructure:"verify_tls"       yaml:"verify_tls"`
	Enabled       bool   `mapstructure:"enabled"          yaml:"enabled"`
	BatchSize     int    `mapstructure:"batch_size"       yaml:"batch_size"`
	FlushInterval int    `mapstructure:"flush_interval_s" yaml:"flush_interval_s"`
}

type WatchConfig struct {
	DebounceMs         int  `mapstructure:"debounce_ms"          yaml:"debounce_ms"`
	AutoBlock          bool `mapstructure:"auto_block"           yaml:"auto_block"`
	AllowListBypassScan bool `mapstructure:"allow_list_bypass_scan" yaml:"allow_list_bypass_scan"`
}

type SkillScannerConfig struct {
	Binary         string `mapstructure:"binary"             yaml:"binary"`
	UseLLM         bool   `mapstructure:"use_llm"            yaml:"use_llm"`
	UseBehavioral  bool   `mapstructure:"use_behavioral"     yaml:"use_behavioral"`
	EnableMeta     bool   `mapstructure:"enable_meta"        yaml:"enable_meta"`
	UseTrigger     bool   `mapstructure:"use_trigger"        yaml:"use_trigger"`
	UseVirusTotal  bool   `mapstructure:"use_virustotal"     yaml:"use_virustotal"`
	UseAIDefense   bool   `mapstructure:"use_aidefense"      yaml:"use_aidefense"`
	LLMProvider    string `mapstructure:"llm_provider"       yaml:"llm_provider"`
	LLMModel       string `mapstructure:"llm_model"          yaml:"llm_model"`
	LLMConsensus   int    `mapstructure:"llm_consensus_runs" yaml:"llm_consensus_runs"`
	Policy         string `mapstructure:"policy"             yaml:"policy"`
	Lenient        bool   `mapstructure:"lenient"            yaml:"lenient"`
	LLMAPIKey      string `mapstructure:"llm_api_key"        yaml:"llm_api_key"`
	VirusTotalKey  string `mapstructure:"virustotal_api_key" yaml:"virustotal_api_key"`
	AIDefenseKey   string `mapstructure:"aidefense_api_key"  yaml:"aidefense_api_key"`
}

type ScannersConfig struct {
	SkillScanner  SkillScannerConfig `mapstructure:"skill_scanner"  yaml:"skill_scanner"`
	MCPScanner    string             `mapstructure:"mcp_scanner"    yaml:"mcp_scanner"`
	PluginScanner string             `mapstructure:"plugin_scanner" yaml:"plugin_scanner"`
	AIBOM         string             `mapstructure:"aibom"           yaml:"aibom"`
	CodeGuard     string             `mapstructure:"codeguard"       yaml:"codeguard"`
}

type OpenShellConfig struct {
	Binary    string `mapstructure:"binary"     yaml:"binary"`
	PolicyDir string `mapstructure:"policy_dir" yaml:"policy_dir"`
}

type GatewayWatcherSkillConfig struct {
	Enabled    bool     `mapstructure:"enabled"      yaml:"enabled"`
	TakeAction bool     `mapstructure:"take_action"   yaml:"take_action"`
	Dirs       []string `mapstructure:"dirs"           yaml:"dirs"`
}

type GatewayWatcherConfig struct {
	Enabled bool                      `mapstructure:"enabled" yaml:"enabled"`
	Skill   GatewayWatcherSkillConfig `mapstructure:"skill"   yaml:"skill"`
}

type CiscoAIDefenseConfig struct {
	Endpoint     string   `mapstructure:"endpoint"       yaml:"endpoint"`
	APIKeyEnv    string   `mapstructure:"api_key_env"    yaml:"api_key_env"`
	TimeoutMs    int      `mapstructure:"timeout_ms"     yaml:"timeout_ms"`
	EnabledRules []string `mapstructure:"enabled_rules"  yaml:"enabled_rules"`
}

type GuardrailConfig struct {
	Enabled        bool                 `mapstructure:"enabled"          yaml:"enabled"`
	Mode           string               `mapstructure:"mode"             yaml:"mode"`
	ScannerMode    string               `mapstructure:"scanner_mode"     yaml:"scanner_mode"`
	Port           int                  `mapstructure:"port"             yaml:"port"`
	Model          string               `mapstructure:"model"            yaml:"model"`
	ModelName      string               `mapstructure:"model_name"       yaml:"model_name"`
	APIKeyEnv      string               `mapstructure:"api_key_env"      yaml:"api_key_env"`
	GuardrailDir   string               `mapstructure:"guardrail_dir"    yaml:"guardrail_dir"`
	LiteLLMConfig  string               `mapstructure:"litellm_config"   yaml:"litellm_config"`
	OriginalModel  string               `mapstructure:"original_model"   yaml:"original_model"`
	CiscoAIDefense CiscoAIDefenseConfig `mapstructure:"cisco_ai_defense" yaml:"cisco_ai_defense"`
}

type GatewayConfig struct {
	Host            string               `mapstructure:"host"              yaml:"host"`
	Port            int                  `mapstructure:"port"              yaml:"port"`
	Token           string               `mapstructure:"token"             yaml:"token"`
	DeviceKeyFile   string               `mapstructure:"device_key_file"   yaml:"device_key_file"`
	AutoApprove     bool                 `mapstructure:"auto_approve_safe" yaml:"auto_approve_safe"`
	ReconnectMs     int                  `mapstructure:"reconnect_ms"      yaml:"reconnect_ms"`
	MaxReconnectMs  int                  `mapstructure:"max_reconnect_ms"  yaml:"max_reconnect_ms"`
	ApprovalTimeout int                  `mapstructure:"approval_timeout_s" yaml:"approval_timeout_s"`
	APIPort         int                  `mapstructure:"api_port"           yaml:"api_port"`
	Watcher         GatewayWatcherConfig `mapstructure:"watcher"            yaml:"watcher"`
}

type RuntimeAction string

const (
	RuntimeDisable RuntimeAction = "disable"
	RuntimeEnable  RuntimeAction = "enable"
)

type FileAction string

const (
	FileActionNone       FileAction = "none"
	FileActionQuarantine FileAction = "quarantine"
)

type InstallAction string

const (
	InstallBlock InstallAction = "block"
	InstallAllow InstallAction = "allow"
	InstallNone  InstallAction = "none"
)

type SeverityAction struct {
	File    FileAction    `mapstructure:"file"    yaml:"file"`
	Runtime RuntimeAction `mapstructure:"runtime" yaml:"runtime"`
	Install InstallAction `mapstructure:"install" yaml:"install"`
}

type SkillActionsConfig struct {
	Critical SeverityAction `mapstructure:"critical" yaml:"critical"`
	High     SeverityAction `mapstructure:"high"     yaml:"high"`
	Medium   SeverityAction `mapstructure:"medium"   yaml:"medium"`
	Low      SeverityAction `mapstructure:"low"      yaml:"low"`
	Info     SeverityAction `mapstructure:"info"     yaml:"info"`
}

func Load() (*Config, error) {
	dataDir := DefaultDataPath()
	configFile := filepath.Join(dataDir, DefaultConfigName)

	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	setDefaults(dataDir)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("config: read %s: %w", configFile, err)
			}
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	if err := cfg.SkillActions.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Save() error {
	configFile := filepath.Join(c.DataDir, DefaultConfigName)

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}

	return os.WriteFile(configFile, data, 0o600)
}

func setDefaults(dataDir string) {
	viper.SetDefault("data_dir", dataDir)
	viper.SetDefault("audit_db", filepath.Join(dataDir, DefaultAuditDBName))
	viper.SetDefault("quarantine_dir", filepath.Join(dataDir, "quarantine"))
	viper.SetDefault("plugin_dir", filepath.Join(dataDir, "plugins"))
	viper.SetDefault("policy_dir", filepath.Join(dataDir, "policies"))
	viper.SetDefault("environment", string(DetectEnvironment()))
	viper.SetDefault("claw.mode", string(ClawOpenClaw))
	viper.SetDefault("claw.home_dir", "~/.openclaw")
	viper.SetDefault("claw.config_file", "~/.openclaw/openclaw.json")

	viper.SetDefault("scanners.skill_scanner.binary", "skill-scanner")
	viper.SetDefault("scanners.skill_scanner.use_llm", false)
	viper.SetDefault("scanners.skill_scanner.use_behavioral", false)
	viper.SetDefault("scanners.skill_scanner.enable_meta", false)
	viper.SetDefault("scanners.skill_scanner.use_trigger", false)
	viper.SetDefault("scanners.skill_scanner.use_virustotal", false)
	viper.SetDefault("scanners.skill_scanner.use_aidefense", false)
	viper.SetDefault("scanners.skill_scanner.llm_provider", "")
	viper.SetDefault("scanners.skill_scanner.llm_model", "")
	viper.SetDefault("scanners.skill_scanner.llm_consensus_runs", 0)
	viper.SetDefault("scanners.skill_scanner.policy", "")
	viper.SetDefault("scanners.skill_scanner.lenient", false)
	viper.SetDefault("scanners.skill_scanner.llm_api_key", "")
	viper.SetDefault("scanners.skill_scanner.virustotal_api_key", "")
	viper.SetDefault("scanners.skill_scanner.aidefense_api_key", "")
	viper.SetDefault("scanners.mcp_scanner", "mcp-scanner")
	viper.SetDefault("scanners.plugin_scanner", "defenseclaw-plugin-scanner")
	viper.SetDefault("scanners.aibom", "cisco-aibom")
	viper.SetDefault("scanners.codeguard", filepath.Join(dataDir, "codeguard-rules"))
	viper.SetDefault("openshell.binary", "openshell")
	viper.SetDefault("openshell.policy_dir", "/etc/openshell/policies")

	viper.SetDefault("watch.debounce_ms", 500)
	viper.SetDefault("watch.auto_block", true)
	viper.SetDefault("watch.allow_list_bypass_scan", true)

	viper.SetDefault("splunk.hec_endpoint", "https://localhost:8088/services/collector/event")
	viper.SetDefault("splunk.hec_token", "")
	viper.SetDefault("splunk.index", "defenseclaw")
	viper.SetDefault("splunk.source", "defenseclaw")
	viper.SetDefault("splunk.sourcetype", "_json")
	viper.SetDefault("splunk.verify_tls", false)
	viper.SetDefault("splunk.enabled", false)
	viper.SetDefault("splunk.batch_size", 50)
	viper.SetDefault("splunk.flush_interval_s", 5)

	viper.SetDefault("skill_actions.critical.file", string(FileActionQuarantine))
	viper.SetDefault("skill_actions.critical.runtime", string(RuntimeDisable))
	viper.SetDefault("skill_actions.critical.install", string(InstallBlock))
	viper.SetDefault("skill_actions.high.file", string(FileActionQuarantine))
	viper.SetDefault("skill_actions.high.runtime", string(RuntimeDisable))
	viper.SetDefault("skill_actions.high.install", string(InstallBlock))
	viper.SetDefault("skill_actions.medium.file", string(FileActionNone))
	viper.SetDefault("skill_actions.medium.runtime", string(RuntimeEnable))
	viper.SetDefault("skill_actions.medium.install", string(InstallNone))
	viper.SetDefault("skill_actions.low.file", string(FileActionNone))
	viper.SetDefault("skill_actions.low.runtime", string(RuntimeEnable))
	viper.SetDefault("skill_actions.low.install", string(InstallNone))
	viper.SetDefault("skill_actions.info.file", string(FileActionNone))
	viper.SetDefault("skill_actions.info.runtime", string(RuntimeEnable))
	viper.SetDefault("skill_actions.info.install", string(InstallNone))

	viper.SetDefault("guardrail.enabled", false)
	viper.SetDefault("guardrail.mode", "observe")
	viper.SetDefault("guardrail.scanner_mode", "local")
	viper.SetDefault("guardrail.port", 4000)
	viper.SetDefault("guardrail.guardrail_dir", dataDir)
	viper.SetDefault("guardrail.litellm_config", filepath.Join(dataDir, "litellm_config.yaml"))
	viper.SetDefault("guardrail.cisco_ai_defense.endpoint", "https://us.api.inspect.aidefense.security.cisco.com")
	viper.SetDefault("guardrail.cisco_ai_defense.api_key_env", "CISCO_AI_DEFENSE_API_KEY")
	viper.SetDefault("guardrail.cisco_ai_defense.timeout_ms", 3000)
	viper.SetDefault("guardrail.cisco_ai_defense.enabled_rules", []string{})

	viper.SetDefault("gateway.host", "127.0.0.1")
	viper.SetDefault("gateway.port", 18789)
	viper.SetDefault("gateway.token", "")
	viper.SetDefault("gateway.device_key_file", filepath.Join(dataDir, "device.key"))
	viper.SetDefault("gateway.auto_approve_safe", false)
	viper.SetDefault("gateway.reconnect_ms", 800)
	viper.SetDefault("gateway.max_reconnect_ms", 15000)
	viper.SetDefault("gateway.approval_timeout_s", 30)
	viper.SetDefault("gateway.api_port", 18790)
	viper.SetDefault("gateway.watcher.enabled", false)
	viper.SetDefault("gateway.watcher.skill.enabled", true)
	viper.SetDefault("gateway.watcher.skill.take_action", true)
	viper.SetDefault("gateway.watcher.skill.dirs", []string{})

	viper.SetDefault("otel.enabled", false)
	viper.SetDefault("otel.protocol", "grpc")
	viper.SetDefault("otel.endpoint", "")
	viper.SetDefault("otel.tls.insecure", false)
	viper.SetDefault("otel.tls.ca_cert", "")
	viper.SetDefault("otel.traces.enabled", true)
	viper.SetDefault("otel.traces.sampler", "always_on")
	viper.SetDefault("otel.traces.sampler_arg", "1.0")
	viper.SetDefault("otel.logs.enabled", true)
	viper.SetDefault("otel.logs.emit_individual_findings", false)
	viper.SetDefault("otel.metrics.enabled", true)
	viper.SetDefault("otel.metrics.export_interval_s", 60)
	viper.SetDefault("otel.batch.max_export_batch_size", 512)
	viper.SetDefault("otel.batch.scheduled_delay_ms", 5000)
	viper.SetDefault("otel.batch.max_queue_size", 2048)
}

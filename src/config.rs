use serde::Deserialize;
use std::path::Path;

/// Config mode: "static" uses TOML rules only, "dynamic" syncs from central backend.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConfigMode {
    Static,
    Dynamic,
}

impl Default for ConfigMode {
    fn default() -> Self {
        ConfigMode::Static
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    /// "static" = rules from TOML only, "dynamic" = sync from central backend
    #[serde(default)]
    pub mode: ConfigMode,
    #[serde(default)]
    pub authz: AuthzConfig,
    #[serde(default)]
    pub dlp: DlpConfig,
    pub breaker: BreakerConfig,
    #[serde(default)]
    pub hitl: HitlConfig,
    pub audit: AuditConfig,
    pub heartbeat: Option<HeartbeatConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Identifier for this sidecar instance (used in HITL approval requests)
    #[serde(default = "default_agent_id")]
    pub agent_id: String,
    /// Max entries in the agent key cache. Default: 10000.
    #[serde(default = "default_cache_max_entries")]
    pub cache_max_entries: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    /// Command to spawn as child MCP server process
    pub command: String,
    /// Arguments for the child process command
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables passed to the child process
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AuthzConfig {
    #[serde(default)]
    pub roles: Vec<RoleBinding>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RoleBinding {
    pub role: String,
    pub allowed_tools: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DlpConfig {
    #[serde(default)]
    pub patterns: Vec<DlpPattern>,
    #[serde(default = "default_redact")]
    pub redact_replacement: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DlpPattern {
    pub name: String,
    pub regex: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BreakerConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct HitlConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub high_risk_tools: Vec<String>,
    #[serde(default)]
    pub webhook_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuditConfig {
    pub enabled: bool,
    pub sink: String, // "stdout" | "file" | "webhook"
    pub file_path: Option<String>,
    pub webhook_url: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HeartbeatConfig {
    pub central_url: String,
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    pub api_key: Option<String>,
}

fn default_interval() -> u64 {
    30
}

fn default_redact() -> String {
    "[REDACTED]".to_string()
}

fn default_agent_id() -> String {
    format!("sidecar-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

fn default_cache_max_entries() -> usize {
    10000
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            patterns: Vec::new(),
            redact_replacement: default_redact(),
        }
    }
}

impl Config {
    /// Load config from TOML file, then apply env var overrides.
    ///
    /// Env vars (all optional — override TOML values when set):
    ///   POIMEN_UPSTREAM_COMMAND  — upstream MCP server command
    ///   POIMEN_UPSTREAM_ARGS    — space-separated args for upstream command
    ///   POIMEN_CENTRAL_URL      — heartbeat central URL (e.g. https://poimen.io)
    ///   POIMEN_SIDECAR_KEY      — sidecar key (hsk_) for heartbeat auth
    ///   POIMEN_MODE             — "static" or "dynamic"
    ///
    /// If the config file doesn't exist, a minimal dynamic-mode default is used.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let mut config: Config = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            if content.trim().is_empty() {
                Config::minimal_default()
            } else {
                toml::from_str(&content)?
            }
        } else {
            Config::minimal_default()
        };

        // Env var overrides
        if let Ok(cmd) = std::env::var("POIMEN_UPSTREAM_COMMAND") {
            config.upstream.command = cmd;
        }
        if let Ok(args) = std::env::var("POIMEN_UPSTREAM_ARGS") {
            config.upstream.args = args.split_whitespace().map(String::from).collect();
        }
        if let Ok(url) = std::env::var("POIMEN_CENTRAL_URL") {
            let hb = config.heartbeat.get_or_insert(HeartbeatConfig {
                central_url: String::new(),
                interval_secs: default_interval(),
                api_key: None,
            });
            hb.central_url = url;
        }
        if let Ok(key) = std::env::var("POIMEN_SIDECAR_KEY") {
            let hb = config.heartbeat.get_or_insert(HeartbeatConfig {
                central_url: "https://poimen.io".into(),
                interval_secs: default_interval(),
                api_key: None,
            });
            hb.api_key = Some(key);
        }
        if let Ok(mode) = std::env::var("POIMEN_MODE") {
            config.mode = match mode.to_lowercase().as_str() {
                "dynamic" => ConfigMode::Dynamic,
                _ => ConfigMode::Static,
            };
        }
        // Pass through upstream env vars from POIMEN_UPSTREAM_ENV_* pattern
        for (k, v) in std::env::vars() {
            if let Some(name) = k.strip_prefix("POIMEN_UPSTREAM_ENV_") {
                config.upstream.env.insert(name.to_string(), v);
            }
        }

        Ok(config)
    }

    /// Minimal config for when no TOML file exists — expects env vars to fill in the blanks.
    fn minimal_default() -> Self {
        Config {
            server: ServerConfig {
                agent_id: default_agent_id(),
                cache_max_entries: default_cache_max_entries(),
            },
            upstream: UpstreamConfig {
                command: String::new(),
                args: Vec::new(),
                env: std::collections::HashMap::new(),
            },
            mode: ConfigMode::Dynamic,
            authz: AuthzConfig::default(),
            dlp: DlpConfig::default(),
            breaker: BreakerConfig {
                requests_per_second: 50,
                burst_size: 100,
            },
            hitl: HitlConfig::default(),
            audit: AuditConfig {
                enabled: true,
                sink: "stdout".into(),
                file_path: None,
                webhook_url: None,
            },
            heartbeat: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn valid_toml() -> &'static str {
        r#"
[server]
agent_id = "test-sidecar"

[upstream]
command = "/usr/bin/echo"

[authz]
[[authz.roles]]
role = "admin"
allowed_tools = ["*"]

[dlp]
redact_replacement = "[REDACTED]"
[[dlp.patterns]]
name = "email"
regex = '[a-z]+@[a-z]+\.[a-z]+'

[breaker]
requests_per_second = 50
burst_size = 100

[hitl]
enabled = true
high_risk_tools = ["db_write"]
webhook_url = "http://localhost:9090/approve"

[audit]
enabled = true
sink = "stdout"
"#
    }

    #[test]
    fn load_valid_config() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{}", valid_toml()).unwrap();
        let config = Config::load(tmp.path()).unwrap();
        assert_eq!(config.server.agent_id, "test-sidecar");
        assert_eq!(config.upstream.command, "/usr/bin/echo");
        assert_eq!(config.authz.roles.len(), 1);
        assert_eq!(config.authz.roles[0].role, "admin");
        assert_eq!(config.dlp.redact_replacement, "[REDACTED]");
        assert_eq!(config.breaker.requests_per_second, 50);
        assert!(config.hitl.enabled);
        assert!(config.audit.enabled);
    }

    #[test]
    fn load_missing_file_returns_minimal_default() {
        let config = Config::load(Path::new("/nonexistent/config.toml")).unwrap();
        // Minimal default uses dynamic mode and empty upstream command
        assert_eq!(config.mode, ConfigMode::Dynamic);
        assert!(config.upstream.command.is_empty());
    }

    #[test]
    fn load_invalid_toml() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "this is not valid toml {{{{").unwrap();
        let result = Config::load(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn load_missing_required_fields() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "[server]\nlisten_addr = \"127.0.0.1:8080\"").unwrap();
        let result = Config::load(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_role_binding() {
        let toml_str = r#"role = "dev"
allowed_tools = ["jira", "github"]"#;
        let rb: RoleBinding = toml::from_str(toml_str).unwrap();
        assert_eq!(rb.role, "dev");
        assert_eq!(rb.allowed_tools, vec!["jira", "github"]);
    }

    #[test]
    fn default_mode_is_static() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{}", valid_toml()).unwrap();
        let config = Config::load(tmp.path()).unwrap();
        assert_eq!(config.mode, ConfigMode::Static);
    }

    #[test]
    fn dynamic_mode_parsed() {
        let toml = format!("mode = \"dynamic\"\n{}", valid_toml());
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{}", toml).unwrap();
        let config = Config::load(tmp.path()).unwrap();
        assert_eq!(config.mode, ConfigMode::Dynamic);
    }

    #[test]
    fn audit_config_optional_fields() {
        let toml_str = r#"enabled = false
sink = "stdout""#;
        let ac: AuditConfig = toml::from_str(toml_str).unwrap();
        assert!(!ac.enabled);
        assert!(ac.file_path.is_none());
        assert!(ac.webhook_url.is_none());
    }
}

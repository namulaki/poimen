use crate::config::{AuthzConfig, DlpConfig, DlpPattern, HitlConfig, RoleBinding};
use crate::dlp::DlpEngine;
use crate::proxy::SidecarState;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::time::{interval, Duration};

#[derive(Serialize)]
struct HeartbeatPayload {
    agent_id: String,
    hostname: String,
    version: String,
    upstream_url: Option<String>,
    total_requests: u64,
    blocked_requests: u64,
}

/// Response from GET /api/config on the central server
#[derive(Deserialize, Debug)]
struct CentralConfig {
    roles: Vec<CentralRole>,
    dlp_patterns: Vec<CentralDlpPattern>,
    hitl_rules: Vec<CentralHitlRule>,
    settings: CentralSettings,
}

#[derive(Deserialize, Debug)]
struct CentralRole {
    role: String,
    allowed_tools: Vec<String>, // JSON array from API
}

#[derive(Deserialize, Debug)]
struct CentralDlpPattern {
    name: String,
    regex: String,
}

#[derive(Deserialize, Debug)]
struct CentralHitlRule {
    tool: String,
}

#[derive(Deserialize, Debug)]
struct CentralSettings {
    hitl_enabled: String,
    hitl_webhook_url: String,
    requests_per_second: String,
    burst_size: String,
}

/// Spawns a background task that sends heartbeats to the central hesed-pro server.
pub fn spawn(
    state: Arc<SidecarState>,
    central_url: String,
    interval_secs: u64,
    upstream_url: String,
    api_key: Option<String>,
) {
    let agent_id = format!("agent-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let hostname = hostname();
    let version = env!("CARGO_PKG_VERSION").to_string();

    tokio::spawn(async move {
        let base = central_url.trim_end_matches('/');
        let heartbeat_url = format!("{}/api/agents/heartbeat", base);
        let config_url = format!("{}/api/config", base);
        let mut tick = interval(Duration::from_secs(interval_secs));

        tracing::info!(
            agent_id = %agent_id,
            central = %central_url,
            interval = interval_secs,
            "heartbeat started"
        );

        loop {
            tick.tick().await;

            // --- Send heartbeat ---
            let payload = HeartbeatPayload {
                agent_id: agent_id.clone(),
                hostname: hostname.clone(),
                version: version.clone(),
                upstream_url: Some(upstream_url.clone()),
                total_requests: state.total_requests.load(Ordering::Relaxed),
                blocked_requests: state.blocked_requests.load(Ordering::Relaxed),
            };

            let mut req = state.http_client.post(&heartbeat_url).json(&payload);
            if let Some(ref key) = api_key {
                req = req.header("authorization", format!("Bearer {}", key));
            }
            match req.send().await {
                Ok(r) if r.status().is_success() => {
                    tracing::debug!("heartbeat sent");
                }
                Ok(r) => {
                    tracing::warn!(status = %r.status(), "heartbeat rejected");
                }
                Err(e) => {
                    tracing::warn!(err = %e, "heartbeat failed");
                }
            }

            // --- Pull config from central ---
            let mut cfg_req = state.http_client.get(&config_url);
            if let Some(ref key) = api_key {
                cfg_req = cfg_req.header("authorization", format!("Bearer {}", key));
            }
            match cfg_req.send().await {
                Ok(r) if r.status().is_success() => {
                    match r.json::<CentralConfig>().await {
                        Ok(cfg) => apply_config(&state, cfg).await,
                        Err(e) => tracing::warn!(err = %e, "config parse failed"),
                    }
                }
                Ok(r) => {
                    tracing::warn!(status = %r.status(), "config pull rejected");
                }
                Err(e) => {
                    tracing::warn!(err = %e, "config pull failed");
                }
            }
        }
    });
}

/// Apply the central config to the sidecar's RwLock-protected state.
async fn apply_config(state: &SidecarState, cfg: CentralConfig) {
    // Update AuthZ roles
    let roles: Vec<RoleBinding> = cfg.roles.iter().map(|r| {
        RoleBinding {
            role: r.role.clone(),
            allowed_tools: r.allowed_tools.clone(),
        }
    }).collect();
    {
        let mut authz = state.authz.write().await;
        *authz = AuthzConfig { roles };
    }

    // Update DLP engine
    let dlp_config = DlpConfig {
        patterns: cfg.dlp_patterns.iter().map(|p| DlpPattern {
            name: p.name.clone(),
            regex: p.regex.clone(),
        }).collect(),
        redact_replacement: state.config.dlp.redact_replacement.clone(),
    };
    match DlpEngine::new(&dlp_config) {
        Ok(engine) => {
            let mut dlp = state.dlp_engine.write().await;
            *dlp = engine;
        }
        Err(e) => {
            tracing::warn!(err = %e, "failed to rebuild DLP engine from central config");
        }
    }

    // Update HITL config
    let hitl_enabled = cfg.settings.hitl_enabled.eq_ignore_ascii_case("true");
    let high_risk_tools: Vec<String> = cfg.hitl_rules.iter().map(|r| r.tool.clone()).collect();
    {
        let mut hitl = state.hitl.write().await;
        *hitl = HitlConfig {
            enabled: hitl_enabled,
            high_risk_tools,
            webhook_url: cfg.settings.hitl_webhook_url,
        };
    }

    tracing::debug!("config updated from central");
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| gethostname())
}

fn gethostname() -> String {
    #[cfg(unix)]
    {
        use std::ffi::CStr;
        let mut buf = [0u8; 256];
        unsafe {
            libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len());
            CStr::from_ptr(buf.as_ptr() as *const libc::c_char)
                .to_string_lossy()
                .into_owned()
        }
    }
    #[cfg(not(unix))]
    {
        "unknown".to_string()
    }
}

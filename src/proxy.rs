use crate::{audit, authz, breaker, config::{self, Config, ConfigMode}, dlp, hitl, interceptor};
use crate::interceptor::InterceptError;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Cached resolution of an agent key (hak_) → (role, project_id, allowed_tools).
#[derive(Debug, Clone)]
struct CachedResolution {
    role: String,
    project_id: String,
    allowed_tools: Vec<String>,
    expires_at: std::time::Instant,
}

/// Default TTL for agent key cache entries (5 minutes).
const AGENT_KEY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

pub struct SidecarState {
    pub config: Config,
    // Dynamic config pulled from central — wrapped in RwLock
    pub authz: RwLock<config::AuthzConfig>,
    pub dlp_engine: RwLock<dlp::DlpEngine>,
    pub hitl: RwLock<config::HitlConfig>,
    pub limiter: breaker::Limiter,
    pub audit_logger: audit::AuditLogger,
    pub http_client: reqwest::Client,
    pub total_requests: AtomicU64,
    pub blocked_requests: AtomicU64,
    /// Local cache: agent_key (hak_) → resolved (role, project_id) + expiry
    agent_key_cache: RwLock<HashMap<String, CachedResolution>>,
}

impl SidecarState {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let dlp_engine = dlp::DlpEngine::new(&config.dlp)?;
        let limiter = breaker::new_limiter(config.breaker.requests_per_second, config.breaker.burst_size)?;
        let central_url = config.heartbeat.as_ref().map(|hb| hb.central_url.clone());
        let api_key = config.heartbeat.as_ref().and_then(|hb| hb.api_key.clone());
        let audit_logger = audit::AuditLogger::new(&config.audit, central_url, api_key);
        let http_client = reqwest::Client::new();
        let authz = config.authz.clone();
        let hitl = config.hitl.clone();
        Ok(Self {
            config,
            authz: RwLock::new(authz),
            dlp_engine: RwLock::new(dlp_engine),
            hitl: RwLock::new(hitl),
            limiter,
            audit_logger,
            http_client,
            total_requests: AtomicU64::new(0),
            blocked_requests: AtomicU64::new(0),
            agent_key_cache: RwLock::new(HashMap::new()),
        })
    }

    /// Resolve an agent key to (role, project_id) via local cache or backend API call.
    /// The agent key is the single source of truth for both role and project context.
    async fn resolve_agent_key(&self, agent_key: &str) -> Option<CachedResolution> {
        // Check cache first
        {
            let cache = self.agent_key_cache.read().await;
            if let Some(cached) = cache.get(agent_key) {
                if cached.expires_at > std::time::Instant::now() {
                    return Some(cached.clone());
                }
            }
        }

        // Cache miss or expired — call backend
        let hb = self.config.heartbeat.as_ref()?;
        let api_key = hb.api_key.as_ref()?;
        let url = format!("{}/api/resolve-agent-key?key={}", hb.central_url, agent_key);

        let resp = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            tracing::warn!(agent_key = %agent_key, status = %resp.status(), "agent key resolution failed");
            return None;
        }

        #[derive(serde::Deserialize)]
        struct Resolution {
            role: String,
            project_id: String,
            #[serde(default)]
            allowed_tools: Vec<String>,
        }

        let res: Resolution = resp.json().await.ok()?;

        let cached = CachedResolution {
            role: res.role,
            project_id: res.project_id,
            allowed_tools: res.allowed_tools,
            expires_at: std::time::Instant::now() + AGENT_KEY_CACHE_TTL,
        };

        // Cache the result
        {
            let mut cache = self.agent_key_cache.write().await;
            cache.insert(agent_key.to_string(), cached.clone());
        }

        Some(cached)
    }
}

/// Main pipeline: Intercept → Breaker → AuthZ → DLP → (HITL?) → Upstream → DLP response → Return
pub async fn handle_request(state: &Arc<SidecarState>, body: &[u8]) -> Vec<u8> {
    let request_id = Uuid::new_v4().to_string();
    state.total_requests.fetch_add(1, Ordering::Relaxed);

    match pipeline(state, body, &request_id).await {
        Ok(response_bytes) => response_bytes,
        Err(err) => {
            state.blocked_requests.fetch_add(1, Ordering::Relaxed);
            let req_id = interceptor::parse_request(body)
                .ok()
                .and_then(|r| r.id);
            serde_json::to_vec(&err.into_response(req_id)).unwrap_or_default()
        }
    }
}

/// The actual pipeline, returning InterceptError on any stage failure
async fn pipeline(
    state: &Arc<SidecarState>,
    body: &[u8],
    request_id: &str,
) -> Result<Vec<u8>, InterceptError> {
    // 1. Parse JSON-RPC
    let req = interceptor::parse_request(body)?;
    let tool_name = interceptor::extract_tool_name(&req);

    // Log intercept
    let mut evt = audit::AuditEvent::new(request_id, "intercept", "received", &req.method);
    if let Some(ref t) = tool_name {
        evt = evt.with_tool(t);
    }
    state.audit_logger.log(&evt).await;

    // For non-tool-call methods, pass through directly
    let tool = match tool_name {
        Some(t) => t,
        None => return forward_upstream(state, body, request_id).await,
    };

    // 2. Circuit Breaker - rate limit check (cheapest gate, run first)
    if !breaker::check(&state.limiter) {
        state.audit_logger.log(
            &audit::AuditEvent::new(request_id, "breaker", "rate_limit", "request throttled")
                .with_tool(&tool)
        ).await;
        return Err(InterceptError::RateLimited);
    }

    // 3. AuthZ - resolve role + project_id + allowed_tools from agent key
    //    When an agent key is present, its resolved allowed_tools are the source of truth
    //    (multi-project: each key carries its own project's permissions).
    //    Without an agent key, fall back to the global config pulled via heartbeat.
    let (role, resolved_project_id) = if let Some(agent_key) = authz::extract_agent_key(req.params.as_ref()) {
        match state.resolve_agent_key(&agent_key).await {
            Some(resolution) => {
                state.audit_logger.log(
                    &audit::AuditEvent::new(request_id, "authz", "key_resolve",
                        &format!("agent_key={} → role={} project={}", agent_key, resolution.role, resolution.project_id))
                        .with_tool(&tool).with_role(&resolution.role)
                ).await;
                // Evaluate against the per-key allowed_tools (project-scoped)
                if !authz::evaluate_tools(&resolution.allowed_tools, &tool) {
                    state.audit_logger.log(
                        &audit::AuditEvent::new(request_id, "authz", "deny", &format!("role={} tool={}", resolution.role, tool))
                            .with_tool(&tool).with_role(&resolution.role)
                    ).await;
                    return Err(InterceptError::AuthzDenied(
                        format!("role '{}' on tool '{}'", resolution.role, tool),
                    ));
                }
                state.audit_logger.log(
                    &audit::AuditEvent::new(request_id, "authz", "allow", &format!("role={} tool={}", resolution.role, tool))
                        .with_tool(&tool).with_role(&resolution.role)
                ).await;
                (resolution.role, Some(resolution.project_id))
            }
            None => {
                state.audit_logger.log(
                    &audit::AuditEvent::new(request_id, "authz", "deny",
                        &format!("invalid agent_key={}", agent_key))
                        .with_tool(&tool)
                ).await;
                return Err(InterceptError::AuthzDenied(
                    format!("invalid agent key '{}'", agent_key),
                ));
            }
        }
    } else {
        // No agent key — use global config (heartbeat-pulled or TOML)
        let role = authz::extract_role(req.params.as_ref());
        {
            let authz_cfg = state.authz.read().await;
            if !authz::evaluate(&authz_cfg, &role, &tool) {
                state.audit_logger.log(
                    &audit::AuditEvent::new(request_id, "authz", "deny", &format!("role={} tool={}", role, tool))
                        .with_tool(&tool).with_role(&role)
                ).await;
                return Err(InterceptError::AuthzDenied(
                    format!("role '{}' on tool '{}'", role, tool),
                ));
            }
        }
        state.audit_logger.log(
            &audit::AuditEvent::new(request_id, "authz", "allow", &format!("role={} tool={}", role, tool))
                .with_tool(&tool).with_role(&role)
        ).await;
        (role, None)
    };

    // 4. DLP - sanitize request params (read from RwLock)
    let mut sanitized_req = req.clone();
    if let Some(ref mut params) = sanitized_req.params {
        let dlp = state.dlp_engine.read().await;
        let detections = dlp.detect(&params.to_string());
        if !detections.is_empty() {
            state.audit_logger.log(
                &audit::AuditEvent::new(request_id, "dlp", "redact", &format!("detected: {:?}", detections))
                    .with_tool(&tool)
            ).await;
            dlp.sanitize_value(params);
        }
    }

    // 5. HITL - human-in-the-loop for high-risk tools (read from RwLock)
    let hitl_cfg = state.hitl.read().await;
    if hitl::requires_approval(&hitl_cfg, &tool) {
        state.audit_logger.log(
            &audit::AuditEvent::new(request_id, "hitl", "pending", &format!("awaiting approval for {}", tool))
                .with_tool(&tool)
        ).await;

        let params = sanitized_req.params.as_ref().cloned().unwrap_or(serde_json::Value::Null);

        // Static mode: always use webhook. Dynamic mode: use central dashboard.
        let central = match state.config.mode {
            ConfigMode::Dynamic => state.config.heartbeat.as_ref().and_then(|hb| {
                hb.api_key.as_ref().map(|key| (hb.central_url.as_str(), key.as_str()))
            }),
            ConfigMode::Static => None,
        };

        let approval_result = if let Some((url, key)) = central {
            let agent_id = &state.config.server.listen_addr;
            hitl::request_approval_central(
                url, key, agent_id, &tool, &role, &params, request_id,
            ).await
        } else {
            hitl::request_approval_webhook(&hitl_cfg, &tool, &role, &params, request_id).await
        };

        match approval_result {
            Ok(true) => {
                state.audit_logger.log(
                    &audit::AuditEvent::new(request_id, "hitl", "approve", "human approved")
                        .with_tool(&tool)
                ).await;
            }
            Ok(false) => {
                state.audit_logger.log(
                    &audit::AuditEvent::new(request_id, "hitl", "reject", "human denied")
                        .with_tool(&tool)
                ).await;
                return Err(InterceptError::ApprovalDenied("human denied".into()));
            }
            Err(e) => {
                state.audit_logger.log(
                    &audit::AuditEvent::new(request_id, "hitl", "reject", &format!("approval error: {}", e))
                        .with_tool(&tool)
                ).await;
                return Err(InterceptError::ApprovalDenied(format!("approval error: {}", e)));
            }
        }
    }
    drop(hitl_cfg);

    // 6. Inject resolved project_id into _meta so upstream MCP server knows the project
    if let Some(pid) = resolved_project_id {
        if let Some(ref mut params) = sanitized_req.params {
            if let Some(meta) = params.get_mut("_meta") {
                meta.as_object_mut().map(|m| m.insert("project_id".into(), serde_json::Value::String(pid)));
            } else {
                params.as_object_mut().map(|p| p.insert(
                    "_meta".into(),
                    serde_json::json!({ "project_id": pid }),
                ));
            }
        }
    }

    // 7. Forward to upstream MCP tool server
    let upstream_body = serde_json::to_vec(&sanitized_req).unwrap_or_default();
    let mut response_bytes = forward_upstream(state, &upstream_body, request_id).await?;

    // 8. DLP - sanitize response (read from RwLock)
    if let Ok(mut resp_value) = serde_json::from_slice::<serde_json::Value>(&response_bytes) {
        let dlp = state.dlp_engine.read().await;
        dlp.sanitize_value(&mut resp_value);
        response_bytes = serde_json::to_vec(&resp_value).unwrap_or(response_bytes);
    }

    state.audit_logger.log(
        &audit::AuditEvent::new(request_id, "upstream", "allow", "response returned")
            .with_tool(&tool)
    ).await;

    Ok(response_bytes)
}

async fn forward_upstream(
    state: &Arc<SidecarState>,
    body: &[u8],
    request_id: &str,
) -> Result<Vec<u8>, InterceptError> {
    let resp = state.http_client
        .post(&state.config.upstream.url)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await;

    match resp {
        Ok(r) => Ok(r.bytes().await.unwrap_or_default().to_vec()),
        Err(e) => {
            tracing::error!(request_id = %request_id, "upstream error: {}", e);
            Err(InterceptError::Upstream(e.to_string()))
        }
    }
}

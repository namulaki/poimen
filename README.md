# poimen

A security sidecar proxy for [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) tool calls. It sits between your AI agent and MCP tool servers, enforcing authorization, data loss prevention, rate limiting, and human-in-the-loop approval — with full audit logging.

## Architecture

```
User → Agent → [poimen: Interceptor → Breaker → AuthZ → DLP → (HITL?) → Tool] → Agent → User
```

Every JSON-RPC `tools/call` request passes through a security pipeline:

| Stage | What it does |
|---|---|
| Protocol Interceptor | Parses JSON-RPC, routes tool calls into the pipeline |
| Circuit Breaker | Token-bucket rate limiting via `governor` — cheapest gate, runs first |
| Policy Engine (AuthZ) | RBAC evaluation — resolves agent key to role and checks allowed tools |
| Semantic Inspector (DLP) | Regex-based PII detection and redaction on both request and response payloads |
| Human-in-the-Loop | Routes high-risk tool calls to webhook (static) or central dashboard (dynamic) for approval |
| Audit Logger | Logs every decision to stdout, file, webhook, or central dashboard |

Non-tool-call methods (e.g. `tools/list`, `resources/read`) are passed through to upstream unmodified.

## Quick Start

Two ways to get poimen running. Pick whichever fits your setup.

### Option A: Docker Compose

Run poimen in front of your MCP server with one command. The MCP server is only reachable through poimen — agents cannot bypass it.

**1. Clone the repo:**

```bash
git clone https://github.com/apridosimarmata/poimen
cd poimen
```

**2. Edit `docker-compose.yml`** — replace the MCP service image with yours. Edit `config.docker.toml` — set your dashboard URL and API key.

**3. Start everything:**

```bash
docker compose up --build
```

```
                ┌───────────────────────────┐
Agent ──▶ :8080 │  poimen ──▶ mcp:3000       │
  (host)        │  (exposed)  (internal only)│
                └───────────────────────────┘
                        Docker network
```

**4. Point your agent to Poimen:**

```bash
MCP_SERVER_URL=http://localhost:8080
```

> The MCP server is intentionally not exposed externally. All traffic must flow through poimen.

### Option B: Build from Source

No Docker required. Clone and build with Cargo.

**1. Clone and build:**

```bash
git clone https://github.com/apridosimarmata/poimen
cd poimen && cargo build --release
```

**2. Edit `config.toml`** — set your upstream MCP server address, dashboard URL, and API key.

**3. Run:**

```bash
./target/release/poimen              # uses config.toml in current dir
./target/release/poimen /path/to/config.toml
```

**4. Point your agent to Poimen:**

```bash
MCP_SERVER_URL=http://localhost:8080
```

The sidecar will start on `127.0.0.1:8080` by default and proxy requests to your upstream.

## Config Modes

The sidecar supports two operating modes, controlled by the top-level `mode` field in your config file:

| Mode | Rules source | HITL approval | Heartbeat | Use case |
|---|---|---|---|---|
| `static` (default) | TOML config file | Webhook | Not started | Standalone / air-gapped deployments |
| `dynamic` | Central dashboard | Central dashboard | Active | Managed fleet with [poimen-pro](https://github.com/apridosimarmata/poimen-pro) |

### Static Mode

All authz roles, DLP patterns, and HITL rules are defined directly in the TOML config. No external dependencies. HITL approvals are sent to the configured `webhook_url`. The heartbeat is never started.

### Dynamic Mode

The sidecar connects to a [poimen-pro](https://github.com/apridosimarmata/poimen-pro) central dashboard and pulls all security rules on every heartbeat tick. The dashboard is the single source of truth — rules in the TOML are used as initial defaults until the first heartbeat syncs.

1. Sidecar starts with rules from TOML (if any)
2. Every `interval_secs`, POSTs heartbeat to `/api/agents/heartbeat`
3. Immediately GETs `/api/config` to fetch roles, DLP patterns, HITL rules
4. Fetched rules replace in-memory config via `RwLock`
5. HITL approvals go through the central dashboard (not webhook)
6. Changes in the dashboard take effect on the next heartbeat (default: 30s)

> If `mode = "dynamic"` but `[heartbeat]` is missing or has no `api_key`, the sidecar logs a warning and falls back to static behavior.

## Configuration

### Static config example

```toml
mode = "static"   # or just omit — static is the default

[server]
listen_addr = "127.0.0.1:8080"
max_request_body_bytes = 1048576   # optional, default 1 MiB
shutdown_timeout_secs = 30         # optional, default 30
cache_max_entries = 10000          # optional, default 10000

[upstream]
url = "http://127.0.0.1:3000"

[authz]
[[authz.roles]]
role = "admin"
allowed_tools = ["*"]

[[authz.roles]]
role = "developer"
allowed_tools = ["jira_read", "github_read", "github_write"]

[[authz.roles]]
role = "default"
allowed_tools = ["jira_read"]

[dlp]
redact_replacement = "[REDACTED]"
[[dlp.patterns]]
name = "email"
regex = '[a-z]+@[a-z]+\.[a-z]+'

[hitl]
enabled = true
high_risk_tools = ["db_delete", "db_write", "github_merge"]
webhook_url = "http://localhost:9090/approve"

[breaker]
requests_per_second = 50
burst_size = 100

[audit]
enabled = true
sink = "stdout"
```

### Dynamic config example

```toml
mode = "dynamic"

[server]
listen_addr = "127.0.0.1:8080"

[upstream]
url = "http://127.0.0.1:3000"

# Rules are pulled from the central dashboard.
# No need to define authz/dlp/hitl here.

[breaker]
requests_per_second = 50
burst_size = 100

[audit]
enabled = true
sink = "stdout"

[heartbeat]
central_url = "http://127.0.0.1:9001"
interval_secs = 30
api_key = "hsk_your_api_key_here"
```

### Server config reference

| Field | Type | Default | Description |
|---|---|---|---|
| `listen_addr` | string | (required) | Address and port to listen on |
| `max_request_body_bytes` | integer | `1048576` (1 MiB) | Maximum request body size. Requests exceeding this are rejected with a JSON-RPC error. |
| `shutdown_timeout_secs` | integer | `30` | Seconds to wait for in-flight connections to drain on SIGTERM/SIGINT before force-closing. |
| `cache_max_entries` | integer | `10000` | Maximum entries in the agent key resolution cache (LRU eviction). |

## Error Handling

The pipeline uses a typed `InterceptError` enum. Each stage returns a specific error variant, which is automatically converted into a JSON-RPC error response with the correct error code:

| Error | Code | When |
|---|---|---|
| `InvalidPayload` | -32700 | Malformed JSON-RPC request |
| `BodyTooLarge` | -32600 | Request body exceeds `max_request_body_bytes` |
| `AuthzDenied` | -32600 | Role not authorized for the requested tool, or missing/invalid agent key |
| `RateLimited` | -32000 | Token bucket exhausted |
| `ApprovalDenied` | -32001 | HITL webhook rejected or failed |
| `Upstream` | -32603 | MCP tool server unreachable or errored |

Example error response:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32600,
    "message": "authorization denied: role 'viewer' on tool 'db_write'"
  }
}
```

## How Roles Work

All `tools/call` requests require an agent key (`hak_` prefix) in the `_meta.agent_key` field of the JSON-RPC params. The sidecar resolves the agent key to a role and project-scoped allowed tools via the central backend.

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "db_read",
    "_meta": {
      "agent_key": "hak_abc123..."
    }
  }
}
```

Requests without an agent key are rejected with `AuthzDenied`. The resolved role and allowed tools are cached locally with a 5-minute TTL in a bounded LRU cache (max `cache_max_entries` entries).

In static mode, roles and allowed tools are defined in `[authz.roles]` in the TOML. In dynamic mode, they're managed in the poimen-pro dashboard and synced via heartbeat.

Wildcard matching is supported: `"*"` allows all tools, and prefix wildcards like `"poimen_*"` match any tool starting with `poimen_`.

## Human-in-the-Loop

When a tool is listed as high-risk, the sidecar pauses execution and requests human approval. The approval path depends on the config mode:

| Mode | Approval path |
|---|---|
| `static` | POST to `webhook_url` configured in `[hitl]` — must respond with `{ "approved": true }` |
| `dynamic` | POST to central dashboard — approval/denial happens in the poimen-pro UI |

If the approval is denied or errors out, the request is rejected with `ApprovalDenied`.

## Graceful Shutdown

The sidecar handles `SIGTERM` and `SIGINT` signals for graceful shutdown:

1. Stops accepting new TCP connections
2. Waits for in-flight requests to complete (up to `shutdown_timeout_secs`, default 30s)
3. Force-closes remaining connections if the timeout is reached
4. Exits cleanly

This ensures `docker stop` and Kubernetes pod termination drain active connections instead of hard-killing them.

## Project Structure

```
src/
├── main.rs          # HTTP server, body size limit, graceful shutdown (hyper)
├── proxy.rs         # Pipeline orchestration, LRU agent key cache, RwLock-guarded config
├── interceptor.rs   # JSON-RPC types, InterceptError enum, parsing
├── authz.rs         # RBAC policy engine with wildcard support
├── dlp.rs           # PII/payload regex scanner & redactor
├── breaker.rs       # Rate limiter (governor)
├── hitl.rs          # Human-in-the-loop (webhook + central dashboard polling)
├── heartbeat.rs     # Heartbeat + config-pull from central (dynamic mode)
├── audit.rs         # Audit event logger (stdout, file, webhook, central)
└── config.rs        # TOML config loader + ConfigMode enum
```

## License

MIT — see [LICENSE](LICENSE).

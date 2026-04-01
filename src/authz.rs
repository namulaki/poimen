use crate::config::AuthzConfig;

/// Check if a given role is allowed to call the specified tool.
/// Supports exact match, full wildcard `"*"`, and prefix wildcards like `"poimen_*"`.
pub fn evaluate(config: &AuthzConfig, role: &str, tool: &str) -> bool {
    config.roles.iter().any(|binding| {
        binding.role == role
            && binding.allowed_tools.iter().any(|t| {
                t == "*"
                    || t == tool
                    || (t.ends_with('*') && tool.starts_with(&t[..t.len() - 1]))
            })
    })
}

/// Evaluate a tool against a pre-resolved list of allowed_tools (from agent key resolution).
/// Same matching logic as `evaluate` but without needing the full config/role lookup.
pub fn evaluate_tools(allowed_tools: &[String], tool: &str) -> bool {
    allowed_tools.iter().any(|t| {
        t == "*"
            || t == tool
            || (t.ends_with('*') && tool.starts_with(&t[..t.len() - 1]))
    })
}

/// Extract the role from JSON-RPC request metadata (params._meta.role).
/// Falls back to "default" if not present.
pub fn extract_role(params: Option<&serde_json::Value>) -> String {
    params
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get("role"))
        .and_then(|r| r.as_str())
        .unwrap_or("default")
        .to_string()
}

/// Extract the agent key (hak_) from JSON-RPC request metadata (params._meta.agent_key).
pub fn extract_agent_key(params: Option<&serde_json::Value>) -> Option<String> {
    params
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get("agent_key"))
        .and_then(|k| k.as_str())
        .filter(|k| k.starts_with("hak_"))
        .map(|k| k.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthzConfig, RoleBinding};
    use serde_json::json;

    fn test_config() -> AuthzConfig {
        AuthzConfig {
            roles: vec![
                RoleBinding {
                    role: "admin".into(),
                    allowed_tools: vec!["*".into()],
                },
                RoleBinding {
                    role: "developer".into(),
                    allowed_tools: vec!["jira_search".into(), "github_pr".into()],
                },
                RoleBinding {
                    role: "default".into(),
                    allowed_tools: vec!["jira_search".into()],
                },
            ],
        }
    }

    #[test]
    fn admin_wildcard_allows_any_tool() {
        assert!(evaluate(&test_config(), "admin", "anything"));
        assert!(evaluate(&test_config(), "admin", "db_delete"));
    }

    #[test]
    fn developer_allowed_tools() {
        assert!(evaluate(&test_config(), "developer", "jira_search"));
        assert!(evaluate(&test_config(), "developer", "github_pr"));
    }

    #[test]
    fn developer_denied_unlisted_tool() {
        assert!(!evaluate(&test_config(), "developer", "db_delete"));
    }

    #[test]
    fn default_role_limited() {
        assert!(evaluate(&test_config(), "default", "jira_search"));
        assert!(!evaluate(&test_config(), "default", "github_pr"));
    }

    #[test]
    fn unknown_role_denied() {
        assert!(!evaluate(&test_config(), "unknown", "jira_search"));
    }

    #[test]
    fn extract_role_from_meta() {
        let params = json!({"_meta": {"role": "admin"}, "name": "test"});
        assert_eq!(extract_role(Some(&params)), "admin");
    }

    #[test]
    fn extract_role_missing_meta() {
        let params = json!({"name": "test"});
        assert_eq!(extract_role(Some(&params)), "default");
    }

    #[test]
    fn extract_role_none_params() {
        assert_eq!(extract_role(None), "default");
    }

    #[test]
    fn extract_role_non_string() {
        let params = json!({"_meta": {"role": 42}});
        assert_eq!(extract_role(Some(&params)), "default");
    }

    #[test]
    fn prefix_wildcard_allows_matching_tools() {
        let config = AuthzConfig {
            roles: vec![RoleBinding {
                role: "playground".into(),
                allowed_tools: vec!["poimen_*".into()],
            }],
        };
        assert!(evaluate(&config, "playground", "poimen_list_roles"));
        assert!(evaluate(&config, "playground", "poimen_create_role"));
        assert!(!evaluate(&config, "playground", "db_delete"));
        assert!(!evaluate(&config, "playground", "list_roles"));
    }
}

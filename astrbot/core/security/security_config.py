"""安全配置管理

统一管理所有安全模块的配置项，提供默认安全级别配置。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SecurityConfig:
    """全局安全配置

    管理 AstrBot 安全增强模块的所有可配置项。
    默认配置采用适中的安全级别，不阻碍正常使用。
    """

    # ── 总开关 ──────────────────────────────────────────
    enabled: bool = True

    # ── Layer 1: Runtime Hook 零信任网关 ────────────────
    # AST 安全检查器
    ast_checker_enabled: bool = True
    ast_enable_ast_analysis: bool = True
    ast_enable_shell_check: bool = True
    ast_enable_path_check: bool = True
    ast_custom_dangerous_patterns: list[str] = field(default_factory=list)

    # ACL 权限网关
    acl_enabled: bool = True
    acl_default_policy: str = "allow"  # "allow" | "deny"
    acl_mcp_server_whitelist: list[str] = field(default_factory=list)
    acl_global_tool_blacklist: list[str] = field(default_factory=list)
    acl_role_acls: list[dict] = field(default_factory=list)

    # ── Layer 2: 实时风控中间件 ─────────────────────────
    # 威胁情报引擎
    threat_intel_enabled: bool = True
    threat_intel_custom_phishing_domains: list[str] = field(default_factory=list)

    # Prompt Injection 检测器
    prompt_injection_enabled: bool = True
    prompt_injection_use_llm: bool = False  # 是否启用 LLM 深度意图研判
    prompt_injection_llm_provider_id: str = ""
    prompt_injection_sensitivity: str = "medium"  # "low" | "medium" | "high"

    # ── Layer 3: 自动拦截撤回 ──────────────────────────
    auto_revoke_enabled: bool = True
    auto_revoke_notify_admin: bool = True

    @classmethod
    def from_dict(cls, config: dict) -> SecurityConfig:
        """从配置字典构建 SecurityConfig

        Args:
            config: 配置字典，支持嵌套结构
        """
        security = config.get("security_enhancement", {})
        if not security:
            return cls()

        acl_cfg = security.get("acl_gateway", {})
        ast_cfg = security.get("ast_checker", {})
        threat_cfg = security.get("threat_intel", {})
        injection_cfg = security.get("prompt_injection", {})
        revoke_cfg = security.get("auto_revoke", {})

        return cls(
            enabled=security.get("enabled", True),
            # AST
            ast_checker_enabled=ast_cfg.get("enabled", True),
            ast_enable_ast_analysis=ast_cfg.get("enable_ast_analysis", True),
            ast_enable_shell_check=ast_cfg.get("enable_shell_check", True),
            ast_enable_path_check=ast_cfg.get("enable_path_check", True),
            ast_custom_dangerous_patterns=ast_cfg.get(
                "custom_dangerous_patterns", []
            ),
            # ACL
            acl_enabled=acl_cfg.get("enabled", True),
            acl_default_policy=acl_cfg.get("default_policy", "allow"),
            acl_mcp_server_whitelist=acl_cfg.get("mcp_server_whitelist", []),
            acl_global_tool_blacklist=acl_cfg.get("global_tool_blacklist", []),
            acl_role_acls=acl_cfg.get("role_acls", []),
            # 威胁情报
            threat_intel_enabled=threat_cfg.get("enabled", True),
            threat_intel_custom_phishing_domains=threat_cfg.get(
                "custom_phishing_domains", []
            ),
            # Prompt Injection
            prompt_injection_enabled=injection_cfg.get("enabled", True),
            prompt_injection_use_llm=injection_cfg.get("use_llm", False),
            prompt_injection_llm_provider_id=injection_cfg.get(
                "llm_provider_id", ""
            ),
            prompt_injection_sensitivity=injection_cfg.get(
                "sensitivity", "medium"
            ),
            # 自动拦截
            auto_revoke_enabled=revoke_cfg.get("enabled", True),
            auto_revoke_notify_admin=revoke_cfg.get("notify_admin", True),
        )

    def to_dict(self) -> dict:
        """导出为配置字典"""
        return {
            "security_enhancement": {
                "enabled": self.enabled,
                "ast_checker": {
                    "enabled": self.ast_checker_enabled,
                    "enable_ast_analysis": self.ast_enable_ast_analysis,
                    "enable_shell_check": self.ast_enable_shell_check,
                    "enable_path_check": self.ast_enable_path_check,
                    "custom_dangerous_patterns": self.ast_custom_dangerous_patterns,
                },
                "acl_gateway": {
                    "enabled": self.acl_enabled,
                    "default_policy": self.acl_default_policy,
                    "mcp_server_whitelist": self.acl_mcp_server_whitelist,
                    "global_tool_blacklist": self.acl_global_tool_blacklist,
                    "role_acls": self.acl_role_acls,
                },
                "threat_intel": {
                    "enabled": self.threat_intel_enabled,
                    "custom_phishing_domains": self.threat_intel_custom_phishing_domains,
                },
                "prompt_injection": {
                    "enabled": self.prompt_injection_enabled,
                    "use_llm": self.prompt_injection_use_llm,
                    "llm_provider_id": self.prompt_injection_llm_provider_id,
                    "sensitivity": self.prompt_injection_sensitivity,
                },
                "auto_revoke": {
                    "enabled": self.auto_revoke_enabled,
                    "notify_admin": self.auto_revoke_notify_admin,
                },
            }
        }

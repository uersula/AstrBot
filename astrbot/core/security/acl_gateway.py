"""基于 ACL 的零信任工具权限网关

实施最小权限原则，通过角色-工具权限矩阵和 MCP Server 白名单
控制 LLM Agent 对工具的访问权限，阻断 MCP 协议下的工具链滥用。
"""

from __future__ import annotations

from dataclasses import dataclass, field

import logging

logger = logging.getLogger("astrbot.core.security.acl_gateway")


@dataclass
class ACLCheckResult:
    """ACL 权限检查结果"""

    allowed: bool
    reason: str = ""


@dataclass
class RoleACL:
    """单个角色的 ACL 配置"""

    role: str
    # 允许的工具列表，空列表表示允许所有(除了 denied 中的)
    allowed_tools: list[str] = field(default_factory=list)
    # 拒绝的工具列表，优先级高于 allowed
    denied_tools: list[str] = field(default_factory=list)


class ACLGateway:
    """零信任工具权限网关

    核心安全组件，实现：
    1. 角色-工具权限矩阵：基于角色控制工具访问权限
    2. MCP Server 白名单：只允许注册的 MCP server 工具被调用
    3. 工具名称黑名单：全局禁止的危险工具

    安全策略: 默认拒绝(deny-by-default)，只有显式允许的才放行。
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        mcp_server_whitelist: list[str] | None = None,
        role_acls: list[dict] | None = None,
        global_tool_blacklist: list[str] | None = None,
        default_policy: str = "allow",  # "allow" 或者 "deny"
    ) -> None:
        self.enabled = enabled
        self.default_policy = default_policy

        # MCP Server 白名单
        self.mcp_server_whitelist: set[str] = set(mcp_server_whitelist or [])

        # 全局工具黑名单
        self.global_tool_blacklist: set[str] = set(global_tool_blacklist or [])

        # 角色 ACL 矩阵
        self.role_acls: dict[str, RoleACL] = {}
        if role_acls:
            for acl_dict in role_acls:
                role = acl_dict.get("role", "")
                if role:
                    self.role_acls[role] = RoleACL(
                        role=role,
                        allowed_tools=acl_dict.get("allowed_tools", []),
                        denied_tools=acl_dict.get("denied_tools", []),
                    )

    def check_permission(
        self,
        *,
        role: str = "default",
        tool_name: str,
        mcp_server_name: str | None = None,
    ) -> ACLCheckResult:
        """检查工具调用权限

        Args:
            role: 调用者角色
            tool_name: 工具名称
            mcp_server_name: MCP 服务器名称（仅 MCP 工具需要）

        Returns:
            ACLCheckResult: 权限检查结果
        """
        if not self.enabled:
            return ACLCheckResult(allowed=True)

        # 1. 全局黑名单检查
        if tool_name in self.global_tool_blacklist:
            reason = f"工具 {tool_name} 在全局黑名单中，禁止调用"
            logger.warning(f"[ACLGateway] {reason}")
            return ACLCheckResult(allowed=False, reason=reason)

        # 2. MCP Server 白名单检查
        if mcp_server_name is not None:
            if (
                self.mcp_server_whitelist
                and mcp_server_name not in self.mcp_server_whitelist
            ):
                reason = (
                    f"MCP Server {mcp_server_name} 不在白名单中，"
                    f"工具 {tool_name} 被拒绝"
                )
                logger.warning(f"[ACLGateway] {reason}")
                return ACLCheckResult(allowed=False, reason=reason)

        # 3. 角色权限检查
        role_acl = self.role_acls.get(role)
        if role_acl:
            # denied_tools 优先级最高
            if tool_name in role_acl.denied_tools:
                reason = f"角色 {role} 被禁止使用工具 {tool_name}"
                logger.warning(f"[ACLGateway] {reason}")
                return ACLCheckResult(allowed=False, reason=reason)

            # 如果配置了 allowed_tools，则只允许列表中的工具
            if role_acl.allowed_tools and tool_name not in role_acl.allowed_tools:
                reason = (
                    f"角色 {role} 未被授权使用工具 {tool_name}，"
                    f"允许的工具: {role_acl.allowed_tools}"
                )
                logger.warning(f"[ACLGateway] {reason}")
                return ACLCheckResult(allowed=False, reason=reason)

        # 4. 默认策略
        if self.default_policy == "deny":
            # deny-by-default: 没有显式允许的都拒绝
            if not role_acl or not role_acl.allowed_tools:
                reason = f"默认策略为拒绝，角色 {role} 未配置工具 {tool_name} 的权限"
                logger.warning(f"[ACLGateway] {reason}")
                return ACLCheckResult(allowed=False, reason=reason)

        return ACLCheckResult(allowed=True)

    def add_mcp_server_to_whitelist(self, server_name: str) -> None:
        """动态添加 MCP Server 到白名单"""
        self.mcp_server_whitelist.add(server_name)
        logger.info(f"[ACLGateway] MCP Server {server_name} 已加入白名单")

    def add_tool_to_blacklist(self, tool_name: str) -> None:
        """动态添加工具到全局黑名单"""
        self.global_tool_blacklist.add(tool_name)
        logger.info(f"[ACLGateway] 工具 {tool_name} 已加入全局黑名单")

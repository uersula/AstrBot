"""Runtime Hook 执行器

劫持 FunctionToolExecutor.execute 的安全代理层。
在工具执行前注入 ACL 权限检查和 AST 参数安全检查，
实现对 MCP 协议下工具链调用的零信任安全管控。
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import mcp.types

import logging

logger = logging.getLogger("astrbot.core.security.runtime_hook")
from astrbot.core.agent.mcp_client import MCPTool
from astrbot.core.agent.run_context import ContextWrapper
from astrbot.core.agent.tool import FunctionTool

from .acl_gateway import ACLGateway
from .ast_checker import ASTSafetyChecker
from .security_config import SecurityConfig


@dataclass
class SecurityAuditEvent:
    """安全审计事件"""

    timestamp: float
    tool_name: str
    action: str  # "blocked" | "allowed"
    reason: str
    check_type: str  # "acl" | "ast" | "combined"
    risk_level: str = "none"
    tool_args: dict = field(default_factory=dict)


class SecurityHookExecutor:
    """Runtime Hook 安全执行器

    作为安全代理层，在工具实际执行前进行多维安全检查：
    1. ACL 权限验证 —— 检查角色是否有权调用该工具
    2. AST 参数安全检查 —— 检测参数中的代码注入、路径遍历等攻击
    3. 审计日志记录 —— 记录所有安全事件供事后分析

    检查链顺序: ACL → AST → 放行/拦截
    """

    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self.enabled = config.enabled

        # 初始化 AST 检查器
        self.ast_checker = ASTSafetyChecker(
            enable_ast_analysis=config.ast_enable_ast_analysis,
            enable_shell_check=config.ast_enable_shell_check,
            enable_path_check=config.ast_enable_path_check,
            custom_dangerous_patterns=config.ast_custom_dangerous_patterns,
        )

        # 初始化 ACL 网关
        self.acl_gateway = ACLGateway(
            enabled=config.acl_enabled,
            mcp_server_whitelist=config.acl_mcp_server_whitelist,
            role_acls=config.acl_role_acls,
            global_tool_blacklist=config.acl_global_tool_blacklist,
            default_policy=config.acl_default_policy,
        )

        # 审计日志
        self._audit_log: list[SecurityAuditEvent] = []

    def check_tool_call(
        self,
        tool: FunctionTool,
        run_context: ContextWrapper,
        tool_args: dict,
    ) -> tuple[bool, str]:
        """在工具执行前进行安全检查

        Args:
            tool: 待执行的工具
            run_context: 运行上下文
            tool_args: 工具调用参数

        Returns:
            (allowed, reason): 是否允许执行，以及拒绝原因
        """
        if not self.enabled:
            return True, ""

        tool_name = tool.name

        # ── Step 1: ACL 权限检查 ─────────────────────
        if self.config.acl_enabled:
            # 获取 MCP server 名称（如果是 MCP 工具）
            mcp_server_name = None
            if isinstance(tool, MCPTool):
                mcp_server_name = getattr(tool, "mcp_server_name", None)

            # 获取调用者角色
            role = "default"
            try:
                event = run_context.context.event
                if hasattr(event, "role") and event.role:
                    role = event.role
            except (AttributeError, TypeError):
                pass

            acl_result = self.acl_gateway.check_permission(
                role=role,
                tool_name=tool_name,
                mcp_server_name=mcp_server_name,
            )
            if not acl_result.allowed:
                self._record_audit(
                    tool_name=tool_name,
                    action="blocked",
                    reason=acl_result.reason,
                    check_type="acl",
                    risk_level="high",
                    tool_args=tool_args,
                )
                return False, acl_result.reason

        # ── Step 2: AST 参数安全检查 ──────────────────
        if self.config.ast_checker_enabled and tool_args:
            ast_result = self.ast_checker.check_tool_args(tool_name, tool_args)
            if not ast_result.safe:
                self._record_audit(
                    tool_name=tool_name,
                    action="blocked",
                    reason=ast_result.reason,
                    check_type="ast",
                    risk_level=ast_result.risk_level,
                    tool_args=tool_args,
                )
                return False, ast_result.reason

        # ── 通过所有检查 ──────────────────────────────
        self._record_audit(
            tool_name=tool_name,
            action="allowed",
            reason="",
            check_type="combined",
            tool_args=tool_args,
        )
        return True, ""

    def _record_audit(
        self,
        *,
        tool_name: str,
        action: str,
        reason: str,
        check_type: str,
        risk_level: str = "none",
        tool_args: dict | None = None,
    ) -> None:
        """记录安全审计事件"""
        event = SecurityAuditEvent(
            timestamp=time.time(),
            tool_name=tool_name,
            action=action,
            reason=reason,
            check_type=check_type,
            risk_level=risk_level,
            tool_args=tool_args or {},
        )
        self._audit_log.append(event)

        # 保持审计日志在合理范围内
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-5000:]

        if action == "blocked":
            logger.warning(
                f"[SecurityHook] 工具调用被拦截: tool={tool_name}, "
                f"type={check_type}, risk={risk_level}, reason={reason}"
            )

    def get_audit_log(self, limit: int = 100) -> list[SecurityAuditEvent]:
        """获取最近的审计日志"""
        return self._audit_log[-limit:]

    def get_blocked_count(self) -> int:
        """获取被拦截的工具调用总数"""
        return sum(1 for e in self._audit_log if e.action == "blocked")

    @staticmethod
    def make_blocked_result(reason: str) -> mcp.types.CallToolResult:
        """生成被拦截的工具调用结果

        Args:
            reason: 拦截原因

        Returns:
            CallToolResult: 包含安全拦截信息的工具调用结果
        """
        return mcp.types.CallToolResult(
            content=[
                mcp.types.TextContent(
                    type="text",
                    text=(
                        f"[SECURITY] 工具调用被安全网关拦截: {reason}\n"
                        "如果你认为这是误报，请联系管理员调整安全策略。"
                    ),
                )
            ],
            isError=True,
        )

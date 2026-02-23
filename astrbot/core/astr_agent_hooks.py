from typing import Any

from mcp.types import CallToolResult

from astrbot.core.agent.hooks import BaseAgentRunHooks
from astrbot.core.agent.message import Message
from astrbot.core.agent.run_context import ContextWrapper
from astrbot.core.agent.tool import FunctionTool
from astrbot.core.astr_agent_context import AstrAgentContext
from astrbot.core.pipeline.context_utils import call_event_hook
from astrbot.core.star.star_handler import EventType

from astrbot import logger


class SecurityToolCallBlocked(Exception):
    """安全网关拦截工具调用时抛出的异常"""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"[SECURITY] 工具调用被拦截: {reason}")


# 全局安全钩子实例（延迟初始化）
_security_hook = None


def _get_security_hook():
    """延迟初始化安全钩子执行器"""
    global _security_hook
    if _security_hook is None:
        try:
            from astrbot.core.security.runtime_hook import SecurityHookExecutor
            from astrbot.core.security.security_config import SecurityConfig

            config = SecurityConfig()  # 使用默认配置
            _security_hook = SecurityHookExecutor(config)
            logger.info("[SecurityHook] 安全钩子执行器已初始化")
        except Exception as e:
            logger.warning(f"[SecurityHook] 安全钩子初始化失败: {e}")
            _security_hook = None
    return _security_hook


def init_security_hook(config_dict: dict) -> None:
    """根据配置初始化安全钩子（由外部调用）"""
    global _security_hook
    try:
        from astrbot.core.security.runtime_hook import SecurityHookExecutor
        from astrbot.core.security.security_config import SecurityConfig

        config = SecurityConfig.from_dict(config_dict)
        _security_hook = SecurityHookExecutor(config)
        logger.info("[SecurityHook] 安全钩子执行器已根据配置初始化")
    except Exception as e:
        logger.warning(f"[SecurityHook] 安全钩子配置初始化失败: {e}")


class MainAgentHooks(BaseAgentRunHooks[AstrAgentContext]):
    async def on_agent_done(self, run_context, llm_response) -> None:
        # 执行事件钩子
        if llm_response and llm_response.reasoning_content:
            # we will use this in result_decorate stage to inject reasoning content to chain
            run_context.context.event.set_extra(
                "_llm_reasoning_content", llm_response.reasoning_content
            )

        await call_event_hook(
            run_context.context.event,
            EventType.OnLLMResponseEvent,
            llm_response,
        )

    async def on_tool_start(
        self,
        run_context: ContextWrapper[AstrAgentContext],
        tool: FunctionTool[Any],
        tool_args: dict | None,
    ) -> None:
        # ── Runtime Hook: 零信任鉴权网关 ──
        security_hook = _get_security_hook()
        if security_hook and tool_args:
            allowed, reason = security_hook.check_tool_call(
                tool=tool,
                run_context=run_context,
                tool_args=tool_args,
            )
            if not allowed:
                raise SecurityToolCallBlocked(reason)

        await call_event_hook(
            run_context.context.event,
            EventType.OnUsingLLMToolEvent,
            tool,
            tool_args,
        )

    async def on_tool_end(
        self,
        run_context: ContextWrapper[AstrAgentContext],
        tool: FunctionTool[Any],
        tool_args: dict | None,
        tool_result: CallToolResult | None,
    ) -> None:
        run_context.context.event.clear_result()
        await call_event_hook(
            run_context.context.event,
            EventType.OnLLMToolRespondEvent,
            tool,
            tool_args,
            tool_result,
        )

        # special handle web_search_tavily
        platform_name = run_context.context.event.get_platform_name()
        if (
            platform_name == "webchat"
            and tool.name in ["web_search_tavily", "web_search_bocha"]
            and len(run_context.messages) > 0
            and tool_result
            and len(tool_result.content)
        ):
            # inject system prompt
            first_part = run_context.messages[0]
            if (
                isinstance(first_part, Message)
                and first_part.role == "system"
                and first_part.content
                and isinstance(first_part.content, str)
            ):
                # we assume system part is str
                first_part.content += (
                    "Always cite web search results you rely on. "
                    "Index is a unique identifier for each search result. "
                    "Use the exact citation format <ref>index</ref> (e.g. <ref>abcd.3</ref>) "
                    "after the sentence that uses the information. Do not invent citations."
                )


class EmptyAgentHooks(BaseAgentRunHooks[AstrAgentContext]):
    pass


MAIN_AGENT_HOOKS = MainAgentHooks()


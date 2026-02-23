"""风控中间件 Pipeline Stage

作为 Pipeline 的新阶段，在消息处理流程中执行实时风控检查，
融合威胁情报引擎和 Prompt Injection 检测器，
实现对钓鱼链接和注入攻击的毫秒级自动拦截。
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from astrbot.core import logger
from astrbot.core.message.message_event_result import MessageEventResult
from astrbot.core.pipeline.context import PipelineContext
from astrbot.core.pipeline.stage import Stage, register_stage
from astrbot.core.platform.astr_message_event import AstrMessageEvent
from astrbot.core.security.auto_revoke import AutoRevokeManager
from astrbot.core.security.prompt_injection_detector import PromptInjectionDetector
from astrbot.core.security.security_config import SecurityConfig
from astrbot.core.security.threat_intel import ThreatIntelEngine


@register_stage
class RiskControlStage(Stage):
    """实时风控中间件 Pipeline Stage

    在 ContentSafetyCheckStage 之后执行，提供更深层的安全检测：
    1. 钓鱼链接 / 恶意 URL 检测（via ThreatIntelEngine）
    2. Prompt Injection / Jailbreak 检测（via PromptInjectionDetector）
    3. 自动拦截撤回（via AutoRevokeManager）
    """

    async def initialize(self, ctx: PipelineContext) -> None:
        """初始化风控组件"""
        config_dict = ctx.astrbot_config
        self.security_config = SecurityConfig.from_dict(config_dict)

        # 初始化威胁情报引擎
        self.threat_intel = ThreatIntelEngine(
            enabled=self.security_config.threat_intel_enabled,
            custom_phishing_domains=self.security_config.threat_intel_custom_phishing_domains,
        )

        # 初始化 Prompt Injection 检测器
        self.injection_detector = PromptInjectionDetector(
            enabled=self.security_config.prompt_injection_enabled,
            use_llm=self.security_config.prompt_injection_use_llm,
            llm_provider_id=self.security_config.prompt_injection_llm_provider_id,
            sensitivity=self.security_config.prompt_injection_sensitivity,
        )

        # 初始化自动拦截管理器
        self.auto_revoke = AutoRevokeManager(
            enabled=self.security_config.auto_revoke_enabled,
            notify_admin=self.security_config.auto_revoke_notify_admin,
        )

        if self.security_config.enabled:
            logger.info(
                "[RiskControl] 风控中间件已初始化: "
                f"threat_intel={self.security_config.threat_intel_enabled}, "
                f"prompt_injection={self.security_config.prompt_injection_enabled}"
            )

    async def process(
        self,
        event: AstrMessageEvent,
    ) -> AsyncGenerator[None, None] | None:
        """执行风控检查

        检查顺序：
        1. 如果安全增强未启用，直接放行
        2. 威胁情报检测（钓鱼链接等）
        3. Prompt Injection 检测
        4. 如果检测到威胁，执行自动拦截
        """
        if not self.security_config.enabled:
            yield
            return

        text = event.get_message_str()
        if not text:
            yield
            return

        # ── 1. 威胁情报检测 ─────────────────────────
        threat_result = self.threat_intel.scan_message(text)
        if threat_result.is_threat:
            logger.warning(
                f"[RiskControl] 威胁情报命中: type={threat_result.threat_type}, "
                f"risk={threat_result.risk_level}, "
                f"urls={threat_result.matched_urls}"
            )

            # high 及以上风险执行拦截
            if threat_result.risk_level in ("high", "critical"):
                self.auto_revoke.block_event(
                    event,
                    reason=threat_result.details,
                    threat_type=threat_result.threat_type,
                    risk_level=threat_result.risk_level,
                )
                return  # 阻止后续 pipeline 阶段
            else:
                # medium/low 风险只记录警告，不拦截
                logger.info(
                    f"[RiskControl] 低风险威胁通过: {threat_result.details}"
                )

        # ── 2. Prompt Injection 检测 ────────────────
        injection_result = self.injection_detector.detect(text)
        if injection_result.is_injection:
            logger.warning(
                f"[RiskControl] Prompt Injection 检测命中: "
                f"type={injection_result.injection_type}, "
                f"risk={injection_result.risk_level}, "
                f"confidence={injection_result.confidence:.2f}"
            )

            # high 及以上风险执行拦截
            if injection_result.risk_level in ("high", "critical"):
                self.auto_revoke.block_event(
                    event,
                    reason=injection_result.details,
                    threat_type=injection_result.injection_type,
                    risk_level=injection_result.risk_level,
                )
                return  # 阻止后续 pipeline 阶段

        # ── 通过所有检查，继续 pipeline ────────────
        yield

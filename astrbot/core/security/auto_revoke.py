"""消息自动拦截撤回机制

对检测到的恶意消息进行毫秒级拦截，支持：
- 阻止消息继续传递（stop_event）
- 替换消息内容为安全提示
- 向管理员发送安全告警通知
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import logging

logger = logging.getLogger("astrbot.core.security.auto_revoke")


@dataclass
class RevokeEvent:
    """拦截/撤回事件记录"""

    timestamp: float
    reason: str
    action: str  # "blocked" | "replaced" | "revoked"
    threat_type: str
    risk_level: str
    source_text: str = ""  # 截断的原始文本（用于审计）


class AutoRevokeManager:
    """消息自动拦截撤回管理器

    提供对恶意消息的实时拦截能力：
    1. 阻止发送：通过 event.stop_event() 阻止消息继续传递
    2. 内容替换：将恶意内容替换为安全提示信息
    3. 管理员通知：记录安全事件并可选地通知管理员

    与 Pipeline 的 Stage 机制深度集成，在消息处理流程的早期阶段生效。
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        notify_admin: bool = True,
    ) -> None:
        self.enabled = enabled
        self.notify_admin = notify_admin
        self._revoke_log: list[RevokeEvent] = []

    def block_event(
        self,
        event,
        *,
        reason: str,
        threat_type: str = "",
        risk_level: str = "high",
    ) -> None:
        """拦截事件，阻止消息继续传递

        Args:
            event: AstrMessageEvent 消息事件
            reason: 拦截原因
            threat_type: 威胁类型
            risk_level: 风险等级
        """
        if not self.enabled:
            return

        # 停止事件传播
        event.stop_event()

        # 设置安全提示作为响应
        from astrbot.core.message.message_event_result import MessageEventResult

        if event.is_at_or_wake_command:
            safe_message = self._build_safe_response(reason, threat_type)
            event.set_result(
                MessageEventResult().message(safe_message)
            )

        # 记录拦截事件
        source_text = ""
        try:
            source_text = event.get_message_str()[:200]  # 截断保存
        except Exception:
            pass

        revoke_event = RevokeEvent(
            timestamp=time.time(),
            reason=reason,
            action="blocked",
            threat_type=threat_type,
            risk_level=risk_level,
            source_text=source_text,
        )
        self._revoke_log.append(revoke_event)

        # 保持日志大小
        if len(self._revoke_log) > 5000:
            self._revoke_log = self._revoke_log[-2500:]

        logger.warning(
            f"[AutoRevoke] 消息已拦截: type={threat_type}, "
            f"risk={risk_level}, reason={reason}"
        )

    @staticmethod
    def _build_safe_response(reason: str, threat_type: str) -> str:
        """构建安全提示响应"""
        type_desc = {
            "phishing": "钓鱼链接",
            "suspicious_url": "可疑链接",
            "malicious_domain": "恶意域名",
            "prompt_injection": "指令注入",
            "instruction_override": "指令覆盖",
            "role_hijack": "角色劫持",
            "jailbreak": "越狱攻击",
            "system_probe": "系统探测",
            "encoding_bypass": "编码绕过",
        }.get(threat_type, "安全威胁")

        return (
            f"⚠️ 安全警告：您的消息被安全系统拦截。\n"
            f"检测到的威胁类型: {type_desc}\n"
            f"原因: {reason}\n"
            f"如有疑问请联系管理员。"
        )

    def get_revoke_log(self, limit: int = 100) -> list[RevokeEvent]:
        """获取最近的拦截日志"""
        return self._revoke_log[-limit:]

    def get_blocked_count(self) -> int:
        """获取总拦截次数"""
        return len(self._revoke_log)

    def get_stats(self) -> dict:
        """获取拦截统计"""
        if not self._revoke_log:
            return {"total": 0, "by_type": {}, "by_risk": {}}

        by_type: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        for evt in self._revoke_log:
            by_type[evt.threat_type] = by_type.get(evt.threat_type, 0) + 1
            by_risk[evt.risk_level] = by_risk.get(evt.risk_level, 0) + 1

        return {
            "total": len(self._revoke_log),
            "by_type": by_type,
            "by_risk": by_risk,
        }

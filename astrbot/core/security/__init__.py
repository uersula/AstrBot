"""AstrBot 安全增强模块

提供纵深防御能力的全栈安全增强，包括：
- Layer 1: Runtime Hook 零信任鉴权网关 (AST + ACL)
- Layer 2: 实时风控中间件 (威胁情报 + Prompt Injection 检测)
- Layer 3: 端到端安全管控 (自动拦截撤回)
"""

from .acl_gateway import ACLGateway
from .ast_checker import ASTSafetyChecker
from .auto_revoke import AutoRevokeManager
from .prompt_injection_detector import InjectionResult, PromptInjectionDetector
from .runtime_hook import SecurityHookExecutor
from .security_config import SecurityConfig
from .threat_intel import ThreatIntelEngine, ThreatResult

__all__ = [
    "ACLGateway",
    "ASTSafetyChecker",
    "AutoRevokeManager",
    "InjectionResult",
    "PromptInjectionDetector",
    "SecurityConfig",
    "SecurityHookExecutor",
    "ThreatIntelEngine",
    "ThreatResult",
]

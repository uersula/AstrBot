"""威胁情报检测引擎

实时检测消息中的恶意内容，包括：
- 钓鱼链接检测：正则提取 URL，对比已知钓鱼域名库 + 可疑模式匹配
- 恶意域名匹配：内置常见钓鱼域名模式库
- IP 直连检测、超长子域名分析、Unicode 混淆字符检测
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import logging

logger = logging.getLogger("astrbot.core.security.threat_intel")


@dataclass
class ThreatResult:
    """威胁检测结果"""

    is_threat: bool
    threat_type: str = ""  # "phishing" | "malicious_domain" | "suspicious_url" | ""
    risk_level: str = "none"  # "none" | "low" | "medium" | "high" | "critical"
    matched_urls: list[str] = field(default_factory=list)
    details: str = ""


# URL 提取正则
URL_PATTERN = re.compile(
    r"https?://[^\s<>\"'`\]\)）》」\u3001\uff0c\u3002]+|"
    r"(?:www\.)[^\s<>\"'`\]\)）》」\u3001\uff0c\u3002]+",
    re.IGNORECASE,
)

# IP 地址直连检测
IP_URL_PATTERN = re.compile(
    r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
    re.IGNORECASE,
)

# 已知钓鱼域名模式（常见仿冒模式）
KNOWN_PHISHING_PATTERNS = [
    # 仿冒大厂
    re.compile(r"(?:login|signin|account|verify|secure|update|confirm)[.-].*"
               r"(?:paypal|apple|google|microsoft|amazon|facebook|twitter|instagram)",
               re.IGNORECASE),
    re.compile(r"(?:paypal|apple|google|microsoft|amazon|facebook|twitter|instagram)"
               r".*[.-](?:login|signin|verify|secure|confirm|update|reset)",
               re.IGNORECASE),
    # 仿冒银行
    re.compile(r"(?:bank|banking)[.-].*(?:login|verify|secure|update)", re.IGNORECASE),
    # 中奖/抽奖诈骗
    re.compile(r"(?:prize|winner|lottery|reward|gift|free|bonus).*(?:claim|redeem|collect)",
               re.IGNORECASE),
    # 紧急/安全告警骗局
    re.compile(r"(?:urgent|suspended|locked|disabled|compromised|unauthorized)",
               re.IGNORECASE),
]

# 可疑 TLD (顶级域名)
SUSPICIOUS_TLDS = frozenset({
    ".tk", ".ml", ".ga", ".cf", ".gq",  # 免费域名
    ".xyz", ".top", ".icu", ".buzz", ".surf",
    ".monster", ".rest", ".casa", ".click",
})

# Unicode 混淆字符映射 (同形攻击 homoglyph)
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "х": "x", "ⅰ": "i", "ⅼ": "l",
    "ɡ": "g", "ɑ": "a", "ο": "o", "і": "i",
}


class ThreatIntelEngine:
    """威胁情报检测引擎

    对消息文本进行实时安全扫描，检测钓鱼链接和恶意内容。
    采用多层检测策略：URL 提取 → 域名分析 → 模式匹配 → 综合研判。
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        custom_phishing_domains: list[str] | None = None,
    ) -> None:
        self.enabled = enabled
        self.custom_phishing_domains: set[str] = set(custom_phishing_domains or [])

    def scan_message(self, text: str) -> ThreatResult:
        """扫描消息文本，检测威胁

        Args:
            text: 待扫描的消息文本

        Returns:
            ThreatResult: 威胁检测结果
        """
        if not self.enabled or not text:
            return ThreatResult(is_threat=False)

        # 提取所有 URL
        urls = URL_PATTERN.findall(text)
        if not urls:
            return ThreatResult(is_threat=False)

        threat_urls: list[str] = []
        max_risk = "none"
        details_parts: list[str] = []

        for url in urls:
            url_result = self._analyze_url(url)
            if url_result.is_threat:
                threat_urls.append(url)
                details_parts.append(f"[{url}]: {url_result.details}")
                if self._risk_priority(url_result.risk_level) > self._risk_priority(max_risk):
                    max_risk = url_result.risk_level

        if threat_urls:
            logger.warning(
                f"[ThreatIntel] 检测到 {len(threat_urls)} 个可疑 URL: "
                f"{', '.join(threat_urls)}"
            )
            return ThreatResult(
                is_threat=True,
                threat_type="phishing",
                risk_level=max_risk,
                matched_urls=threat_urls,
                details="; ".join(details_parts),
            )

        return ThreatResult(is_threat=False)

    def _analyze_url(self, url: str) -> ThreatResult:
        """分析单个 URL 的安全性"""
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
        except Exception:
            return ThreatResult(is_threat=False)

        hostname = parsed.hostname or ""
        checks: list[ThreatResult] = []

        # 1. IP 直连检测
        if IP_URL_PATTERN.match(url):
            checks.append(ThreatResult(
                is_threat=True,
                threat_type="suspicious_url",
                risk_level="medium",
                details=f"IP 直连 URL: {url}",
            ))

        # 2. 已知钓鱼域名模式
        for pattern in KNOWN_PHISHING_PATTERNS:
            if pattern.search(hostname) or pattern.search(url):
                checks.append(ThreatResult(
                    is_threat=True,
                    threat_type="phishing",
                    risk_level="high",
                    details=f"匹配钓鱼模式: {pattern.pattern[:50]}...",
                ))
                break

        # 3. 自定义钓鱼域名
        if hostname in self.custom_phishing_domains:
            checks.append(ThreatResult(
                is_threat=True,
                threat_type="phishing",
                risk_level="critical",
                details=f"匹配自定义钓鱼域名: {hostname}",
            ))

        # 4. 可疑 TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                checks.append(ThreatResult(
                    is_threat=True,
                    threat_type="suspicious_url",
                    risk_level="low",
                    details=f"可疑顶级域名: {tld}",
                ))
                break

        # 5. 超长子域名（通常用于钓鱼）
        subdomain_count = hostname.count(".")
        if subdomain_count >= 4:
            checks.append(ThreatResult(
                is_threat=True,
                threat_type="suspicious_url",
                risk_level="medium",
                details=f"超长子域名 ({subdomain_count} 级): {hostname}",
            ))

        # 6. Unicode 混淆字符检测 (同形攻击)
        homoglyph_detected = any(c in HOMOGLYPH_MAP for c in hostname)
        if homoglyph_detected:
            checks.append(ThreatResult(
                is_threat=True,
                threat_type="phishing",
                risk_level="high",
                details=f"检测到 Unicode 同形字符混淆: {hostname}",
            ))

        # 综合判定：取最高风险
        if checks:
            highest = max(checks, key=lambda r: self._risk_priority(r.risk_level))
            highest.matched_urls = [url]
            return highest

        return ThreatResult(is_threat=False)

    @staticmethod
    def _risk_priority(level: str) -> int:
        """风险等级优先级排序"""
        return {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
            level, 0
        )

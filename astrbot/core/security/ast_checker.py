"""基于 AST 的工具参数安全检查器

对工具调用参数进行静态分析，阻断代码注入、路径遍历和 Shell 命令注入等攻击。
采用 Python ast 模块解析参数字符串，检测危险的 AST 节点模式。
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

import logging

logger = logging.getLogger("astrbot.core.security.ast_checker")


@dataclass
class ASTCheckResult:
    """AST 安全检查结果"""

    safe: bool
    reason: str = ""
    risk_level: str = "none"  # none, low, medium, high, critical
    matched_patterns: list[str] = field(default_factory=list)


# 危险的内置函数和模块
DANGEROUS_BUILTINS = frozenset({
    "eval", "exec", "compile", "execfile",
    "__import__", "getattr", "setattr", "delattr",
    "globals", "locals", "vars", "dir",
    "open",  # 文件操作
    "input",  # 可能用于社工
})

# 危险的模块名
DANGEROUS_MODULES = frozenset({
    "os", "sys", "subprocess", "shutil",
    "importlib", "ctypes", "socket", "http",
    "requests", "urllib", "pathlib",
    "pickle", "shelve", "marshal",
    "code", "codeop", "compileall",
    "signal", "multiprocessing", "threading",
})

# 危险的属性访问模式
DANGEROUS_ATTRIBUTES = frozenset({
    "__builtins__", "__class__", "__subclasses__",
    "__globals__", "__code__", "__import__",
    "__dict__", "__bases__", "__mro__",
    "__qualname__", "__module__",
    "system", "popen", "exec", "spawn",
    "call", "check_output", "run",  # subprocess 相关
})

# Shell 注入模式
SHELL_INJECTION_PATTERNS = [
    re.compile(r";\s*\w+"),           # 命令链接: ; rm -rf
    re.compile(r"\|\s*\w+"),          # 管道: | cat /etc/passwd
    re.compile(r"\$\(.*\)"),          # 命令替换: $(whoami)
    re.compile(r"`.*`"),              # 反引号命令替换
    re.compile(r"&&\s*\w+"),          # 逻辑与链接
    re.compile(r"\|\|\s*\w+"),        # 逻辑或链接
    re.compile(r">\s*/"),              # 输出重定向到绝对路径
]

# 路径遍历模式
PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),             # 相对路径遍历
    re.compile(r"\.\\.\\"),           # Windows 路径遍历
    re.compile(r"^/etc/"),            # 敏感 Linux 路径
    re.compile(r"^/proc/"),           # proc 文件系统
    re.compile(r"^/dev/"),            # 设备文件
    re.compile(r"^C:\\Windows", re.IGNORECASE),   # Windows 系统目录
    re.compile(r"^C:\\System32", re.IGNORECASE),
    re.compile(r"%[A-Za-z]+%"),       # Windows 环境变量路径
]


class ASTSafetyChecker:
    """基于 AST 的工具参数安全检查器

    通过解析工具参数字符串并分析其 AST 结构，
    检测代码注入、路径遍历、Shell 命令注入等安全威胁。
    """

    def __init__(
        self,
        *,
        enable_ast_analysis: bool = True,
        enable_shell_check: bool = True,
        enable_path_check: bool = True,
        custom_dangerous_patterns: list[str] | None = None,
    ) -> None:
        self.enable_ast_analysis = enable_ast_analysis
        self.enable_shell_check = enable_shell_check
        self.enable_path_check = enable_path_check
        self.custom_patterns = [
            re.compile(p) for p in (custom_dangerous_patterns or [])
        ]

    def check_tool_args(
        self, tool_name: str, args: dict
    ) -> ASTCheckResult:
        """检查工具调用参数的安全性

        Args:
            tool_name: 工具名称
            args: 工具调用参数字典

        Returns:
            ASTCheckResult: 安全检查结果
        """
        matched_patterns: list[str] = []

        for key, value in args.items():
            if not isinstance(value, str):
                continue

            # 1. AST 分析 - 检测代码注入
            if self.enable_ast_analysis:
                ast_result = self._check_ast_injection(value)
                if not ast_result.safe:
                    logger.warning(
                        f"[ASTChecker] 工具 {tool_name} 参数 {key} "
                        f"检测到代码注入: {ast_result.reason}"
                    )
                    return ast_result

            # 2. Shell 命令注入检测
            if self.enable_shell_check:
                shell_result = self._check_shell_injection(value)
                if not shell_result.safe:
                    logger.warning(
                        f"[ASTChecker] 工具 {tool_name} 参数 {key} "
                        f"检测到 Shell 注入: {shell_result.reason}"
                    )
                    return shell_result

            # 3. 路径遍历检测
            if self.enable_path_check:
                path_result = self._check_path_traversal(value)
                if not path_result.safe:
                    logger.warning(
                        f"[ASTChecker] 工具 {tool_name} 参数 {key} "
                        f"检测到路径遍历: {path_result.reason}"
                    )
                    return path_result

            # 4. 自定义模式检测
            for pattern in self.custom_patterns:
                if pattern.search(value):
                    matched_patterns.append(pattern.pattern)

        if matched_patterns:
            return ASTCheckResult(
                safe=False,
                reason=f"匹配到自定义危险模式: {', '.join(matched_patterns)}",
                risk_level="high",
                matched_patterns=matched_patterns,
            )

        return ASTCheckResult(safe=True, risk_level="none")

    def _check_ast_injection(self, value: str) -> ASTCheckResult:
        """使用 AST 分析检测代码注入

        尝试将字符串解析为 Python AST，
        如果成功且包含危险节点则判定为注入攻击。
        """
        try:
            tree = ast.parse(value, mode="exec")
        except SyntaxError:
            # 无法解析为 Python 代码，不是代码注入，放行
            return ASTCheckResult(safe=True)

        # 遍历 AST 节点，检测危险模式
        dangerous_nodes: list[str] = []

        for node in ast.walk(tree):
            # 检测危险函数调用: eval(), exec(), __import__() 等
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name and func_name in DANGEROUS_BUILTINS:
                    dangerous_nodes.append(f"危险函数调用: {func_name}()")

            # 检测 import 语句
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in DANGEROUS_MODULES:
                        dangerous_nodes.append(f"危险模块导入: import {alias.name}")

            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in DANGEROUS_MODULES:
                    dangerous_nodes.append(f"危险模块导入: from {node.module}")

            # 检测危险属性访问: obj.__builtins__, obj.__class__ 等
            elif isinstance(node, ast.Attribute):
                if node.attr in DANGEROUS_ATTRIBUTES:
                    dangerous_nodes.append(f"危险属性访问: .{node.attr}")

        if dangerous_nodes:
            return ASTCheckResult(
                safe=False,
                reason=f"AST 分析检测到危险节点: {'; '.join(dangerous_nodes)}",
                risk_level="critical",
                matched_patterns=dangerous_nodes,
            )

        # 检查是否包含多条语句（可能是注入的代码块）
        if len(tree.body) > 1:
            # 多条独立语句，可能是注入代码块
            stmt_types = [type(s).__name__ for s in tree.body]
            # 但如果只是简单的表达式（如 "hello world" 被分割），则放行
            if not all(isinstance(s, ast.Expr) for s in tree.body):
                return ASTCheckResult(
                    safe=False,
                    reason=f"检测到多语句代码块 ({', '.join(stmt_types)}), 疑似代码注入",
                    risk_level="high",
                    matched_patterns=[f"multi_statement:{','.join(stmt_types)}"],
                )

        return ASTCheckResult(safe=True)

    def _check_shell_injection(self, value: str) -> ASTCheckResult:
        """检测 Shell 命令注入模式"""
        matched: list[str] = []
        for pattern in SHELL_INJECTION_PATTERNS:
            if pattern.search(value):
                matched.append(pattern.pattern)

        if matched:
            return ASTCheckResult(
                safe=False,
                reason=f"检测到 Shell 命令注入模式: {', '.join(matched)}",
                risk_level="high",
                matched_patterns=matched,
            )
        return ASTCheckResult(safe=True)

    def _check_path_traversal(self, value: str) -> ASTCheckResult:
        """检测路径遍历攻击"""
        matched: list[str] = []
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern.search(value):
                matched.append(pattern.pattern)

        if matched:
            return ASTCheckResult(
                safe=False,
                reason=f"检测到路径遍历模式: {', '.join(matched)}",
                risk_level="high",
                matched_patterns=matched,
            )
        return ASTCheckResult(safe=True)

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        """从 ast.Call 节点提取函数名"""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

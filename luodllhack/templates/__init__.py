# -*- coding: utf-8 -*-
"""
luodllhack/templates/__init__.py - 统一模板引擎

提供代码生成的模板管理系统:
- Jinja2 模板渲染
- 内置模板和外部模板支持
- 模板缓存和验证
"""

from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

# 模板目录
TEMPLATE_DIR = Path(__file__).parent

# Jinja2 支持
try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape, BaseLoader, TemplateNotFound
    HAVE_JINJA2 = True
except ImportError:
    HAVE_JINJA2 = False
    Environment = None


class StringLoader(BaseLoader if HAVE_JINJA2 else object):
    """从字典加载模板字符串"""

    def __init__(self, templates: Dict[str, str]):
        self.templates = templates

    def get_source(self, environment, template):
        if template in self.templates:
            source = self.templates[template]
            return source, template, lambda: True
        raise TemplateNotFound(template)


class TemplateEngine:
    """
    统一模板引擎

    支持两种模式:
    1. Jinja2 模式 (推荐): 功能完整，支持继承、宏、过滤器
    2. 简单模式: 使用 str.format()，无外部依赖

    用法:
        engine = TemplateEngine()

        # 从文件加载
        code = engine.render('poc/buffer_overflow.py.j2', context)

        # 从字符串加载
        code = engine.render_string(template_str, context)
    """

    def __init__(self, template_dir: Path = None, use_jinja2: bool = True):
        """
        初始化模板引擎

        Args:
            template_dir: 模板目录路径
            use_jinja2: 是否使用 Jinja2 (需要安装)
        """
        self.template_dir = template_dir or TEMPLATE_DIR
        self.use_jinja2 = use_jinja2 and HAVE_JINJA2
        self._env = None
        self._string_templates: Dict[str, str] = {}

        if self.use_jinja2:
            self._init_jinja2()
        else:
            logger.info("Jinja2 not available, using simple template mode")

    def _init_jinja2(self):
        """初始化 Jinja2 环境"""
        self._env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )

        # 添加自定义过滤器
        self._env.filters['hex'] = lambda x: f'0x{x:x}' if isinstance(x, int) else x
        self._env.filters['hexbytes'] = self._hexbytes_filter
        self._env.filters['escape_string'] = self._escape_string_filter

    @staticmethod
    def _hexbytes_filter(data: bytes, per_line: int = 16) -> str:
        """将 bytes 转换为 C 风格十六进制数组"""
        if not data:
            return ''
        lines = []
        for i in range(0, len(data), per_line):
            chunk = data[i:i + per_line]
            hex_str = ', '.join(f'0x{b:02x}' for b in chunk)
            lines.append(f'    {hex_str},')
        return '\n'.join(lines)

    @staticmethod
    def _escape_string_filter(s: str) -> str:
        """转义字符串中的特殊字符"""
        return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')

    def render(self, template_name: str, context: Dict[str, Any]) -> str:
        """
        渲染模板文件

        Args:
            template_name: 模板文件名 (相对于 template_dir)
            context: 模板上下文变量

        Returns:
            渲染后的字符串
        """
        if self.use_jinja2:
            try:
                template = self._env.get_template(template_name)
                return template.render(**context)
            except Exception as e:
                logger.error(f"Template render error: {e}")
                raise
        else:
            # 简单模式: 读取文件并使用 format
            template_path = self.template_dir / template_name
            if template_path.exists():
                template_str = template_path.read_text(encoding='utf-8')
                return self._simple_render(template_str, context)
            raise FileNotFoundError(f"Template not found: {template_name}")

    def render_string(self, template_str: str, context: Dict[str, Any]) -> str:
        """
        渲染模板字符串

        Args:
            template_str: 模板字符串
            context: 模板上下文变量

        Returns:
            渲染后的字符串
        """
        if self.use_jinja2:
            # 使用已配置的环境来编译模板，这样过滤器就可用了
            template = self._env.from_string(template_str)
            return template.render(**context)
        else:
            return self._simple_render(template_str, context)

    def _simple_render(self, template_str: str, context: Dict[str, Any]) -> str:
        """简单模式渲染 (使用 str.format)"""
        try:
            # 将 Jinja2 语法转换为 format 语法的简单替换
            # {{ var }} -> {var}
            import re
            simple_template = re.sub(r'\{\{\s*(\w+)\s*\}\}', r'{\1}', template_str)
            # 移除 Jinja2 控制语句 (简单模式不支持)
            simple_template = re.sub(r'\{%.*?%\}', '', simple_template)
            return simple_template.format(**context)
        except KeyError as e:
            logger.error(f"Missing template variable: {e}")
            raise

    def register_string_template(self, name: str, template: str):
        """注册字符串模板"""
        self._string_templates[name] = template

    def list_templates(self) -> list:
        """列出所有可用模板"""
        templates = []
        if self.template_dir.exists():
            for f in self.template_dir.rglob('*.j2'):
                templates.append(str(f.relative_to(self.template_dir)))
        return sorted(templates)


# 全局模板引擎实例
_engine: Optional[TemplateEngine] = None


def get_engine() -> TemplateEngine:
    """获取全局模板引擎实例"""
    global _engine
    if _engine is None:
        _engine = TemplateEngine()
    return _engine


def render(template_name: str, **context) -> str:
    """快捷渲染函数"""
    return get_engine().render(template_name, context)


def render_string(template_str: str, **context) -> str:
    """快捷字符串渲染函数"""
    return get_engine().render_string(template_str, context)

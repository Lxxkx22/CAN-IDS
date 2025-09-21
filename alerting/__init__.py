"""
告警模块

提供CAN总线入侵检测系统的告警管理功能，包括：
- 告警生成和格式化
- 告警限流和去重
- 告警日志记录
- 告警统计分析
"""

from .alert_manager import AlertManager

__all__ = ['AlertManager']
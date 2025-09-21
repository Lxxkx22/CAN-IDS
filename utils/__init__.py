"""
工具模块

提供CAN总线入侵检测系统的通用工具函数，包括：
- 数学计算工具（熵、统计）
- 数据处理工具（哈希、批处理）
- 系统监控工具（内存监控）
- 错误处理工具
"""

from .helpers import (
    calculate_entropy,
    hash_payload,
    calculate_stats,
    is_entropy_anomaly,
)

__all__ = [
    'calculate_entropy',
    'hash_payload',
    'calculate_stats',
    'is_entropy_anomaly',
]
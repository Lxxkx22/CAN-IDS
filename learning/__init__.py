"""
学习模块

提供CAN总线数据的基线学习功能，包括：
- 统计基线计算
- 字节行为模式分析
- 熵参数学习
- DLC学习
"""

from .baseline_engine import BaselineEngine

__all__ = ['BaselineEngine']
"""
检测模块

提供各种CAN总线攻击检测功能，包括：
- 丢包攻击检测
- 篡改攻击检测
- 重放攻击检测
- 通用规则检测
- 状态管理
"""

from .state_manager import StateManager
from .base_detector import BaseDetector, Alert
from .drop_detector import DropDetector
from .tamper_detector import TamperDetector
from .replay_detector import ReplayDetector
from .general_rules_detector import GeneralRulesDetector

__all__ = [
    'StateManager',
    'BaseDetector',
    'Alert',
    'DropDetector',
    'TamperDetector',
    'ReplayDetector',
    'GeneralRulesDetector'
]
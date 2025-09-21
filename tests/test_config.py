"""测试配置模块

提供测试用的配置管理器和模拟数据
"""

import time
from typing import Dict, Any, List, Optional
from unittest.mock import Mock


class MockConfigManager:
    """模拟配置管理器，用于测试"""
    
    def __init__(self):
        self.config_data = {
            'detection': {
                'enabled': True,
                'detectors': {
                    'drop': {
                        'enabled': True,
                        'iat_sigma_threshold': 3.0,
                        'consecutive_missing_threshold': 3,
                        'max_iat_factor': 5.0,
                        'dlc_zero_special_handling': True
                    },
                    'tamper': {
                        'enabled': True,
                        'entropy_threshold': 6.0,
                        'payload_analysis_min_dlc': 1,
                        'byte_change_ratio_threshold': 0.5,
                        'static_byte_tolerance': 0.1
                    },
                    'replay': {
                        'enabled': True,
                        'fast_replay_threshold': 0.001,
                        'identical_payload_threshold': 5,
                        'sequence_length': 5,
                        'sequence_threshold': 3,
                        'min_iat_factor_for_fast_replay': 0.3,
                        'absolute_min_iat_ms': 1.0,
                        'sequence_replay_params': {
                            'enabled': True,
                            'sequence_length': 3,
                            'max_sequence_age_sec': 300,
                            'min_interval_between_sequences_sec': 0.1
                        }
                    },
                    'general_rules': {
                        'enabled': True,
                        'detect_unknown_id': {
                            'enabled': True,
                            'learning_mode': 'alert_immediate',
                            'shadow_duration_sec': 30,
                            'auto_add_to_baseline': True,
                            'min_frames_for_learning': 10
                        }
                    }
                }
            },
            'learning': {
                'baseline': {
                    '123': {
                        'iat_stats': {
                            'mean': 0.1,
                            'std': 0.01,
                            'min': 0.08,
                            'max': 0.15
                        },
                        'learned_dlcs': [8],
                        'entropy_stats': {
                            'mean': 4.5,
                            'std': 0.5
                        },
                        'byte_behavior': {
                            '0': {'type': 'static', 'expected_value': 0x01},
                            '1': {'type': 'counter', 'min': 0, 'max': 255},
                            '2': {'type': 'dynamic'}
                        },
                        'periodicity_baseline': {
                            'dominant_periods': [0.1, 0.2],
                            'period_tolerances': [0.01, 0.02],
                            'confidence_scores': [0.9, 0.8]
                        }
                    },
                    '456': {
                        'iat_stats': {
                            'mean': 0.05,
                            'std': 0.005,
                            'min': 0.04,
                            'max': 0.08
                        },
                        'learned_dlcs': [4, 8],
                        'entropy_stats': {
                            'mean': 3.2,
                            'std': 0.3
                        }
                    }
                }
            }
        }
        
        self.known_ids = {'123', '456', '789'}
        self.observers = []
        self.config_version = 1
    
    def get_config_version(self) -> int:
        """获取配置版本号"""
        return self.config_version
    
    def add_observer(self, observer):
        """添加配置变更观察者"""
        self.observers.append(observer)
    
    def is_known_id(self, can_id: str) -> bool:
        """检查ID是否已知"""
        return can_id in self.known_ids
    
    def add_known_id(self, can_id: str) -> bool:
        """添加已知ID"""
        if can_id not in self.known_ids:
            self.known_ids.add(can_id)
            return True
        return False
    
    def get_detection_config(self, can_id: str, detector_type: str) -> Dict[str, Any]:
        """获取检测配置"""
        return self.config_data.get('detection', {}).get('detectors', {}).get(detector_type, {})
    
    def get_baseline_data(self, can_id: str) -> Optional[Dict[str, Any]]:
        """获取基线数据"""
        return self.config_data.get('learning', {}).get('baseline', {}).get(can_id)
    
    def get_learned_iat_stats(self, can_id: str) -> Optional[Dict[str, float]]:
        """获取学习到的IAT统计数据"""
        baseline = self.get_baseline_data(can_id)
        return baseline.get('iat_stats') if baseline else None
    
    def get_learned_dlcs(self, can_id: str) -> List[int]:
        """获取学习到的DLC列表"""
        baseline = self.get_baseline_data(can_id)
        return baseline.get('learned_dlcs', []) if baseline else []
    
    def get_entropy_stats(self, can_id: str) -> Optional[Dict[str, float]]:
        """获取熵统计数据"""
        baseline = self.get_baseline_data(can_id)
        return baseline.get('entropy_stats') if baseline else None
    
    def get_byte_behavior(self, can_id: str) -> Dict[str, Dict[str, Any]]:
        """获取字节行为数据"""
        baseline = self.get_baseline_data(can_id)
        return baseline.get('byte_behavior', {}) if baseline else {}
    
    def get_effective_setting(self, can_id: str, section: str, key: str):
        """获取有效配置设置"""
        # 首先尝试从检测器配置中获取
        detector_config = self.config_data.get('detection', {}).get('detectors', {}).get(section, {})
        
        # 处理嵌套键（如 detect_unknown_id.enabled）
        if '.' in key:
            keys = key.split('.')
            value = detector_config
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    break
            else:
                return value
        elif key in detector_config:
            return detector_config[key]
        
        # 对于已知ID，尝试从learned data中获取
        # 处理CAN ID格式（移除0x前缀进行查找）
        lookup_id = can_id.replace('0x', '') if can_id and can_id.startswith('0x') else can_id
        
        if self.is_known_id(lookup_id):
            baseline = self.get_baseline_data(lookup_id)
            if baseline:
                # 处理drop检测器的学习数据映射
                if section == 'drop':
                    iat_stats = baseline.get('iat_stats', {})
                    if key == 'learned_mean_iat':
                        return iat_stats.get('mean')
                    elif key == 'learned_std_iat':
                        return iat_stats.get('std')
                    elif key == 'learned_median_iat':
                        # 如果没有median，使用mean作为近似
                        return iat_stats.get('median', iat_stats.get('mean'))
                    elif key == 'min_iat':
                        return iat_stats.get('min')
                    elif key == 'max_iat':
                        return iat_stats.get('max')
                
                # 处理tamper检测器的学习数据映射
                if section == 'tamper':
                    if key == 'entropy_params':
                        return baseline.get('entropy_stats', {})
                    elif key == 'byte_behavior':
                        return baseline.get('byte_behavior', {})
                
                # 直接查找键
                if key in baseline:
                    return baseline[key]
        
        # 如果是未知的检测器类型，抛出异常
        if section not in self.config_data.get('detection', {}).get('detectors', {}):
            raise KeyError(f"Unknown detector type: {section}")
        
        # 如果键不存在，抛出异常
        raise KeyError(f"Key {key} not found in section {section}")
    
    def remove_observer(self, observer):
        """移除配置变更观察者"""
        if observer in self.observers:
            self.observers.remove(observer)
    
    def get_id_specific_setting(self, can_id: str, section: str, key: str, default=None):
        """获取ID特定设置
        
        Args:
            can_id: CAN ID
            section: 设置节名
            key: 设置键名
            default: 默认值
            
        Returns:
            设置值或默认值
        """
        # 对于测试，我们简单地返回默认值或从检测器配置中获取
        try:
            return self.get_effective_setting(can_id, section, key)
        except KeyError as e:
            # 对于未知检测器类型的enabled键，返回False
            if key == 'enabled' and 'Unknown detector type' in str(e):
                return False
            return default
    
    def get_config_value(self, can_id: str, section: str, key: str, default=None):
        """获取配置值（兼容BaseDetector的_get_config_value方法）"""
        try:
            # 如果是learned_dlcs，从baseline数据中获取
            if key == 'learned_dlcs':
                baseline = self.get_baseline_data(can_id)
                if baseline and 'learned_dlcs' in baseline:
                    return baseline['learned_dlcs']
                return default if default is not None else []
            
            # 如果是periodicity_baseline，从baseline数据中获取
            if key == 'periodicity_baseline':
                baseline = self.get_baseline_data(can_id)
                if baseline and 'periodicity_baseline' in baseline:
                    return baseline['periodicity_baseline']
                return default
            
            # 其他配置从检测器配置中获取
            return self.get_effective_setting(can_id, section, key)
        except KeyError:
            return default


def create_mock_baseline_engine():
    """创建模拟基线引擎"""
    mock_engine = Mock()
    mock_engine.add_frame_to_shadow_learning = Mock()
    mock_engine.should_auto_add_id = Mock(return_value=False)
    mock_engine.auto_add_id_to_baseline = Mock()
    return mock_engine


def get_test_config_manager() -> MockConfigManager:
    """获取测试用配置管理器"""
    return MockConfigManager()
"""测试配置设置

包含所有测试的配置参数和设置
"""

import os
from typing import Dict, Any

# 测试数据目录
TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), 'test_data')

# 测试输出目录
TEST_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'test_output')

# 确保测试目录存在
os.makedirs(TEST_DATA_DIR, exist_ok=True)
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

# 默认测试配置
DEFAULT_TEST_CONFIG = {
    # 丢包检测配置
    'drop_detection': {
        'enabled': True,
        'iat_threshold_factor': 3.0,
        'max_iat_factor': 10.0,
        'min_samples_for_learning': 10,
        'consecutive_loss_threshold': 3,
        'memory_pressure_mode': False
    },
    
    # 篡改检测配置
    'tamper_detection': {
        'enabled': True,
        'dlc_check_enabled': True,
        'entropy_check_enabled': True,
        'byte_behavior_check_enabled': True,
        'byte_change_rate_check_enabled': True,
        'entropy_threshold': 0.5,
        'byte_change_rate_threshold': 0.3,
        'min_payload_size_for_analysis': 2,
        'memory_pressure_mode': False
    },
    
    # 重放检测配置
    'replay_detection': {
        'enabled': True,
        'fast_replay_enabled': True,
        'enhanced_fast_replay_enabled': True,
        'context_payload_repeat_enabled': True,
        'sequence_replay_enabled': True,
        'fast_replay_threshold': 3,
        'enhanced_fast_replay_threshold': 2,
        'context_payload_repeat_threshold': 5,
        'sequence_replay_threshold': 3,
        'payload_history_size': 10,
        'sequence_buffer_size': 20,
        'sequence_pattern_min_length': 3,
        'periodicity_cache_size': 100,
        'periodicity_cleanup_interval': 300,
        'memory_pressure_mode': False
    },
    
    # 通用规则检测配置
    'general_rules_detection': {
        'enabled': True,
        'unknown_id_detection_enabled': True,
        'shadow_learning_enabled': False,
        'auto_add_threshold': 10,
        'memory_pressure_mode': False
    },
    
    # 全局配置
    'global': {
        'config_cache_ttl': 60,
        'memory_pressure_threshold': 0.8,
        'max_alerts_per_frame': 10
    }
}

# 性能测试配置
PERFORMANCE_TEST_CONFIG = {
    'small_dataset_size': 100,
    'medium_dataset_size': 1000,
    'large_dataset_size': 10000,
    'max_processing_time_per_frame': 0.001,  # 1ms
    'min_frames_per_second': 1000,
    'memory_growth_threshold': 1024 * 1024,  # 1MB
}

# 攻击模拟配置
ATTACK_SIMULATION_CONFIG = {
    'drop_attack': {
        'normal_interval': 0.1,
        'attack_interval_multiplier': 5.0,
        'missing_frame_ratio': 0.3
    },
    
    'tamper_attack': {
        'dlc_change_probability': 0.5,
        'payload_change_probability': 0.8,
        'entropy_increase_factor': 2.0,
        'byte_change_rate': 0.5
    },
    
    'replay_attack': {
        'immediate_replay_probability': 0.3,
        'delayed_replay_probability': 0.4,
        'sequence_replay_probability': 0.3,
        'replay_delay_range': (0.001, 0.1)
    },
    
    'unknown_id_attack': {
        'unknown_id_probability': 1.0,
        'payload_randomness': True
    }
}

# 测试CAN ID配置
TEST_CAN_IDS = {
    'known_ids': ['123', '456', '789', 'ABC', 'DEF'],
    'unknown_ids': ['999', 'XXX', 'ZZZ', '000'],
    'high_frequency_ids': ['123', '456'],
    'low_frequency_ids': ['789', 'ABC'],
    'periodic_ids': ['123'],
    'aperiodic_ids': ['999']
}

# 测试载荷模式
TEST_PAYLOAD_PATTERNS = {
    'static': b'\x01\x02\x03\x04',
    'counter': lambda i: (i % 256).to_bytes(1, 'big') * 4,
    'random': lambda: os.urandom(4),
    'alternating': lambda i: b'\xAA\x55' * 2 if i % 2 == 0 else b'\x55\xAA' * 2,
    'increasing': lambda i: ((i % 256) + j for j in range(4)),
    'high_entropy': lambda: os.urandom(8),
    'low_entropy': b'\x00\x00\x00\x00'
}

# 基线引擎模拟数据
MOCK_BASELINE_DATA = {
    '123': {
        'iat_stats': {
            'mean': 0.1,
            'std': 0.01,
            'min': 0.09,
            'max': 0.11,
            'count': 100
        },
        'dlc_stats': {
            'mode': 8,
            'valid_dlcs': [8],
            'count': 100
        },
        'payload_stats': {
            'entropy_mean': 0.3,
            'entropy_std': 0.05,
            'byte_behaviors': {
                0: 'static',
                1: 'counter',
                2: 'static',
                3: 'static'
            },
            'common_payloads': [
                b'\x01\x02\x03\x04',
                b'\x01\x03\x03\x04',
                b'\x01\x04\x03\x04'
            ]
        },
        'periodicity': {
            'is_periodic': True,
            'period': 0.1,
            'confidence': 0.95
        }
    },
    '456': {
        'iat_stats': {
            'mean': 0.2,
            'std': 0.02,
            'min': 0.18,
            'max': 0.22,
            'count': 50
        },
        'dlc_stats': {
            'mode': 4,
            'valid_dlcs': [4],
            'count': 50
        },
        'payload_stats': {
            'entropy_mean': 0.8,
            'entropy_std': 0.1,
            'byte_behaviors': {
                0: 'counter',
                1: 'counter',
                2: 'random',
                3: 'random'
            },
            'common_payloads': [
                b'\x00\x01\xAA\x55',
                b'\x01\x02\xBB\x66',
                b'\x02\x03\xCC\x77'
            ]
        },
        'periodicity': {
            'is_periodic': False,
            'period': None,
            'confidence': 0.1
        }
    }
}

# 测试断言配置
TEST_ASSERTIONS = {
    'tolerance': {
        'time_tolerance': 0.001,  # 1ms
        'float_tolerance': 1e-6,
        'percentage_tolerance': 0.01  # 1%
    },
    'timeouts': {
        'default_timeout': 5.0,  # 5秒
        'performance_timeout': 10.0,  # 10秒
        'integration_timeout': 30.0  # 30秒
    },
    'limits': {
        'max_alerts_per_test': 1000,
        'max_memory_usage_mb': 100,
        'max_test_duration': 60.0
    }
}

# 日志配置
LOGGING_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file_logging': False,
    'console_logging': True
}


def get_test_config(config_name: str = 'default') -> Dict[str, Any]:
    """获取测试配置
    
    Args:
        config_name: 配置名称 ('default', 'performance', 'attack_simulation')
    
    Returns:
        配置字典
    """
    if config_name == 'default':
        return DEFAULT_TEST_CONFIG.copy()
    elif config_name == 'performance':
        config = DEFAULT_TEST_CONFIG.copy()
        config.update(PERFORMANCE_TEST_CONFIG)
        return config
    elif config_name == 'attack_simulation':
        config = DEFAULT_TEST_CONFIG.copy()
        config.update(ATTACK_SIMULATION_CONFIG)
        return config
    else:
        raise ValueError(f"Unknown config name: {config_name}")


def get_mock_baseline_data(can_id: str) -> Dict[str, Any]:
    """获取模拟基线数据
    
    Args:
        can_id: CAN ID
    
    Returns:
        基线数据字典
    """
    return MOCK_BASELINE_DATA.get(can_id, {
        'iat_stats': {'mean': 0.1, 'std': 0.01, 'count': 0},
        'dlc_stats': {'mode': 8, 'valid_dlcs': [8], 'count': 0},
        'payload_stats': {
            'entropy_mean': 0.5,
            'entropy_std': 0.1,
            'byte_behaviors': {},
            'common_payloads': []
        },
        'periodicity': {'is_periodic': False, 'period': None, 'confidence': 0.0}
    })


def create_test_directories():
    """创建测试所需的目录"""
    directories = [
        TEST_DATA_DIR,
        TEST_OUTPUT_DIR,
        os.path.join(TEST_OUTPUT_DIR, 'reports'),
        os.path.join(TEST_OUTPUT_DIR, 'logs'),
        os.path.join(TEST_OUTPUT_DIR, 'coverage')
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)


if __name__ == '__main__':
    # 创建测试目录
    create_test_directories()
    print(f"测试目录已创建:")
    print(f"  数据目录: {TEST_DATA_DIR}")
    print(f"  输出目录: {TEST_OUTPUT_DIR}")
    
    # 显示配置信息
    print(f"\n默认测试配置:")
    for category, config in DEFAULT_TEST_CONFIG.items():
        print(f"  {category}: {len(config)} 个配置项")
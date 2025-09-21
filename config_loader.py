import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional, Callable

# 配置日志
logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """配置文件异常"""
    pass


class ConfigManager:
    """配置管理器"""

    def __init__(self, filepath: str):
        """
        初始化配置管理器

        Args:
            filepath: 配置文件路径
        """
        self.filepath = filepath
        self.config = {}
        self.validation_errors = []
        self._load_config(filepath)
        self._validate_config()

        # 缓存已知ID列表
        self._known_ids = set(self.config.get('ids', {}).keys())
        
        # 配置变更观察者列表
        self._observers = []
        
        # 配置更新锁
        self._update_lock = threading.RLock()
        
        # 配置变更计数器（用于缓存失效）
        self._config_version = 0

    def _load_config(self, filepath: str):
        """
        加载配置文件

        Args:
            filepath: 配置文件路径
        """
        try:
            if not os.path.exists(filepath):
                raise ConfigError(f"Configuration file not found: {filepath}")

            with open(filepath, 'r', encoding='utf-8') as f:
                self.config = json.load(f)

            logger.info(f"Configuration loaded from {filepath}")

        except FileNotFoundError:
            raise ConfigError(f"Configuration file not found: {filepath}")
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in configuration file: {e}")
        except Exception as e:
            raise ConfigError(f"Error loading configuration: {e}")

    def _validate_config(self):
        """验证配置文件结构"""
        required_sections = ['global_settings', 'ids']

        for section in required_sections:
            if section not in self.config:
                logger.warning(f"Missing required section: {section}")
                self.config[section] = {}

        # 验证全局设置必需的子节
        global_settings = self.config['global_settings']
        required_global_sections = ['learning_params', 'drop', 'tamper', 'replay', 'throttle']

        for section in required_global_sections:
            if section not in global_settings:
                logger.warning(f"Missing global settings section: {section}")
                global_settings[section] = {}

        # 设置默认值
        self._set_defaults()
        
        # 验证配置
        self._validate_config_values()
        
        if self.validation_errors:
            logger.warning(f"Configuration validation found {len(self.validation_errors)} issues:")
            for error in self.validation_errors:
                logger.warning(f"  - {error}")

        logger.info("Configuration validation completed")

    def _set_defaults(self):
        """设置默认配置值"""
        defaults = {
            'global_settings': {
                'learning_params': {
                    'initial_learning_window_sec': 60,
                    'baseline_update_interval_sec': 15,
                    'min_samples_for_stable_baseline': 5
                },
                'drop': {
                    'missing_frame_sigma': 3.5,
                    'consecutive_missing_allowed': 2,
                    'max_iat_factor': 2.5,
                    'treat_dlc_zero_as_special': True
                },
                'tamper': {
                    'dlc_learning_mode': 'strict_whitelist',
                    'payload_analysis_min_dlc': 1,
                    'entropy_params': {
                        'enabled': True,
                        'learning_mode': 'per_id_baseline',
                        'sigma_threshold': 3.0
                    },
                    'byte_behavior_params': {
                        'enabled': True,
                        'learning_window_min_changes_for_variable': 5,
                        'static_byte_mismatch_threshold': 1,
                        'counter_byte_params': {
                            'detect_simple_counters': True,
                            'max_value_before_rollover_guess': 255,
                            'allowed_counter_skips': 1
                        }
                    },
                    'byte_change_ratio_threshold': 0.85
                },
                'replay': {
                    'min_iat_factor_for_fast_replay': 0.3,
                    'absolute_min_iat_ms': 0.2,
                    'identical_payload_params': {
                        'enabled': True,
                        'time_window_ms': 1000,
                        'repetition_threshold': 4
                    },
                    'sequence_replay_params': {
                        'enabled': True,
                        'sequence_length': 5,
                        'max_sequence_age_sec': 300,
                        'min_interval_between_sequences_sec': 10
                    }
                },
                'throttle': {
                    'max_alerts_per_id_per_sec': 3,
                    'global_max_alerts_per_sec': 20,
                    'cooldown_ms': 250
                }
            },
            'general_rules': {
                'detect_unknown_id': {
                    'enabled': True,
                    'learning_mode': 'shadow',
                    'shadow_duration_sec': 600,
                    'auto_add_to_baseline': True
                }
            }
        }

        # 递归合并默认值
        self._merge_defaults(self.config, defaults)

    def _merge_defaults(self, config: dict, defaults: dict):
        """递归合并默认配置（增强类型安全）"""
        for key, value in defaults.items():
            if key not in config:
                config[key] = value
            elif isinstance(value, dict):
                if isinstance(config[key], dict):
                    self._merge_defaults(config[key], value)
                else:
                    # 类型不匹配，记录警告并使用默认值
                    logger.warning(f"Type mismatch for config key '{key}': expected dict, got {type(config[key])}. Using default.")
                    config[key] = value
            else:
                # 对于非字典类型，检查类型兼容性
                if not self._is_type_compatible(config[key], value):
                    logger.warning(f"Type mismatch for config key '{key}': expected {type(value)}, got {type(config[key])}. Using default.")
                    config[key] = value
    
    def _is_type_compatible(self, config_value: Any, default_value: Any) -> bool:
        """检查配置值与默认值的类型兼容性"""
        # 如果类型完全相同
        if type(config_value) == type(default_value):
            return True
            
        # 数值类型之间的兼容性
        if isinstance(default_value, (int, float)) and isinstance(config_value, (int, float)):
            return True
            
        # 字符串和数值的兼容性（可以转换）
        if isinstance(default_value, (int, float)) and isinstance(config_value, str):
            try:
                float(config_value)
                return True
            except ValueError:
                return False
                
        # 布尔值的兼容性
        if isinstance(default_value, bool):
            if isinstance(config_value, str):
                return config_value.lower() in ('true', 'false', '1', '0', 'yes', 'no', 'on', 'off')
            return isinstance(config_value, (bool, int))
            
        return False
    
    def _validate_config_values(self):
        """验证配置值的有效性和一致性"""
        self.validation_errors = []
        
        # 验证全局设置
        self._validate_global_settings()
        
        # 验证ID特定设置
        self._validate_id_specific_settings()
        
        # 验证配置一致性
        self._validate_config_consistency()
    
    def _validate_global_settings(self):
        """验证全局设置"""
        global_settings = self.config.get('global_settings', {})
        
        # 验证学习参数
        learning_params = global_settings.get('learning_params', {})
        if learning_params.get('initial_learning_window_sec', 0) <= 0:
            self.validation_errors.append("initial_learning_window_sec must be positive")
        
        if learning_params.get('min_samples_for_stable_baseline', 0) <= 0:
            self.validation_errors.append("min_samples_for_stable_baseline must be positive")
        
        # 验证检测参数范围
        drop_params = global_settings.get('drop', {})
        if drop_params.get('missing_frame_sigma', 0) <= 0:
            self.validation_errors.append("missing_frame_sigma must be positive")
        
        tamper_params = global_settings.get('tamper', {})
        entropy_params = tamper_params.get('entropy_params', {})
        if entropy_params.get('sigma_threshold', 0) <= 0:
            self.validation_errors.append("entropy sigma_threshold must be positive")
        
        # 验证阈值范围
        byte_change_ratio = tamper_params.get('byte_change_ratio_threshold', 1.0)
        if not (0 < byte_change_ratio <= 1.0):
            self.validation_errors.append("byte_change_ratio_threshold must be between 0 and 1")
    
    def _validate_id_specific_settings(self):
        """验证ID特定设置"""
        ids_config = self.config.get('ids', {})
        
        for can_id, id_config in ids_config.items():
            # 验证CAN ID格式
            if not self._is_valid_can_id(can_id):
                self.validation_errors.append(f"Invalid CAN ID format: {can_id}")
            
            # 验证学习数据的一致性
            self._validate_learned_data_consistency(can_id, id_config)
    
    def _validate_config_consistency(self):
        """验证配置一致性"""
        # 检查学习参数与检测参数的一致性
        global_settings = self.config.get('global_settings', {})
        learning_params = global_settings.get('learning_params', {})
        
        learning_window = learning_params.get('initial_learning_window_sec', 60)
        update_interval = learning_params.get('baseline_update_interval_sec', 15)
        
        if update_interval >= learning_window:
            self.validation_errors.append(
                "baseline_update_interval_sec should be less than initial_learning_window_sec"
            )
    
    def _is_valid_can_id(self, can_id: str) -> bool:
        """验证CAN ID格式"""
        try:
            # 支持十六进制格式（如 "0x123"）、纯十六进制字符串（如 "018f"）和十进制格式
            if can_id.startswith('0x') or can_id.startswith('0X'):
                int(can_id, 16)
            elif all(c in '0123456789abcdefABCDEF' for c in can_id):
                # 纯十六进制字符串
                int(can_id, 16)
            else:
                # 十进制格式
                int(can_id)
            return True
        except ValueError:
            return False
    
    def _validate_learned_data_consistency(self, can_id: str, id_config: dict):
        """验证学习数据的一致性"""
        # 检查DLC学习数据
        tamper_config = id_config.get('tamper', {})
        learned_dlcs = tamper_config.get('learned_dlcs', [])
        
        if learned_dlcs:
            for dlc in learned_dlcs:
                if not isinstance(dlc, int) or dlc < 0 or dlc > 8:
                    self.validation_errors.append(
                        f"Invalid learned DLC for ID {can_id}: {dlc} (must be 0-8)"
                    )
        
        # 检查IAT统计数据
        drop_config = id_config.get('drop', {})
        learned_mean = drop_config.get('learned_mean_iat')
        learned_std = drop_config.get('learned_std_iat')
        
        if learned_mean is not None and learned_std is not None:
            if learned_mean <= 0:
                self.validation_errors.append(
                    f"Invalid learned_mean_iat for ID {can_id}: {learned_mean} (must be positive)"
                )
            if learned_std < 0:
                self.validation_errors.append(
                    f"Invalid learned_std_iat for ID {can_id}: {learned_std} (must be non-negative)"
                )

    def get_global_setting(self, section: str, key: str, default: Any = None) -> Any:
        """
        获取全局设置

        Args:
            section: 设置节名
            key: 设置键名
            default: 默认值

        Returns:
            设置值
        """
        try:
            return self.config['global_settings'][section][key]
        except KeyError:
            if default is not None:
                return default
            raise ConfigError(f"Global setting not found: {section}.{key}")

    def get_id_specific_setting(self, can_id: str, section: str, key: str, default: Any = None) -> Any:
        """
        获取ID特定设置

        Args:
            can_id: CAN ID
            section: 设置节名
            key: 设置键名
            default: 默认值

        Returns:
            设置值或None
        """
        try:
            return self.config['ids'][can_id][section][key]
        except KeyError:
            return default

    def get_effective_setting(self, can_id: str, section: str, key: str) -> Any:
        """
        获取有效设置（ID特定优先，全局后备）

        Args:
            can_id: CAN ID
            section: 设置节名
            key: 设置键名

        Returns:
            有效设置值
        """
        # 首先尝试获取ID特定设置
        id_setting = self.get_id_specific_setting(can_id, section, key)
        if id_setting is not None:
            return id_setting

        # 回退到全局设置
        try:
            return self.get_global_setting(section, key)
        except ConfigError:
            raise ConfigError(f"Setting not found in global or ID-specific config: {section}.{key}")

    def get_learned_dlcs(self, can_id: str) -> List[int]:
        """
        获取学习到的DLC列表

        Args:
            can_id: CAN ID

        Returns:
            DLC列表
        """
        return self.get_id_specific_setting(can_id, 'tamper', 'learned_dlcs', [])

    def get_byte_behavior_profiles(self, can_id: str) -> List[Dict]:
        """
        获取字节行为配置

        Args:
            can_id: CAN ID

        Returns:
            字节行为配置列表
        """
        return self.get_id_specific_setting(can_id, 'tamper', 'byte_behavior_profiles', [])

    def add_observer(self, observer: Callable[[str, str, str], None]):
        """
        添加配置变更观察者（解决问题1：配置缓存一致性）
        
        Args:
            observer: 观察者回调函数，参数为(can_id, section, key)
        """
        with self._update_lock:
            if observer not in self._observers:
                self._observers.append(observer)
    
    def remove_observer(self, observer: Callable[[str, str, str], None]):
        """
        移除配置变更观察者
        
        Args:
            observer: 要移除的观察者回调函数
        """
        with self._update_lock:
            if observer in self._observers:
                self._observers.remove(observer)
    
    def _notify_observers(self, can_id: str, section: str, key: str):
        """
        通知所有观察者配置已变更
        
        Args:
            can_id: 变更的CAN ID
            section: 变更的配置节
            key: 变更的配置键
        """
        for observer in self._observers:
            try:
                observer(can_id, section, key)
            except Exception as e:
                logger.warning(f"Observer notification failed: {e}")
    
    def get_config_version(self) -> int:
        """
        获取配置版本号（用于缓存失效检查）
        
        Returns:
            配置版本号
        """
        return self._config_version

    def update_learned_data(self, can_id: str, data_type: str, data: Any):
        """
        更新学习到的数据（带原子性保证）

        Args:
            can_id: CAN ID
            data_type: 数据类型 ('learned_dlcs', 'entropy_stats', 'byte_behavior_profiles', 'drop_stats')
            data: 要更新的数据
        """
        # 使用锁确保原子性（解决问题2）
        with self._update_lock:
            # 确保ID存在于配置中
            if can_id not in self.config['ids']:
                self.config['ids'][can_id] = {}

            # 根据数据类型更新不同的配置路径
            if data_type == 'learned_dlcs':
                if 'tamper' not in self.config['ids'][can_id]:
                    self.config['ids'][can_id]['tamper'] = {}
                self.config['ids'][can_id]['tamper']['learned_dlcs'] = data
                section = 'tamper'
                key = 'learned_dlcs'

            elif data_type == 'entropy_stats':
                if 'tamper' not in self.config['ids'][can_id]:
                    self.config['ids'][can_id]['tamper'] = {}
                if 'entropy_params' not in self.config['ids'][can_id]['tamper']:
                    self.config['ids'][can_id]['tamper']['entropy_params'] = {}

                self.config['ids'][can_id]['tamper']['entropy_params'].update(data)
                section = 'tamper'
                key = 'entropy_params'

            elif data_type == 'byte_behavior_profiles':
                if 'tamper' not in self.config['ids'][can_id]:
                    self.config['ids'][can_id]['tamper'] = {}
                self.config['ids'][can_id]['tamper']['byte_behavior_profiles'] = data
                section = 'tamper'
                key = 'byte_behavior_profiles'

            elif data_type == 'drop_stats':
                if 'drop' not in self.config['ids'][can_id]:
                    self.config['ids'][can_id]['drop'] = {}
                self.config['ids'][can_id]['drop'].update(data)
                section = 'drop'
                key = 'drop_stats'

            else:
                raise ConfigError(f"Unknown data type: {data_type}")

            # 更新已知ID集合
            self._known_ids.add(can_id)
            
            # 增加配置版本号
            self._config_version += 1

            logger.debug(f"Updated {data_type} for ID {can_id}")
            
            # 通知观察者配置已变更（解决问题1）
            self._notify_observers(can_id, section, key)

    def get_known_ids(self) -> set:
        """
        获取已知ID列表

        Returns:
            已知ID集合
        """
        return self._known_ids.copy()

    def add_known_id(self, can_id: str):
        """
        添加已知ID

        Args:
            can_id: 要添加的CAN ID
        """
        self._known_ids.add(can_id)
        if can_id not in self.config['ids']:
            self.config['ids'][can_id] = {}

    def is_known_id(self, can_id: str) -> bool:
        """
        检查ID是否已知

        Args:
            can_id: CAN ID

        Returns:
            True如果ID已知
        """
        return can_id in self._known_ids

    def get_general_rule_setting(self, rule_name: str, key: str, default: Any = None) -> Any:
        """
        获取通用规则设置

        Args:
            rule_name: 规则名称
            key: 设置键名
            default: 默认值

        Returns:
            设置值
        """
        try:
            return self.config['general_rules'][rule_name][key]
        except KeyError:
            if default is not None:
                return default
            raise ConfigError(f"General rule setting not found: {rule_name}.{key}")

    def save_config(self, filepath: Optional[str] = None):
        """
        保存配置到文件

        Args:
            filepath: 保存路径，默认为原文件路径
        """
        save_path = filepath or self.filepath

        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            logger.info(f"Configuration saved to {save_path}")
        except Exception as e:
            raise ConfigError(f"Error saving configuration: {e}")

    def get_config_summary(self) -> Dict:
        """
        获取配置摘要信息

        Returns:
            配置摘要字典
        """
        return {
            'version': self.config.get('meta', {}).get('version', 'unknown'),
            'known_ids_count': len(self._known_ids),
            'known_ids': list(self._known_ids),
            'learning_window_sec': self.get_global_setting('learning_params', 'initial_learning_window_sec'),
            'min_samples': self.get_global_setting('learning_params', 'min_samples_for_stable_baseline'),
            'general_rules_enabled': any(
                self.get_general_rule_setting(rule, 'enabled', False)
                for rule in self.config.get('general_rules', {}).keys()
            )
        }
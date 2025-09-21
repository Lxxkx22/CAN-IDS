from abc import ABC, abstractmethod
from typing import List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import time


class AlertSeverity(Enum):
    """告警严重性级别"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    """告警数据结构"""
    alert_type: str
    can_id: str
    details: str
    timestamp: float = 0.0
    severity: AlertSeverity = AlertSeverity.MEDIUM
    frame_data: Optional[dict] = None
    detection_context: Optional[dict] = None

    

    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            'alert_type': self.alert_type,
            'can_id': self.can_id,
            'timestamp': self.timestamp,
            'details': self.details,
            'severity': self.severity.value,
            'frame_data': self.frame_data,
            'detection_context': self.detection_context,
            'alert_id': f"{self.can_id}_{self.alert_type}_{self.timestamp}"
        }

    def __str__(self) -> str:
        """字符串表示"""
        return f"Alert[{self.severity.value.upper()}] {self.alert_type} on ID {self.can_id}: {self.details}"


class BaseDetector(ABC):
    """检测器基类"""

    def __init__(self, config_manager):
        """
        初始化检测器

        Args:
            config_manager: 配置管理器实例
        """
        self.config_manager = config_manager
        self.detector_name = self.__class__.__name__
        self.detection_count = 0
        self.alert_count = 0
        self.last_detection_time = None

        # 检测器特定的配置缓存
        self._config_cache = {}
        
        # 配置缓存清理计数器
        self._cache_access_count = 0
        self._cache_cleanup_threshold = 100  # 降低清理阈值，防止内存泄漏
        
        # 配置版本号缓存（用于检测配置变更）
        self._cached_config_version = config_manager.get_config_version()
        
        # 内存压力模式标志（解决问题4）
        self._memory_pressure_mode = False
        self._memory_pressure_cache_limit = 50  # 内存压力下的缓存限制
        
        # 注册为配置变更观察者（解决问题1）
        self.config_manager.add_observer(self._on_config_changed)

    @abstractmethod
    def detect(self, frame, id_state: dict, config_proxy) -> List[Alert]:
        """
        检测异常（抽象方法）

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            config_proxy: 配置代理（通常是config_manager）

        Returns:
            Alert对象列表
        """
        pass

    def _create_alert(self, alert_type: str, frame, details: str,
                      severity: AlertSeverity = AlertSeverity.MEDIUM,
                      detection_context: Optional[dict] = None) -> Alert:
        """
        创建告警对象

        Args:
            alert_type: 告警类型
            frame: CANFrame对象
            details: 告警详情
            severity: 告警严重性
            detection_context: 检测上下文信息

        Returns:
            Alert对象
        """
        # 准备frame数据
        frame_data = {
            'timestamp': frame.timestamp,
            'can_id': frame.can_id,
            'dlc': frame.dlc,
            'payload': frame.payload.hex().upper() if frame.payload else '',
            'payload_hash': frame.get_payload_hash(),
            'raw_text': frame.raw_text
        } if frame else None

        # 添加检测器信息到上下文
        if detection_context is None:
            detection_context = {}
        detection_context.update({
            'detector': self.detector_name,
            'detection_time': time.time()
        })

        # 修复时间戳问题：优先使用frame.timestamp，确保时间戳正确性
        if frame and hasattr(frame, 'timestamp') and frame.timestamp is not None:
            alert_timestamp = frame.timestamp
        else:
            alert_timestamp = time.time()
            
        alert = Alert(
            alert_type=alert_type,
            can_id=frame.can_id if frame else 'unknown',
            timestamp=alert_timestamp,
            details=details,
            severity=severity,
            frame_data=frame_data,
            detection_context=detection_context
        )

        self.alert_count += 1
        return alert

    def _on_config_changed(self, can_id: str, section: str, key: str):
        """
        配置变更回调（解决问题1：配置缓存一致性）
        
        Args:
            can_id: 变更的CAN ID
            section: 变更的配置节
            key: 变更的配置键
        """
        # 清理相关的缓存项
        keys_to_remove = [k for k in self._config_cache.keys() 
                         if k.startswith(f"{can_id}_{section}")]
        for cache_key in keys_to_remove:
            del self._config_cache[cache_key]
        
        # 更新配置版本号
        self._cached_config_version = self.config_manager.get_config_version()
    
    def set_memory_pressure_mode(self, enabled: bool):
        """
        设置内存压力模式（解决问题4）
        
        Args:
            enabled: 是否启用内存压力模式
        """
        self._memory_pressure_mode = enabled
        if enabled:
            # 在内存压力模式下，清理大部分缓存
            self._aggressive_cache_cleanup()
    
    def _aggressive_cache_cleanup(self):
        """
        激进的缓存清理（内存压力下使用）
        """
        if len(self._config_cache) > self._memory_pressure_cache_limit:
            # 只保留最近访问的缓存项
            # 这里简化处理，直接清理一半缓存
            items_to_keep = list(self._config_cache.items())[:self._memory_pressure_cache_limit]
            self._config_cache = dict(items_to_keep)
    
    def _periodic_cache_cleanup(self):
        """
        定期缓存清理，防止内存泄漏
        """
        max_cache_size = 500 if not self._memory_pressure_mode else self._memory_pressure_cache_limit
        
        if len(self._config_cache) > max_cache_size:
            # 清理超出限制的缓存项
            items_to_keep = list(self._config_cache.items())[:max_cache_size]
            self._config_cache = dict(items_to_keep)
            
            import logging
            logger = logging.getLogger(__name__)
            logger.debug(f"Cache cleanup performed for {self.detector_name}, "
                        f"cache size reduced to {len(self._config_cache)}")
    
    def _should_use_cache(self) -> bool:
        """
        判断是否应该使用缓存
        
        Returns:
            是否使用缓存
        """
        # 检查配置版本是否变更
        current_version = self.config_manager.get_config_version()
        if current_version != self._cached_config_version:
            # 配置已变更，清理所有缓存
            self._config_cache.clear()
            self._cached_config_version = current_version
        
        # 在内存压力模式下，限制缓存使用
        if self._memory_pressure_mode:
            return len(self._config_cache) < self._memory_pressure_cache_limit
        
        return True

    def _get_config_value(self, can_id: str, section: str, key: str, default: Any = None) -> Any:
        """
        统一的配置获取方法（带缓存和类型安全）

        Args:
            can_id: CAN ID
            section: 配置节
            key: 配置键
            default: 默认值

        Returns:
            配置值（与默认值同类型）
        """
        cache_key = f"{can_id}_{section}_{key}"
        
        # 检查是否应该使用缓存
        use_cache = self._should_use_cache()
        
        if use_cache and cache_key in self._config_cache:
            return self._config_cache[cache_key]
        
        try:
            # 统一使用get_effective_setting方法
            value = self.config_manager.get_effective_setting(can_id, section, key)
            
            # 添加调试信息
            import logging
            logger = logging.getLogger(__name__)
            logger.debug(f"Config lookup: {can_id}.{section}.{key} = {value} (type: {type(value)})")
            
            # 类型安全转换
            if default is not None:
                value = self._safe_type_conversion(value, default)
            
            # 在允许的情况下缓存结果
            if use_cache:
                self._config_cache[cache_key] = value
                
                # 定期清理缓存，防止内存泄漏
                self._cache_access_count += 1
                if self._cache_access_count >= self._cache_cleanup_threshold:
                    self._periodic_cache_cleanup()
                    self._cache_access_count = 0
            
            return value
            
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.debug(f"Config value not found for {can_id}.{section}.{key}, using default: {e}")
            
            # 在允许的情况下缓存默认值
            if use_cache:
                self._config_cache[cache_key] = default
            
            return default

    def _get_cached_config(self, can_id: str, section: str, key: str, default: Any = None) -> Any:
        """
        获取缓存的配置值（兼容性方法，内部调用_get_config_value）
        
        Args:
            can_id: CAN ID
            section: 配置节
            key: 配置键
            default: 默认值
            
        Returns:
            配置值
        """
        return self._get_config_value(can_id, section, key, default)

    def _safe_type_conversion(self, value: Any, default: Any) -> Any:
        """
        安全的类型转换
        
        Args:
            value: 要转换的值
            default: 默认值（用于确定目标类型）
            
        Returns:
            转换后的值或默认值
        """
        if value is None:
            return default
            
        try:
            # 如果类型已经匹配，直接返回
            if type(value) == type(default):
                return value
                
            # 数值类型转换
            if isinstance(default, bool):
                if isinstance(value, str):
                    return value.lower() in ('true', '1', 'yes', 'on')
                return bool(value)
            elif isinstance(default, int):
                return int(float(value))  # 先转float再转int，处理"1.0"这种情况
            elif isinstance(default, float):
                return float(value)
            elif isinstance(default, str):
                return str(value)
            elif isinstance(default, (list, tuple)):
                if isinstance(value, (list, tuple)):
                    return value
                return [value]  # 单个值转为列表
            else:
                return value
                
        except (TypeError, ValueError) as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Type conversion failed for value {value} to type {type(default)}: {e}")
            return default

    def _is_detection_enabled(self, can_id: str, detection_type: str) -> bool:
        """
        检查特定检测类型是否启用（使用统一配置获取方法）

        Args:
            can_id: CAN ID
            detection_type: 检测类型（如'drop', 'tamper', 'replay'）

        Returns:
            True如果启用
        """
        try:
            # 使用现有的get_id_specific_setting方法检查enabled配置
            enabled = self.config_manager.get_id_specific_setting(can_id, detection_type, 'enabled', True)
            return enabled
        except (KeyError, AttributeError, TypeError):
            # 对于未知的检测器类型或配置错误，返回False
            return False

    def pre_detect(self, frame, id_state: dict) -> bool:
        """
        检测前的预处理

        Args:
            frame: CANFrame对象
            id_state: ID状态字典

        Returns:
            True如果应该继续检测，False跳过
        """
        self.detection_count += 1
        self.last_detection_time = frame.timestamp

        # 可以在这里添加通用的预检查逻辑
        # 例如：检查帧是否有效、是否在检测范围内等

        return True

    def post_detect(self, frame, id_state: dict, alerts: List[Alert]):
        """
        检测后的后处理

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            alerts: 生成的告警列表
        """
        # 更新告警计数统计信息
        if alerts:
            self.alert_count += len(alerts)
            
            # 更新状态中的最后告警时间
            current_time = frame.timestamp
            if 'last_alert_timestamps' not in id_state:
                id_state['last_alert_timestamps'] = {}

            for alert in alerts:
                id_state['last_alert_timestamps'][alert.alert_type] = current_time

    def get_statistics(self) -> dict:
        """
        获取检测器统计信息

        Returns:
            统计信息字典
        """
        return {
            'detector_name': self.detector_name,
            'detection_count': self.detection_count,
            'alert_count': self.alert_count,
            'last_detection_time': self.last_detection_time,
            'alert_rate': self.alert_count / max(self.detection_count, 1) * 100
        }

    def reset_statistics(self):
        """重置统计信息"""
        self.detection_count = 0
        self.alert_count = 0
        self.last_detection_time = None

    def cleanup_config_cache(self):
        """清理配置缓存"""
        self._config_cache.clear()
        self._cache_access_count = 0
    
    def __del__(self):
        """析构函数，移除观察者"""
        try:
            if hasattr(self, 'config_manager') and self.config_manager:
                self.config_manager.remove_observer(self._on_config_changed)
        except Exception:
            # 忽略析构时的异常
            pass


class DetectorError(Exception):
    """检测器异常"""
    pass


def detect_with_error_handling(detector: BaseDetector, frame, id_state: dict, config_proxy) -> List[Alert]:
    """
    带错误处理的检测包装器

    Args:
        detector: 检测器实例
        frame: CANFrame对象
        id_state: ID状态字典
        config_proxy: 配置代理

    Returns:
        Alert对象列表
    """
    try:
        # 预处理
        if not detector.pre_detect(frame, id_state):
            return []

        # 执行检测
        alerts = detector.detect(frame, id_state, config_proxy)

        # 后处理
        detector.post_detect(frame, id_state, alerts)

        return alerts if alerts else []

    except DetectorError as e:
        # 检测器特定错误
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Detector {detector.detector_name} failed for ID {frame.can_id}: {e}")
        return []

    except MemoryError:
        # 内存不足时的降级策略
        import logging
        logger = logging.getLogger(__name__)
        logger.critical(f"Memory exhausted in detector {detector.detector_name}, entering minimal detection mode")

        # 返回一个基本的内存警告
        return [detector._create_alert(
            'memory_pressure',
            frame,
            'Detection degraded due to memory pressure',
            AlertSeverity.HIGH
        )]

    except Exception as e:
        # 其他未预期的错误
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Unexpected error in detector {detector.detector_name}: {e}")
        return []
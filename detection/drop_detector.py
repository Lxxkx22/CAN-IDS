from detection.base_detector import BaseDetector, Alert, AlertSeverity, DetectorError
import logging
from typing import Dict, Any, Optional
import numpy as np

logger = logging.getLogger(__name__)


class DropDetector(BaseDetector):
    """丢包攻击检测器"""

    def __init__(self, config_manager):
        """
        初始化丢包检测器

        Args:
            config_manager: 配置管理器实例
        """
        super().__init__(config_manager)
        self.detector_type = 'drop'

        # 初始化统计计数器
        self._initialize_counters()

    def _initialize_counters(self):
        """初始化所有统计计数器"""
        self.iat_anomaly_count = 0
        self.consecutive_missing_count = 0
        self.max_iat_violations = 0

    def detect(self, frame, id_state: dict, config_proxy) -> list[Alert]:
        """
        检测丢包攻击

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            config_proxy: 配置代理

        Returns:
            Alert对象列表
        """
        alerts = []
        can_id = frame.can_id

        # 检查是否启用drop检测
        if not self._is_detection_enabled(can_id, self.detector_type):
            return alerts

        try:
            # 获取学习到的IAT统计数据
            learned_stats = self._get_learned_iat_stats(can_id, config_proxy)
            if not learned_stats:
                # 没有学习数据，跳过检测
                logger.debug(f"No learned IAT stats for ID {can_id}, skipping drop detection")
                return alerts

            # 计算当前IAT
            current_iat = self._calculate_current_iat(frame, id_state)
            if current_iat is None:
                return alerts

            logger.debug(f"Drop detection for ID {can_id}: current_iat={current_iat:.6f}")

            # 1. 检查IAT异常（Sigma-based检测）
            iat_alerts = self._check_iat_anomaly(frame, id_state, current_iat, learned_stats, config_proxy)
            logger.debug(f"IAT anomaly check returned {len(iat_alerts)} alerts")
            alerts.extend(iat_alerts)

            # 2. 检查连续丢失帧
            consecutive_alerts = self._check_consecutive_missing(frame, id_state, current_iat, learned_stats,
                                                                 config_proxy)
            alerts.extend(consecutive_alerts)

            # 3. 检查最大IAT因子违反
            max_iat_alerts = self._check_max_iat_factor(frame, current_iat, learned_stats, config_proxy)
            alerts.extend(max_iat_alerts)

            # 4. 特殊DLC处理
            if frame.dlc == 0:
                dlc_zero_alerts = self._check_dlc_zero_special(frame, current_iat, learned_stats, config_proxy)
                alerts.extend(dlc_zero_alerts)

        except Exception as e:
            logger.error(f"Error in drop detection for ID {can_id}: {e}")
            raise DetectorError(f"Drop detection failed: {e}")

        return alerts

    def _get_learned_iat_stats(self, can_id: str, config_proxy) -> Optional[Dict[str, Any]]:
        """
        获取学习到的IAT统计数据

        Args:
            can_id: CAN ID
            config_proxy: 配置代理

        Returns:
            IAT统计数据字典，如果没有则返回None
        """
        try:
            # 确保CAN ID格式正确（添加0x前缀如果需要）
            config_can_id = can_id if can_id.startswith('0x') else f'0x{can_id}'
            
            # 使用统一的配置获取方法
            learned_mean = self._get_config_value(config_can_id, 'drop', 'learned_mean_iat')
            learned_std = self._get_config_value(config_can_id, 'drop', 'learned_std_iat')
            learned_median = self._get_config_value(config_can_id, 'drop', 'learned_median_iat')
            
            # 添加调试信息
            logger.debug(f"ID {can_id} (config: {config_can_id}): learned_mean={learned_mean}, learned_std={learned_std}, learned_median={learned_median}")

            # 添加类型转换 - 确保所有值都是标量数值
            # 更健壮的转换函数
            def to_scalar(v, default=0.0):
                # 处理None
                if v is None:
                    return default

                # 处理标量类型
                if isinstance(v, (int, float)):
                    return float(v)

                # 处理numpy标量
                if hasattr(v, 'item'):
                    return float(v.item())

                # 处理序列类型
                if isinstance(v, (list, tuple, np.ndarray)):
                    flat = np.array(v).flatten()
                    if flat.size > 0:
                        return float(flat[0])
                    return default

                # 最后尝试强制转换
                try:
                    return float(v)
                except (TypeError, ValueError):
                    logger.debug(f"无法转换为标量: {type(v)} - {v}")
                    return default

            # 检查关键值是否有效（learned_mean和learned_std是必需的）
            if learned_mean is None or learned_std is None:
                return None

            # 转换为标量
            learned_mean = to_scalar(learned_mean)
            learned_std = to_scalar(learned_std)
            # learned_median是可选的，如果不存在则使用learned_mean作为默认值
            learned_median = to_scalar(learned_median, learned_mean)

            return {
                'mean_iat': learned_mean,
                'std_iat': learned_std,
                'median_iat': learned_median,
                'min_iat': self._get_config_value(config_can_id, 'drop', 'min_iat', 0.0),
                'max_iat': self._get_config_value(config_can_id, 'drop', 'max_iat', float('inf'))
            }

        except Exception as e:
            logger.warning(f"Failed to get learned IAT stats for ID {can_id}: {e}")
            return None

    def _calculate_current_iat(self, frame, id_state: dict) -> Optional[float]:
        """
        计算当前IAT（Inter-Arrival Time）

        Args:
            frame: CANFrame对象
            id_state: ID状态字典

        Returns:
            当前IAT，如果无法计算则返回None
        """
        # 首先尝试使用StateManager已经计算好的IAT
        current_iat = id_state.get('last_iat')
        
        if current_iat is not None:
            logger.debug(f"Using StateManager calculated IAT for ID {frame.can_id}: {current_iat:.6f}s")
            # 更新状态中的IAT信息（保持兼容性）
            id_state['current_iat'] = current_iat
            return current_iat
        
        # 如果StateManager没有计算IAT，则手动计算
        last_timestamp = id_state.get('last_timestamp')
        if last_timestamp is None or last_timestamp >= frame.timestamp:
            logger.debug(f"No IAT available for ID {frame.can_id} (first frame or invalid timestamp)")
            return None
        
        current_iat = frame.timestamp - last_timestamp
        logger.debug(f"Manually calculated IAT for ID {frame.can_id}: {current_iat:.6f}s")
        
        # 更新状态中的IAT信息
        id_state['current_iat'] = current_iat
        
        return current_iat

    def _check_iat_anomaly(self, frame, id_state: dict, current_iat: float,
                           learned_stats: dict, config_proxy) -> list[Alert]:
        """
        检查IAT异常（基于Sigma阈值）

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            current_iat: 当前IAT
            learned_stats: 学习到的统计数据
            config_proxy: 配置代理

        Returns:
            Alert列表
        """
        alerts = []
        can_id = frame.can_id

        # 获取sigma阈值
        sigma_threshold = self._get_cached_config(can_id, 'drop', 'missing_frame_sigma', 3.5)

        try:
            # 如果是单元素序列则提取第一个元素
            if isinstance(sigma_threshold, (list, tuple)) and len(sigma_threshold) == 1:
                sigma_threshold = float(sigma_threshold[0])
            else:
                sigma_threshold = float(sigma_threshold)
        except (TypeError, ValueError):
            # 转换失败时使用默认值
            sigma_threshold = 3.5

        # 计算异常阈值
        mean_iat = learned_stats.get('mean_iat', learned_stats.get('mean', 0))
        std_iat = learned_stats.get('std_iat', learned_stats.get('std', 0))

        # 如果标准差为0，使用均值的10%作为容差
        if std_iat == 0:
            threshold = mean_iat * 1.1
        else:
            threshold = mean_iat + sigma_threshold * std_iat

        # 添加详细调试信息
        logger.debug(f"ID {can_id}: IAT threshold calculation - mean={mean_iat:.6f}, std={std_iat:.6f}, sigma={sigma_threshold}, threshold={threshold:.6f}, current={current_iat:.6f}")

        # 检查是否超过阈值
        if current_iat > threshold:
            self.iat_anomaly_count += 1

            # 增加连续丢失计数
            id_state['consecutive_missing_count'] = id_state.get('consecutive_missing_count', 0) + 1

            severity = AlertSeverity.MEDIUM
            if current_iat > threshold * 2:
                severity = AlertSeverity.HIGH

            details = (f"IAT anomaly detected: current={current_iat:.6f}s, "
                       f"expected<={threshold:.6f}s (mean={mean_iat:.6f}s, "
                       f"std={std_iat:.6f}s, sigma={sigma_threshold})")

            context = {
                'current_iat': current_iat,
                'threshold': threshold,
                'learned_mean': mean_iat,
                'learned_std': std_iat,
                'sigma_threshold': sigma_threshold,
                'consecutive_count': id_state['consecutive_missing_count']
            }

            alerts.append(self._create_alert(
                'iat_anomaly',
                frame,
                details,
                severity,
                context
            ))

        else:
            # 重置连续丢失计数
            id_state['consecutive_missing_count'] = 0

        return alerts

    def _check_consecutive_missing(self, frame, id_state: dict, current_iat: float,
                                   learned_stats: dict, config_proxy) -> list[Alert]:
        """
        检查连续丢失帧

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            current_iat: 当前IAT
            learned_stats: 学习到的统计数据
            config_proxy: 配置代理

        Returns:
            Alert列表
        """
        alerts = []
        can_id = frame.can_id

        try:
            # 使用正确的默认值2
            consecutive_allowed = self._get_cached_config(can_id, 'drop', 'consecutive_missing_allowed', 2)

            # 如果返回值不是数字类型，尝试转换
            if not isinstance(consecutive_allowed, (int, float)):
                consecutive_allowed = int(consecutive_allowed)
        except (TypeError, ValueError) as e:
            # 记录错误并使用安全默认值
            consecutive_allowed = 2

        consecutive_count = id_state.get('consecutive_missing_count', 0)

        # 检查是否超过允许的连续丢失数量
        if consecutive_count > consecutive_allowed:
            self.consecutive_missing_count += 1

            severity = AlertSeverity.HIGH
            if consecutive_count > consecutive_allowed * 2:
                severity = AlertSeverity.CRITICAL

            details = (f"Consecutive missing frames detected: "
                       f"count={consecutive_count}, allowed<={consecutive_allowed}, "
                       f"current_iat={current_iat:.6f}s")

            # 安全计算估算的丢失帧数
            median_iat = learned_stats.get('median_iat', 0)
            if median_iat > 0:
                estimated_missing = max(1, int(current_iat / median_iat) - 1)
            else:
                estimated_missing = 1
                
            context = {
                'consecutive_count': consecutive_count,
                'consecutive_allowed': consecutive_allowed,
                'current_iat': current_iat,
                'estimated_missing_frames': estimated_missing
            }

            alerts.append(self._create_alert(
                'consecutive_missing_frames',
                frame,
                details,
                severity,
                context
            ))

        return alerts

    def _check_max_iat_factor(self, frame, current_iat: float,
                              learned_stats: dict, config_proxy) -> list[Alert]:
        """
        检查最大IAT因子违反

        Args:
            frame: CANFrame对象
            current_iat: 当前IAT
            learned_stats: 学习到的统计数据
            config_proxy: 配置代理

        Returns:
            Alert列表
        """
        alerts = []
        can_id = frame.can_id

        try:
            # 获取最大IAT因子
            max_iat_factor = self._get_cached_config(can_id, 'drop', 'max_iat_factor', 2.5)

            # 如果返回值不是数字类型，尝试转换
            if not isinstance(max_iat_factor, (int, float)):
                max_iat_factor = int(max_iat_factor)
        except (TypeError, ValueError) as e:
            max_iat_factor = 2.5



        # 使用中位数作为基准（更稳定），如果没有则使用平均值
        baseline_iat = learned_stats.get('median_iat', learned_stats.get('mean_iat', learned_stats.get('mean', 0)))
        
        # 避免除零错误
        if baseline_iat <= 0:
            return alerts
            
        max_allowed_iat = baseline_iat * max_iat_factor

        if current_iat > max_allowed_iat:
            self.max_iat_violations += 1

            severity = AlertSeverity.MEDIUM
            if current_iat > max_allowed_iat * 2:
                severity = AlertSeverity.HIGH

            details = (f"IAT exceeded max factor: current={current_iat:.6f}s, "
                       f"max_allowed={max_allowed_iat:.6f}s "
                       f"(median={baseline_iat:.6f}s * factor={max_iat_factor})")

            # 安全计算violation_ratio
            violation_ratio = current_iat / max_allowed_iat if max_allowed_iat > 0 else float('inf')
            
            context = {
                'current_iat': current_iat,
                'max_allowed_iat': max_allowed_iat,
                'baseline_iat': baseline_iat,
                'max_iat_factor': max_iat_factor,
                'violation_ratio': violation_ratio
            }

            alerts.append(self._create_alert(
                'iat_max_factor_violation',
                frame,
                details,
                severity,
                context
            ))

        return alerts

    def _check_dlc_zero_special(self, frame, current_iat: float,
                                learned_stats: dict, config_proxy) -> list[Alert]:
        """
        检查DLC=0的特殊处理

        Args:
            frame: CANFrame对象
            current_iat: 当前IAT
            learned_stats: 学习到的统计数据
            config_proxy: 配置代理

        Returns:
            Alert列表
        """
        alerts = []
        can_id = frame.can_id

        # 检查是否启用DLC=0特殊处理
        treat_special = self._get_cached_config(can_id, 'drop', 'treat_dlc_zero_as_special', True)

        if not treat_special:
            return alerts

        # DLC=0帧可能是心跳或状态帧，使用更宽松的阈值
        special_factor = 1.5  # 比正常阈值宽松50%
        mean_iat = learned_stats.get('mean_iat', learned_stats.get('mean', 0))
        std_iat = learned_stats.get('std_iat', learned_stats.get('std', 0))
        sigma_threshold = self._get_cached_config(can_id, 'drop', 'missing_frame_sigma', 3.5)

        # 计算特殊阈值
        if std_iat == 0:
            special_threshold = mean_iat * (1 + special_factor)
        else:
            special_threshold = mean_iat + (sigma_threshold * special_factor) * std_iat

        if current_iat > special_threshold:
            details = (f"DLC=0 frame timing anomaly: current={current_iat:.6f}s, "
                       f"special_threshold={special_threshold:.6f}s "
                       f"(relaxed by factor {special_factor})")

            context = {
                'current_iat': current_iat,
                'special_threshold': special_threshold,
                'special_factor': special_factor,
                'frame_dlc': frame.dlc
            }

            alerts.append(self._create_alert(
                'dlc_zero_timing_anomaly',
                frame,
                details,
                AlertSeverity.LOW,  # 较低优先级
                context
            ))

        return alerts

    def _estimate_missing_frames(self, current_iat: float, learned_stats: dict) -> int:
        """
        估算丢失的帧数
        
        Args:
            current_iat: 当前帧间时间间隔
            learned_stats: 学习到的统计信息
            
        Returns:
            估算的丢失帧数
        """
        if 'median_iat' in learned_stats and learned_stats['median_iat'] > 0:
            expected_frames = current_iat / learned_stats['median_iat']
            missing_frames = max(0, int(expected_frames) - 1)
        elif 'mean_iat' in learned_stats and learned_stats['mean_iat'] > 0:
            expected_frames = current_iat / learned_stats['mean_iat']
            missing_frames = max(0, int(expected_frames) - 1)
        else:
            missing_frames = 0
            
        return missing_frames

    def _calculate_iat_z_score(self, current_iat: float, learned_stats: dict) -> float:
        """
        计算IAT的Z分数
        
        Args:
            current_iat: 当前帧间时间间隔
            learned_stats: 学习到的统计信息
            
        Returns:
            Z分数
        """
        mean = learned_stats.get('mean', 0.0)
        std = learned_stats.get('std', 0.0)
        
        if std == 0.0:
            if current_iat == mean:
                return 0.0
            else:
                return float('inf')
        
        return (current_iat - mean) / std
    
    def _update_drop_state(self, frame, id_state, alerts):
        """
        更新丢包检测状态
        
        Args:
            frame: CAN帧
            id_state: ID状态字典
            alerts: 告警列表
        """
        current_time = frame.timestamp
        
        # 更新最后检测时间
        id_state['drop_last_detection_time'] = current_time
        
        # 更新检测计数
        if 'drop_detection_count' not in id_state:
            id_state['drop_detection_count'] = 0
        id_state['drop_detection_count'] += 1

    def get_detector_statistics(self) -> dict:
        """
        获取检测器特定统计信息

        Returns:
            统计信息字典
        """
        base_stats = self.get_statistics()

        drop_stats = {
            'iat_anomaly_count': self.iat_anomaly_count,
            'consecutive_missing_count': self.consecutive_missing_count,
            'max_iat_violations': self.max_iat_violations,
            'total_drop_alerts': (self.iat_anomaly_count +
                                  self.consecutive_missing_count +
                                  self.max_iat_violations)
        }

        return {**base_stats, **drop_stats}

    def reset_detector_statistics(self):
        """重置检测器特定统计信息"""
        super().reset_statistics()
        self._initialize_counters()
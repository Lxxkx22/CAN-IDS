from detection.base_detector import BaseDetector, Alert, AlertSeverity, DetectorError
from utils.helpers import calculate_entropy
import logging

logger = logging.getLogger(__name__)


class TamperDetector(BaseDetector):
    """篡改攻击检测器"""

    def __init__(self, config_manager, baseline_engine_ref):
        """初始化篡改检测器"""
        super().__init__(config_manager)
        self.detector_type = 'tamper'
        self.baseline_engine = baseline_engine_ref

        # 初始化统计计数器
        self._initialize_counters()

        logger.info("TamperDetector initialized")

    def _initialize_counters(self):
        """初始化所有统计计数器"""
        self.dlc_anomaly_count = 0
        self.entropy_anomaly_count = 0
        self.static_byte_mismatch_count = 0
        self.counter_byte_anomaly_count = 0
        self.byte_change_ratio_count = 0

    def detect(self, frame, id_state: dict, config_proxy) -> list[Alert]:
        """
        检测篡改攻击

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            config_proxy: 配置代理

        Returns:
            Alert对象列表
        """
        alerts = []
        can_id = frame.can_id

        # 检查是否启用tamper检测
        if not self._is_detection_enabled(can_id, self.detector_type):
            return alerts

        try:
            # 1. DLC检查
            dlc_alerts = self._check_dlc_anomaly(frame, config_proxy)
            alerts.extend(dlc_alerts)

            # 获取载荷分析的最小DLC
            min_dlc_for_analysis = self._get_cached_config(
                can_id, 'tamper', 'payload_analysis_min_dlc', 1
            )

            # 如果DLC过小，跳过载荷分析
            if frame.dlc < min_dlc_for_analysis:
                return alerts

            # 2. 熵检查
            entropy_alerts = self._check_entropy_anomaly(frame, config_proxy)
            alerts.extend(entropy_alerts)

            # 3. 字节行为检查
            byte_behavior_alerts = self._check_byte_behavior_anomaly(frame, id_state, config_proxy)
            alerts.extend(byte_behavior_alerts)

            # 4. 字节变化率检查
            byte_change_alerts = self._check_byte_change_ratio(frame, id_state, config_proxy)
            alerts.extend(byte_change_alerts)

            # 更新状态信息
            self._update_tamper_state(frame, id_state, alerts)

        except Exception as e:
            logger.error(f"Error in tamper detection for ID {can_id}: {e}")
            raise DetectorError(f"Tamper detection failed: {e}")

        return alerts

    def _check_dlc_anomaly(self, frame, config_proxy) -> list[Alert]:
        """
        检查DLC异常

        Args:
            frame: CANFrame对象
            config_proxy: 配置代理

        Returns:
            Alert列表
        """
        alerts = []
        can_id = frame.can_id

        # 获取学习到的DLC白名单
        try:
            # 首先尝试从配置管理器直接获取
            if hasattr(self.config_manager, 'get_config_value'):
                learned_dlcs = self.config_manager.get_config_value(can_id, 'tamper', 'learned_dlcs', [])
            else:
                learned_dlcs = self._get_config_value(can_id, 'tamper', 'learned_dlcs', [])
        except Exception:
            learned_dlcs = []
            
        if not isinstance(learned_dlcs, list):
            learned_dlcs = []

        if not learned_dlcs:
            # 没有学习数据，跳过检测
            logger.debug(f"No learned DLCs for ID {can_id}, skipping DLC check")
            return alerts

        # 检查当前DLC是否在白名单中
        if frame.dlc not in learned_dlcs:
            self.dlc_anomaly_count += 1

            severity = AlertSeverity.HIGH
            # 如果DLC明显异常（如超过8或为负数），提高严重性
            if frame.dlc > 8 or frame.dlc < 0:
                severity = AlertSeverity.CRITICAL

            details = (f"DLC anomaly detected: current={frame.dlc}, "
                       f"learned_dlcs={sorted(learned_dlcs)}")

            context = {
                'current_dlc': frame.dlc,
                'learned_dlcs': sorted(learned_dlcs),
                'payload_length': len(frame.payload),
                'dlc_learning_mode': self._get_cached_config(can_id, 'tamper', 'dlc_learning_mode', 'strict_whitelist')
            }

            alerts.append(self._create_alert(
                'tamper_dlc_anomaly',
                frame,
                details,
                severity,
                context
            ))

        return alerts

    def _check_entropy_anomaly(self, frame, config_proxy) -> list[Alert]:
        """
        检查熵异常

        Args:
            frame: CANFrame对象
            config_proxy: 配置代理

        Returns:
            Alert列表
        """
        alerts = []
        can_id = frame.can_id

        # 获取熵检测参数
        entropy_params = self._get_cached_config(can_id, 'tamper', 'entropy_params', {})

        if not entropy_params.get('enabled', True):
            return alerts

        # 检查是否有载荷
        if not frame.payload:
            return alerts

        # 获取学习到的熵统计数据
        entropy_params = self._get_config_value(can_id, 'tamper', 'entropy_params', {})
        if not isinstance(entropy_params, dict):
            entropy_params = {}

        learned_mean_entropy = entropy_params.get('learned_mean')
        learned_stddev_entropy = entropy_params.get('learned_stddev')

        if learned_mean_entropy is None or learned_stddev_entropy is None:
            # 没有学习数据，跳过检测
            logger.debug(f"No learned entropy stats for ID {can_id}, skipping entropy check")
            return alerts

        # 新增：最小标准差常量 (避免除零和低方差场景过度敏感)
        MIN_STDDEV = 0.01  # 经验值，可根据实际流量调整
        EPSILON = 1e-5  # 用于浮点数比较
        # 修改：处理零标准差和低方差场景
        if learned_stddev_entropy is None or learned_stddev_entropy < EPSILON:
            effective_stddev = MIN_STDDEV
            is_low_variance = True
        else:
            effective_stddev = learned_stddev_entropy
            is_low_variance = False
        # 计算当前载荷的熵 (保持不变)
        current_entropy = calculate_entropy(frame.payload)

        # 修改：计算基于有效标准差的阈值
        sigma_threshold = entropy_params.get('sigma_threshold', 3.0)
        deviation = abs(current_entropy - learned_mean_entropy)

        # 修改：双重检测逻辑 (增加绝对偏差阈值)
        absolute_threshold = entropy_params.get('absolute_threshold', 0.1)  # 新增配置项
        is_anomaly = False

        # 场景1：低方差ID使用绝对偏差检测
        if is_low_variance:
            if deviation > absolute_threshold:
                is_anomaly = True
                logger.debug(f"Low-variance ID {can_id} triggered absolute threshold: "
                             f"dev={deviation:.3f} > abs_thresh={absolute_threshold}")

        # 场景2：常规ID使用sigma检测
        else:
            sigma_deviation = deviation / effective_stddev
            if sigma_deviation > sigma_threshold:
                is_anomaly = True
        if is_anomaly:
            # 修改：严重性判断 (低方差ID默认MEDIUM)
            severity = AlertSeverity.MEDIUM

            if not is_low_variance:
                sigma_deviation = deviation / effective_stddev
                if sigma_deviation > sigma_threshold * 2:
                    severity = AlertSeverity.HIGH

            # 修改：警报详情添加检测类型说明
            anomaly_type = "low-variance" if is_low_variance else "sigma"
            details = (f"Entropy anomaly ({anomaly_type}) detected: current={current_entropy:.3f}, "
                       f"learned_mean={learned_mean_entropy:.3f}±{learned_stddev_entropy:.3f}, "
                       f"deviation={deviation:.3f}, threshold={absolute_threshold if is_low_variance else sigma_threshold}")
            context = {
                'current_entropy': current_entropy,
                'learned_mean_entropy': learned_mean_entropy,
                'learned_stddev_entropy': learned_stddev_entropy,
                'deviation': deviation,
                'sigma_threshold': sigma_threshold,
                'sigma_deviation': deviation / effective_stddev,
                'payload_size': len(frame.payload),
                'detection_type': 'absolute' if is_low_variance else 'sigma'  # 新增
            }

            alerts.append(self._create_alert(
                'entropy_anomaly',
                frame,
                details,
                severity,
                context
            ))

        return alerts

    def _check_byte_behavior_anomaly(self, frame, id_state: dict, config_proxy) -> list[Alert]:
        """
        检查字节行为异常

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            config_proxy: 配置代理

        Returns:
            Alert列表
        """
        alerts = []
        can_id = frame.can_id

        # 获取字节行为检测参数
        byte_behavior_params = self._get_cached_config(can_id, 'tamper', 'byte_behavior_params', {})

        if not byte_behavior_params.get('enabled', True):
            return alerts

        # 获取字节行为配置
        try:
            # 直接从配置文件获取byte_behavior_profiles数据
            byte_behavior_profiles = self._get_config_value(can_id, 'tamper', 'byte_behavior_profiles', [])
            
            # 如果获取到的是列表格式，需要为静态字节添加expected_value
            if isinstance(byte_behavior_profiles, list):
                for profile in byte_behavior_profiles:
                    if profile.get('type') == 'static' and 'value' not in profile:
                        # 从most_common_value获取期望值
                        profile['value'] = profile.get('most_common_value')
            else:
                # 如果不是列表格式，尝试旧的转换逻辑
                converted_profiles = []
                for pos_str, behavior in byte_behavior_profiles.items():
                    try:
                        position = int(pos_str)
                        profile = {
                            'position': position,
                            'type': behavior.get('type', 'unknown')
                        }
                        if behavior.get('type') == 'static':
                            profile['value'] = behavior.get('expected_value')
                        elif behavior.get('type') == 'counter':
                            profile['min'] = behavior.get('min', 0)
                            profile['max'] = behavior.get('max', 255)
                        converted_profiles.append(profile)
                    except (ValueError, TypeError):
                        continue
                byte_behavior_profiles = converted_profiles
        except Exception as e:
            logger.debug(f"Error getting byte_behavior_profiles for {can_id}: {e}")
            byte_behavior_profiles = []

        if not byte_behavior_profiles:
            # 没有学习数据，跳过检测
            logger.debug(f"No byte behavior profiles for ID {can_id}, skipping byte behavior check")
            return alerts

        # 检查每个字节位置
        for profile in byte_behavior_profiles:
            position = profile.get('position', 0)

            # 检查位置是否有效
            if position >= len(frame.payload):
                continue

            current_byte = frame.payload[position]
            profile_type = profile.get('type', 'unknown')

            # 根据字节类型进行不同的检查
            if profile_type == 'static':
                static_alerts = self._check_static_byte_mismatch(frame, profile, position, current_byte, id_state,
                                                                 byte_behavior_params)
                alerts.extend(static_alerts)

            elif profile_type == 'counter':
                counter_alerts = self._check_counter_byte_anomaly(frame, profile, position, current_byte, id_state,
                                                                  byte_behavior_params)
                alerts.extend(counter_alerts)

            elif profile_type == 'variable':
                variable_alerts = self._check_variable_byte_anomaly(frame, profile, position, current_byte,
                                                                    byte_behavior_params)
                alerts.extend(variable_alerts)

        return alerts

    def _check_static_byte_mismatch(self, frame, profile: dict, position: int,
                                    current_byte: int, id_state: dict, params: dict) -> list[Alert]:
        """
        检查静态字节不匹配

        Args:
            frame: CANFrame对象
            profile: 字节行为配置
            position: 字节位置
            current_byte: 当前字节值
            id_state: ID状态字典
            params: 字节行为参数

        Returns:
            Alert列表
        """
        alerts = []
        expected_value = profile.get('value')

        if expected_value is None:
            return alerts

        # 检查是否匹配
        if current_byte != expected_value:
            # 增加不匹配计数
            mismatch_counts = id_state.get('static_byte_mismatch_counts', [0] * 8)
            if position < len(mismatch_counts):
                mismatch_counts[position] += 1

            # 获取阈值
            mismatch_threshold = params.get('static_byte_mismatch_threshold', 1)

            if mismatch_counts[position] >= mismatch_threshold:
                self.static_byte_mismatch_count += 1

                severity = AlertSeverity.HIGH
                # 如果严重偏离预期值，提高严重性
                if abs(current_byte - expected_value) > 100:
                    severity = AlertSeverity.CRITICAL

                details = (f"Static byte mismatch at position {position}: "
                           f"current=0x{current_byte:02X}, expected=0x{expected_value:02X}, "
                           f"mismatch_count={mismatch_counts[position]}, threshold={mismatch_threshold}")

                context = {
                    'byte_position': position,
                    'current_value': current_byte,
                    'expected_value': expected_value,
                    'mismatch_count': mismatch_counts[position],
                    'mismatch_threshold': mismatch_threshold,
                    'value_difference': current_byte - expected_value
                }

                alerts.append(self._create_alert(
                    'static_byte_mismatch',
                    frame,
                    details,
                    severity,
                    context
                ))
        else:
            # 重置不匹配计数
            mismatch_counts = id_state.get('static_byte_mismatch_counts', [0] * 8)
            if position < len(mismatch_counts):
                mismatch_counts[position] = 0

        return alerts

    def _check_counter_byte_anomaly(self, frame, profile: dict, position: int,
                                    current_byte: int, id_state: dict, params: dict) -> list[Alert]:
        """
        检查计数器字节异常

        Args:
            frame: CANFrame对象
            profile: 字节行为配置
            position: 字节位置
            current_byte: 当前字节值
            id_state: ID状态字典
            params: 字节行为参数

        Returns:
            Alert列表
        """
        alerts = []

        # 获取计数器检测参数
        counter_params = params.get('counter_byte_params', {})

        if not counter_params.get('detect_simple_counters', True):
            return alerts

        # 获取计数器配置
        expected_step = profile.get('step', 1)
        max_value = profile.get('max', 255)
        min_value = profile.get('min', 0)
        rollover_detected = profile.get('rollover_detected', False)
        allowed_skips = counter_params.get('allowed_counter_skips', 1)

        # 获取上一个值
        last_byte_values = id_state.get('last_byte_values_for_counter', [0] * 8)
        if position >= len(last_byte_values):
            return alerts

        last_value = last_byte_values[position]
        
        # 如果是第一次检测（没有历史数据），跳过检测
        counter_initialized = id_state.get('counter_initialized', set())
        if position not in counter_initialized:
            counter_initialized.add(position)
            id_state['counter_initialized'] = counter_initialized
            last_byte_values[position] = current_byte
            return alerts

        # 计算预期值
        expected_values = []
        for skip in range(allowed_skips + 1):
            expected_value = (last_value + expected_step * (skip + 1)) % 256
            expected_values.append(expected_value)

        # 处理回绕情况
        if rollover_detected:
            for skip in range(allowed_skips + 1):
                if last_value + expected_step * (skip + 1) > max_value:
                    rollover_value = min_value + ((last_value + expected_step * (skip + 1)) - max_value - 1)
                    expected_values.append(rollover_value % 256)

        # 检查当前值是否在预期范围内
        if current_byte not in expected_values:
            self.counter_byte_anomaly_count += 1

            severity = AlertSeverity.MEDIUM
            # 如果值严重偏离计数器模式，提高严重性
            min_expected = min(expected_values) if expected_values else 0
            max_expected = max(expected_values) if expected_values else 255
            if current_byte < min_expected - 10 or current_byte > max_expected + 10:
                severity = AlertSeverity.HIGH

            details = (f"Counter byte anomaly at position {position}: "
                       f"current=0x{current_byte:02X}, last=0x{last_value:02X}, "
                       f"expected_values={[f'0x{v:02X}' for v in expected_values]}, "
                       f"step={expected_step}, allowed_skips={allowed_skips}")

            context = {
                'byte_position': position,
                'current_value': current_byte,
                'last_value': last_value,
                'expected_values': expected_values,
                'expected_step': expected_step,
                'allowed_skips': allowed_skips,
                'rollover_detected': rollover_detected,
                'min_value': min_value,
                'max_value': max_value
            }

            alerts.append(self._create_alert(
                'counter_byte_anomaly',
                frame,
                details,
                severity,
                context
            ))

        # 更新最后值（无论是否有告警都要更新）
        last_byte_values[position] = current_byte
        id_state['last_byte_values_for_counter'] = last_byte_values

        return alerts

    def _check_variable_byte_anomaly(self, frame, profile: dict, position: int,
                                     current_byte: int, params: dict) -> list[Alert]:
        """
        检查变量字节异常

        Args:
            frame: CANFrame对象
            profile: 字节行为配置
            position: 字节位置
            current_byte: 当前字节值
            params: 字节行为参数

        Returns:
            Alert列表
        """
        alerts = []

        # 对于变量字节，目前只进行基本的范围检查
        value_range = profile.get('value_range', [0, 255])
        observed_values = profile.get('observed_values', [])

        # 检查是否在观测范围内
        if value_range and len(value_range) == 2:
            min_val, max_val = value_range
            if current_byte < min_val or current_byte > max_val:
                severity = AlertSeverity.LOW  # 变量字节异常通常严重性较低

                details = (f"Variable byte out of learned range at position {position}: "
                           f"current=0x{current_byte:02X}, learned_range=[0x{min_val:02X}, 0x{max_val:02X}]")

                context = {
                    'byte_position': position,
                    'current_value': current_byte,
                    'learned_range': value_range,
                    'observed_values': observed_values[:10]  # 只显示前10个观测值
                }

                alerts.append(self._create_alert(
                    'variable_byte_range_violation',
                    frame,
                    details,
                    severity,
                    context
                ))

        return alerts

    def _check_byte_change_ratio(self, frame, id_state: dict, config_proxy) -> list[Alert]:
        """
        检查字节变化率

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            config_proxy: 配置代理

        Returns:
            Alert列表
        """
        alerts = []
        can_id = frame.can_id

        # 获取字节变化率阈值
        change_ratio_threshold = self._get_cached_config(can_id, 'tamper', 'byte_change_ratio_threshold', 0.85)

        if change_ratio_threshold <= 0 or change_ratio_threshold > 1:
            return alerts

        # 获取上一个载荷
        last_payload = id_state.get('last_payload_bytes')

        if last_payload is None or len(last_payload) != len(frame.payload):
            # 没有历史数据或长度不匹配，更新状态并跳过检测
            id_state['last_payload_bytes'] = frame.payload
            return alerts

        # 计算字节变化率
        change_ratio = self._calculate_byte_change_ratio(last_payload, frame.payload)

        if change_ratio > change_ratio_threshold:
            self.byte_change_ratio_count += 1

            # 重新计算用于显示的变量
            changed_bytes = sum(1 for i in range(len(frame.payload))
                                if frame.payload[i] != last_payload[i])
            total_bytes = len(frame.payload)

            severity = AlertSeverity.MEDIUM
            if change_ratio > 0.95:  # 95%以上的字节都变化
                severity = AlertSeverity.HIGH

            details = (f"High byte change ratio: {change_ratio:.2%} "
                       f"({changed_bytes}/{total_bytes} bytes changed), "
                       f"threshold={change_ratio_threshold:.2%}")

            context = {
                'change_ratio': change_ratio,
                'changed_bytes': changed_bytes,
                'total_bytes': total_bytes,
                'threshold': change_ratio_threshold,
                'current_payload': frame.payload.hex().upper(),
                'last_payload': last_payload.hex().upper(),
                'changed_positions': [i for i in range(len(frame.payload))
                                      if frame.payload[i] != last_payload[i]]
            }

            alerts.append(self._create_alert(
                'tamper_byte_change_ratio',
                frame,
                details,
                severity,
                context
            ))

        # 更新last_payload（只有在没有其他篡改告警时才更新，避免学习到异常数据）
        if not alerts:
            id_state['last_payload_bytes'] = frame.payload

        return alerts

    def _update_tamper_state(self, frame, id_state: dict, alerts: list):
        """
        更新篡改检测相关状态

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            alerts: 当前检测到的告警列表
        """
        # 初始化状态字典（如果不存在）
        if 'static_byte_mismatch_counts' not in id_state:
            id_state['static_byte_mismatch_counts'] = [0] * 8

        if 'last_byte_values_for_counter' not in id_state:
            id_state['last_byte_values_for_counter'] = [0] * 8

        # 更新检测统计
        id_state['last_tamper_check_time'] = frame.timestamp
        id_state['tamper_alert_count'] = id_state.get('tamper_alert_count', 0) + len(alerts)
        
        # 添加测试期望的字段
        id_state['tamper_last_detection_time'] = frame.timestamp
        id_state['tamper_detection_count'] = id_state.get('tamper_detection_count', 0) + 1
        id_state['tamper_last_payload'] = frame.payload

    def _calculate_byte_change_ratio(self, payload1: bytes, payload2: bytes) -> float:
        """
        计算两个载荷之间的字节变化率

        Args:
            payload1: 第一个载荷
            payload2: 第二个载荷

        Returns:
            字节变化率（0.0-1.0）
        """
        if not payload1 or not payload2 or len(payload1) != len(payload2):
            return 1.0  # 长度不同视为完全不同

        # 计算变化的字节数
        changed_bytes = sum(1 for i in range(len(payload1)) if payload1[i] != payload2[i])
        total_bytes = len(payload1)

        return changed_bytes / total_bytes if total_bytes > 0 else 0.0

    def _analyze_byte_behavior(self, position: int, byte_value: int, profile: dict) -> dict:
        """
        分析字节行为

        Args:
            position: 字节位置
            byte_value: 字节值
            profile: 字节行为配置

        Returns:
            分析结果字典
        """
        byte_type = profile.get('type', 'dynamic')
        
        if byte_type == 'static':
            expected_value = profile.get('expected_value', 0)
            is_normal = byte_value == expected_value
            return {
                'is_normal': is_normal,
                'type': 'static',
                'expected_value': expected_value,
                'actual_value': byte_value
            }
        elif byte_type == 'counter':
            min_value = profile.get('min', 0)
            max_value = profile.get('max', 255)
            is_normal = min_value <= byte_value <= max_value
            return {
                'is_normal': is_normal,
                'type': 'counter',
                'min_value': min_value,
                'max_value': max_value,
                'actual_value': byte_value
            }
        else:  # dynamic
            return {
                'is_normal': True,
                'type': 'dynamic',
                'actual_value': byte_value
            }

    def get_detector_statistics(self) -> dict:
        """
        获取检测器特定统计信息

        Returns:
            统计信息字典
        """
        base_stats = self.get_statistics()

        tamper_stats = {
            'dlc_anomaly_count': self.dlc_anomaly_count,
            'entropy_anomaly_count': self.entropy_anomaly_count,
            'static_byte_mismatch_count': self.static_byte_mismatch_count,
            'counter_byte_anomaly_count': self.counter_byte_anomaly_count,
            'byte_change_ratio_count': self.byte_change_ratio_count,
            'total_tamper_alerts': (self.dlc_anomaly_count +
                                    self.entropy_anomaly_count +
                                    self.static_byte_mismatch_count +
                                    self.counter_byte_anomaly_count +
                                    self.byte_change_ratio_count)
        }

        return {**base_stats, **tamper_stats}

    def reset_detector_statistics(self):
        """重置检测器特定统计信息"""
        super().reset_statistics()
        self._initialize_counters()
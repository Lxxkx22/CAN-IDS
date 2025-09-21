from detection.base_detector import BaseDetector, Alert, AlertSeverity, DetectorError
import time
import logging

logger = logging.getLogger(__name__)


class GeneralRulesDetector(BaseDetector):
    """通用规则检测器"""

    def __init__(self, config_manager, baseline_engine_ref=None):
        """
        初始化通用规则检测器

        Args:
            config_manager: 配置管理器实例
            baseline_engine_ref: 基线引擎引用（用于shadow学习）
        """
        super().__init__(config_manager)
        self.detector_type = 'general_rules'
        self.baseline_engine = baseline_engine_ref

        # 初始化统计计数器
        self._initialize_counters()

    def _initialize_counters(self):
        """初始化所有统计计数器"""
        self.unknown_id_count = 0
        self.shadow_learning_count = 0
        self.auto_added_id_count = 0

        # Shadow学习状态跟踪
        self.shadow_learning_state = {}  # can_id -> {'first_seen': timestamp, 'frame_count': int, 'added_to_baseline': bool}

    def detect(self, frame, id_state: dict, config_proxy) -> list[Alert]:
        """
        检测通用规则违反

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            config_proxy: 配置代理

        Returns:
            Alert对象列表
        """
        # 检查检测器是否启用
        if not self._is_detection_enabled(frame.can_id, 'general_rules'):
            return []

        if not self.pre_detect(frame, id_state):
            return []

        alerts = []
        processed_successfully = False

        try:
            # 检测未知ID
            unknown_id_alerts = self._check_unknown_id(frame, id_state, config_proxy)
            alerts.extend(unknown_id_alerts)

            # 可以在这里添加其他通用规则检测
            # 例如：检测异常频率、检测通信模式异常等

        except Exception as e:
            logger.error(f"Error in general rules detection for ID {frame.can_id}: {e}")
            raise DetectorError(f"General rules detection failed: {e}")

        finally:
            self.post_detect(frame, id_state, alerts)

        return alerts

    def _check_unknown_id(self, frame, id_state: dict, config_proxy) -> list[Alert]:
        """
        检测未知ID

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            config_proxy: 配置代理

        Returns:
            Alert列表
        """
        alerts = []
        can_id = frame.can_id

        # 获取未知ID检测设置
        unknown_id_settings = self._get_unknown_id_settings(config_proxy)

        if not unknown_id_settings.get('enabled', True):
            return alerts

        # 检查ID是否已知
        if self.config_manager.is_known_id(can_id):
            return alerts

        # ID未知，根据学习模式处理
        learning_mode = unknown_id_settings.get('learning_mode', 'alert_immediate')

        if learning_mode == 'shadow':
            # Shadow学习模式
            shadow_alerts = self._handle_shadow_learning(frame, unknown_id_settings, config_proxy)
            alerts.extend(shadow_alerts)
        else:
            # 立即告警模式
            immediate_alerts = self._handle_immediate_alert(frame, unknown_id_settings)
            alerts.extend(immediate_alerts)

        return alerts

    def _get_unknown_id_settings(self, config_proxy) -> dict:
        """
        获取未知ID检测设置

        Args:
            config_proxy: 配置代理

        Returns:
            设置字典
        """
        try:
            return {
                'enabled': self._get_config_value(None, 'general_rules', 'detect_unknown_id.enabled', True),
                'learning_mode': self._get_config_value(None, 'general_rules', 'detect_unknown_id.learning_mode', 'shadow'),
                'shadow_duration_sec': self._get_config_value(None, 'general_rules', 'detect_unknown_id.shadow_duration_sec', 30),
                'auto_add_to_baseline': self._get_config_value(None, 'general_rules', 'detect_unknown_id.auto_add_to_baseline', True),
                'min_frames_for_learning': self._get_config_value(None, 'general_rules', 'detect_unknown_id.min_frames_for_learning', 10)
            }
        except Exception as e:
            logger.warning(f"Error getting unknown ID settings: {e}")
            return {
                'enabled': True,
                'learning_mode': 'alert_immediate',
                'shadow_duration_sec': 600,
                'auto_add_to_baseline': True,
                'min_frames_for_learning': 50
            }

    def _handle_shadow_learning(self, frame, settings: dict, config_proxy) -> list[Alert]:
        """
        处理Shadow学习模式

        Args:
            frame: CANFrame对象
            settings: 未知ID设置
            config_proxy: 配置代理

        Returns:
            Alert列表
        """
        alerts = []
        can_id = frame.can_id
        current_time = frame.timestamp

        # 初始化shadow学习状态
        if can_id not in self.shadow_learning_state:
            self.shadow_learning_state[can_id] = {
                'first_seen': current_time,
                'frame_count': 0,
                'added_to_baseline': False,
                'last_seen': current_time
            }

            # 在shadow模式下，第一次遇到未知ID时也产生告警
            details = f"Unknown CAN ID detected in shadow learning mode: {can_id}"
            context = {
                'learning_mode': 'shadow',
                'is_first_detection': True,
                'id_format': self._analyze_id_format(can_id)
            }
            
            alerts.append(self._create_alert(
                'unknown_id_detected',
                frame,
                details,
                AlertSeverity.MEDIUM,
                context
            ))

            logger.info(f"Started shadow learning for unknown ID: {can_id}")

        shadow_state = self.shadow_learning_state[can_id]
        shadow_state['frame_count'] += 1
        shadow_state['last_seen'] = current_time
        
        # 将帧添加到baseline引擎的shadow学习中
        if hasattr(self.baseline_engine, 'add_frame_to_shadow_learning'):
            self.baseline_engine.add_frame_to_shadow_learning(frame, can_id)

        # 检查是否满足添加到基线的条件
        shadow_duration = settings.get('shadow_duration_sec', 600)
        auto_add = settings.get('auto_add_to_baseline', True)
        min_frames = settings.get('min_frames_for_learning', 50)

        time_in_shadow = current_time - shadow_state['first_seen']

        if (not shadow_state['added_to_baseline'] and
                auto_add and
                time_in_shadow >= shadow_duration and
                shadow_state['frame_count'] >= min_frames and
                self.baseline_engine.should_auto_add_id(can_id)):

            # 满足条件，添加到基线
            success = self._add_id_to_baseline(can_id, shadow_state, config_proxy)

            if success:
                shadow_state['added_to_baseline'] = True
                self.auto_added_id_count += 1

                # 生成info级别的告警通知
                details = (f"Unknown ID {can_id} auto-added to baseline after shadow learning: "
                           f"duration={time_in_shadow:.1f}s, frames={shadow_state['frame_count']}")

                context = {
                    'shadow_duration': time_in_shadow,
                    'frame_count': shadow_state['frame_count'],
                    'min_required_duration': shadow_duration,
                    'min_required_frames': min_frames,
                    'auto_added': True
                }

                alerts.append(self._create_alert(
                    'unknown_id_auto_added',
                    frame,
                    details,
                    AlertSeverity.LOW,  # 信息性告警
                    context
                ))

                logger.info(f"Auto-added unknown ID {can_id} to baseline")

        # 记录shadow学习统计
        self.shadow_learning_count += 1

        return alerts

    def _handle_immediate_alert(self, frame, settings: dict) -> list[Alert]:
        """
        处理立即告警模式

        Args:
            frame: CANFrame对象
            settings: 未知ID设置

        Returns:
            Alert列表
        """
        alerts = []
        can_id = frame.can_id

        self.unknown_id_count += 1

        severity = AlertSeverity.HIGH

        # 检查是否是可疑的ID（例如：异常范围的ID）
        if self._is_suspicious_id(can_id):
            severity = AlertSeverity.HIGH

        details = f"Unknown CAN ID detected: {can_id}"

        context = {
            'learning_mode': 'immediate_alert',
            'is_suspicious': self._is_suspicious_id(can_id),
            'id_format': self._analyze_id_format(can_id)
        }

        alerts.append(self._create_alert(
            'unknown_id_detected',
            frame,
            details,
            severity,
            context
        ))

        return alerts

    def _add_id_to_baseline(self, can_id: str, shadow_state: dict, config_proxy) -> bool:
        """
        将ID添加到基线

        Args:
            can_id: CAN ID
            shadow_state: Shadow学习状态
            config_proxy: 配置代理

        Returns:
            True如果添加成功
        """
        try:
            # 添加到已知ID列表
            self.config_manager.add_known_id(can_id)

            # 如果有基线引擎引用，可以触发对该ID的学习
            if self.baseline_engine:
                # 调用基线引擎的自动添加方法
                if hasattr(self.baseline_engine, 'auto_add_id_to_baseline'):
                    self.baseline_engine.auto_add_id_to_baseline(can_id, shadow_state)

            logger.info(f"Successfully added ID {can_id} to baseline")
            return True

        except Exception as e:
            logger.error(f"Failed to add ID {can_id} to baseline: {e}")
            return False

    def _auto_add_id_to_baseline(self, can_id: str) -> bool:
        """
        自动添加ID到基线（用于测试）

        Args:
            can_id: CAN ID

        Returns:
            True如果添加成功
        """
        if can_id in self.shadow_learning_state:
            shadow_state = self.shadow_learning_state[can_id]
            
            # 调用基线引擎的自动添加方法
            if self.baseline_engine and hasattr(self.baseline_engine, 'auto_add_id_to_baseline'):
                self.baseline_engine.auto_add_id_to_baseline(can_id)
                
            # 更新状态
            shadow_state['added_to_baseline'] = True
            self.auto_added_id_count += 1
            
            logger.info(f"Auto-added ID {can_id} to baseline")
            return True
            
        return False

    def _is_suspicious_id(self, can_id: str) -> bool:
        """
        检查ID是否可疑

        Args:
            can_id: CAN ID

        Returns:
            True如果ID可疑
        """
        try:
            # 转换为整数进行分析
            id_int = int(can_id, 16)

            # 检查是否在正常范围内（标准CAN: 0x000-0x7FF, 扩展CAN: 0x00000000-0x1FFFFFFF）
            if id_int > 0x1FFFFFFF:
                return True

            # 检查是否为异常模式（例如：全1或全0）
            if can_id.upper() in ['0x0000', '0x7FF', '0xFFFF', '0x1FFFFFFF']:
                return True

            # 检查是否为保留或特殊用途的ID范围
            # 这些范围可以根据具体的CAN网络规范进行配置
            suspicious_ranges = [
                (0x7F0, 0x7FF),  # 诊断ID范围
            ]

            for start, end in suspicious_ranges:
                if start <= id_int <= end:
                    return True

            return False

        except ValueError:
            # 无法解析的ID格式本身就是可疑的
            return True

    def _analyze_id_format(self, can_id: str) -> dict:
        """
        分析ID格式

        Args:
            can_id: CAN ID

        Returns:
            格式分析结果
        """
        try:
            id_int = int(can_id, 16)

            # 判断是否为扩展ID
            is_extended = id_int > 0x7FF

            return {
                'hex_string': can_id.upper(),
                'decimal_value': id_int,
                'is_extended_id': is_extended,
                'bit_length': len(bin(id_int)) - 2,  # 减去'0b'前缀
                'is_valid_format': True
            }

        except ValueError:
            return {
                'hex_string': can_id,
                'decimal_value': None,
                'is_extended_id': None,
                'bit_length': None,
                'is_valid_format': False
            }

    def get_shadow_learning_summary(self) -> dict:
        """
        获取Shadow学习摘要

        Returns:
            Shadow学习状态摘要
        """
        current_time = time.time()

        active_shadow_ids = []
        completed_shadow_ids = []

        for can_id, state in self.shadow_learning_state.items():
            shadow_info = {
                'can_id': can_id,
                'first_seen': state['first_seen'],
                'frame_count': state['frame_count'],
                'duration': current_time - state['first_seen'],
                'added_to_baseline': state['added_to_baseline']
            }

            if state['added_to_baseline']:
                completed_shadow_ids.append(shadow_info)
            else:
                active_shadow_ids.append(shadow_info)

        return {
            'active_shadow_learning': active_shadow_ids,
            'completed_shadow_learning': completed_shadow_ids,
            'total_shadow_ids': len(self.shadow_learning_state),
            'auto_added_count': self.auto_added_id_count
        }

    def cleanup_old_shadow_state(self, max_age_sec: int = 3600):
        """
        清理过期的Shadow学习状态

        Args:
            max_age_sec: 最大年龄（秒）
        """
        current_time = time.time()
        cutoff_time = current_time - max_age_sec

        expired_ids = [
            can_id for can_id, state in self.shadow_learning_state.items()
            if state['last_seen'] < cutoff_time
        ]

        for can_id in expired_ids:
            del self.shadow_learning_state[can_id]
            logger.debug(f"Cleaned up expired shadow state for ID: {can_id}")

    def post_detect(self, frame, id_state: dict, alerts: list[Alert]):
        """
        检测后的后处理

        Args:
            frame: CANFrame对象
            id_state: ID状态字典
            alerts: 生成的告警列表
        """
        # 调用父类的post_detect方法
        super().post_detect(frame, id_state, alerts)
        
        # 设置通用规则检测器特定的状态信息
        id_state['general_rules_last_detection_time'] = frame.timestamp
        id_state['general_rules_detection_count'] = id_state.get('general_rules_detection_count', 0) + 1

    def get_detector_statistics(self) -> dict:
        """
        获取检测器特定统计信息

        Returns:
            统计信息字典
        """
        base_stats = self.get_statistics()

        general_rules_stats = {
            'unknown_id_count': self.unknown_id_count,
            'shadow_learning_count': self.shadow_learning_count,
            'auto_added_id_count': self.auto_added_id_count,
            'active_shadow_ids': len([s for s in self.shadow_learning_state.values() if not s['added_to_baseline']]),
            'total_shadow_ids': len(self.shadow_learning_state)
        }

        return {**base_stats, **general_rules_stats}

    def reset_detector_statistics(self):
        """重置检测器特定统计信息"""
        super().reset_statistics()
        self._initialize_counters()
        # 注意：不重置shadow_learning_state，因为它包含持久状态

    def _update_shadow_learning_state(self, frame):
        """
        更新Shadow学习状态
        
        Args:
            frame: CANFrame对象
        """
        can_id = frame.can_id
        current_time = time.time()
        
        if can_id not in self.shadow_learning_state:
            # 初始化新的shadow学习状态
            self.shadow_learning_state[can_id] = {
                'first_seen': current_time,
                'frame_count': 1,
                'added_to_baseline': False
            }
        else:
            # 更新现有状态
            self.shadow_learning_state[can_id]['frame_count'] += 1

    def _should_auto_add_id(self, can_id: int, settings: dict) -> bool:
        """
        判断是否应该自动添加ID到基线
        
        Args:
            can_id: CAN ID
            settings: 配置设置
            
        Returns:
            bool: 是否应该自动添加
        """
        if can_id not in self.shadow_learning_state:
            return False
            
        state = self.shadow_learning_state[can_id]
        
        # 如果已经添加过，不再添加
        if state['added_to_baseline']:
            return False
            
        # 检查是否满足自动添加条件
        frame_threshold = settings.get('shadow_learning_frames', 10)
        if state['frame_count'] >= frame_threshold:
            # 如果有baseline_engine，询问其意见
            if self.baseline_engine and hasattr(self.baseline_engine, 'should_auto_add_id'):
                return self.baseline_engine.should_auto_add_id(can_id)
            else:
                # 默认策略：达到阈值就添加
                return True
                
        return False
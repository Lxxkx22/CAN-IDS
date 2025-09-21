import statistics
import time
import logging
from collections import defaultdict, Counter, deque
from typing import Dict, List, Any, Optional
from utils.helpers import calculate_entropy, calculate_stats, hash_payload

# 可选的科学计算库导入
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False
    np = None

try:
    from scipy.fft import fft
    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False
    fft = None

# 配置日志
logger = logging.getLogger(__name__)


class BaselineEngine:
    """基线学习引擎"""

    def __init__(self, config_manager):
        """
        初始化学习引擎

        Args:
            config_manager: 配置管理器实例
        """
        self.config_manager = config_manager
        self.learning_start_time = None
        self.learning_duration = self.config_manager.get_global_setting(
            'learning_params', 'initial_learning_window_sec'
        )
        self.min_samples = self.config_manager.get_global_setting(
            'learning_params', 'min_samples_for_stable_baseline'
        )

        # 学习数据存储结构
        self.data_per_id = defaultdict(lambda: {
            'timestamps': [],
            'dlcs': set(),
            'payloads_for_entropy': [],
            'bytes_at_pos': [[] for _ in range(8)],  # 最多8字节
            'frame_count': 0,
            'first_seen': None,
            'last_seen': None
        })

        self.periodicity_data = defaultdict(lambda: {
            'timestamps': deque(maxlen=1000),
            'payload_patterns': defaultdict(list),
            'iat_patterns': [],
            'dominant_periods': [],
            'periodicity_score': 0.0
        })

        # 学习状态
        self.is_learning_active = False
        self.learning_completed = False

        logger.info(
            f"BaselineEngine initialized: learning_duration={self.learning_duration}s, min_samples={self.min_samples}")

    def reset_learning(self):
        """重置学习状态"""
        self.learning_start_time = None
        self.is_learning_active = False
        self.learning_completed = False
        self.data_per_id.clear()
        self.periodicity_data.clear()
        logger.info("Learning state reset")

    def start_learning(self):
        """开始学习阶段"""
        self.learning_start_time = time.time()
        self.is_learning_active = True
        self.learning_completed = False
        logger.info("Learning phase started")

    def process_frame_for_learning(self, frame):
        """
        处理学习阶段的帧数据

        Args:
            frame: CANFrame对象
        """
        if not self.is_learning_active:
            self.start_learning()

        can_id = frame.can_id
        data = self.data_per_id[can_id]

        # 记录时间戳
        data['timestamps'].append(frame.timestamp)

        # 记录首次和最后见到的时间
        if data['first_seen'] is None:
            data['first_seen'] = frame.timestamp
        data['last_seen'] = frame.timestamp

        # 记录DLC
        data['dlcs'].add(frame.dlc)

        # 记录payload用于熵计算（如果启用）
        tamper_params = self.config_manager.get_effective_setting(can_id, 'tamper', 'entropy_params')
        if tamper_params.get('enabled', False):
            data['payloads_for_entropy'].append(frame.payload)

        # 记录字节级行为（如果启用）
        byte_behavior_params = self.config_manager.get_effective_setting(can_id, 'tamper', 'byte_behavior_params')
        if byte_behavior_params.get('enabled', False):
            for pos_idx, byte_value in enumerate(frame.payload):
                if pos_idx < 8:  # 限制在8字节内
                    data['bytes_at_pos'][pos_idx].append(byte_value)

        # 增加帧计数
        data['frame_count'] += 1

        # 更新周期性数据
        periodicity_data = self.periodicity_data[can_id]
        periodicity_data['timestamps'].append(frame.timestamp)
        
        # 记录payload模式用于周期性分析
        payload_hash = hash(frame.payload)
        periodicity_data['payload_patterns'][payload_hash].append(frame.timestamp)

        # 检查学习是否完成
        if self.is_learning_complete():
            if not self.learning_completed:
                logger.info("Learning completion conditions met")
                self.finalize_baselines()

    def is_learning_complete(self) -> bool:
        """
        检查学习是否完成

        Returns:
            True如果学习完成
        """
        if self.learning_completed:
            return True

        if not self.learning_start_time:
            return False

        # 检查时间条件
        elapsed_time = time.time() - self.learning_start_time
        time_condition = elapsed_time >= self.learning_duration

        # 检查样本数量条件
        sample_condition = all(
            data['frame_count'] >= self.min_samples
            for data in self.data_per_id.values()
            if data['frame_count'] > 0
        )

        # 至少需要时间条件满足，样本条件是可选的
        return time_condition and (sample_condition or len(self.data_per_id) == 0)

    def finalize_baselines(self):
        """完成基线学习并更新配置"""
        if self.learning_completed:
            return

        logger.info("Finalizing baselines...")

        for can_id, data in self.data_per_id.items():
            if data['frame_count'] < 10:  # 最小样本数检查
                logger.warning(f"Insufficient samples for ID {can_id}: {data['frame_count']}")
                continue

            try:
                # 计算Drop攻击基线
                self._compute_drop_baselines(can_id, data)

                # 计算Tamper攻击基线
                self._compute_tamper_baselines(can_id, data)

                # 添加到已知ID列表
                self.config_manager.add_known_id(can_id)

                logger.info(f"Completed baseline learning for ID {can_id} with {data['frame_count']} samples")

            except Exception as e:
                logger.error(f"Error computing baselines for ID {can_id}: {e}")

        self.learning_completed = True
        self.is_learning_active = False

        # 输出学习摘要
        self._log_learning_summary()

        logger.info("Baseline learning completed")

    def _compute_drop_baselines(self, can_id: str, data: Dict):
        """
        计算丢包攻击基线

        Args:
            can_id: CAN ID
            data: 该ID的学习数据
        """
        timestamps = data['timestamps']
        if len(timestamps) < 2:
            logger.warning(f"Insufficient timestamps for IAT calculation: ID {can_id}")
            return

        # 计算IAT（Inter-Arrival Time）
        iats = []
        for i in range(1, len(timestamps)):
            iat = timestamps[i] - timestamps[i - 1]
            if iat > 0:  # 过滤无效IAT
                iats.append(iat)

        if not iats:
            logger.warning(f"No valid IATs found for ID {can_id}")
            return

        # 计算统计数据
        stats = calculate_stats(iats)

        drop_stats = {
            'learned_mean_iat': stats['mean'],
            'learned_std_iat': stats['std'],
            'learned_median_iat': stats['median'],
            'min_iat': stats['min'],
            'max_iat': stats['max'],
            'iat_count': stats['count']
        }

        # 更新配置
        self.config_manager.update_learned_data(can_id, 'drop_stats', drop_stats)

        logger.debug(f"Drop baseline for {can_id}: mean_iat={stats['mean']:.6f}s, std_iat={stats['std']:.6f}s")

    def _compute_tamper_baselines(self, can_id: str, data: Dict):
        """
        计算篡改攻击基线

        Args:
            can_id: CAN ID
            data: 该ID的学习数据
        """
        # 1. 学习DLC白名单
        learned_dlcs = list(data['dlcs'])
        self.config_manager.update_learned_data(can_id, 'learned_dlcs', learned_dlcs)

        # 2. 计算熵基线
        tamper_params = self.config_manager.get_effective_setting(can_id, 'tamper', 'entropy_params')
        if tamper_params.get('enabled', False) and data['payloads_for_entropy']:
            self._compute_entropy_baseline(can_id, data['payloads_for_entropy'])

        # 3. 分析字节行为模式
        byte_behavior_params = self.config_manager.get_effective_setting(can_id, 'tamper', 'byte_behavior_params')
        if byte_behavior_params.get('enabled', False):
            self._compute_byte_behavior_baseline(can_id, data['bytes_at_pos'], byte_behavior_params)

    def _compute_entropy_baseline(self, can_id: str, payloads: List[bytes]):
        """
        计算熵基线

        Args:
            can_id: CAN ID
            payloads: 载荷列表
        """
        entropies = []
        for payload in payloads:
            if len(payload) > 0:  # 跳过空载荷
                entropy = calculate_entropy(payload)
                entropies.append(entropy)

        if not entropies:
            logger.warning(f"No valid payloads for entropy calculation: ID {can_id}")
            return

        stats = calculate_stats(entropies)

        entropy_stats = {
            'learned_mean': stats['mean'],
            'learned_stddev': stats['std'],
            'min_entropy': stats['min'],
            'max_entropy': stats['max'],
            'entropy_count': stats['count']
        }

        self.config_manager.update_learned_data(can_id, 'entropy_stats', entropy_stats)

        logger.debug(f"Entropy baseline for {can_id}: mean={stats['mean']:.3f}, std={stats['std']:.3f}")

    def _compute_byte_behavior_baseline(self, can_id: str, bytes_at_pos: List[Dict], params: Dict):
        """
        计算字节行为基线

        Args:
            can_id: CAN ID
            bytes_at_pos: 各位置的字节数据
            params: 字节行为参数
        """
        min_changes = params.get('learning_window_min_changes_for_variable', 5)
        profiles = []

        for pos_idx, byte_data in enumerate(bytes_at_pos):
            if 'values' not in byte_data or not byte_data['values']:
                profiles.append({'type': 'unknown', 'position': pos_idx})
                continue

            byte_values = byte_data['values']
            profile = self._analyze_byte_behavior(byte_values, min_changes, pos_idx)
            profiles.append(profile)

        # 只保留有数据的位置
        non_empty_profiles = [p for p in profiles if p['type'] != 'unknown']

        if non_empty_profiles:
            self.config_manager.update_learned_data(can_id, 'byte_behavior_profiles', non_empty_profiles)
            logger.debug(f"Byte behavior baseline for {can_id}: {len(non_empty_profiles)} positions analyzed")

    def _analyze_byte_behavior(self, byte_values: List[int], min_changes_for_variable: int, position: int) -> Dict:
        """
        分析字节行为模式

        Args:
            byte_values: 字节值列表
            min_changes_for_variable: 判定为变量的最小变化次数
            position: 字节位置

        Returns:
            行为配置字典
        """
        if not byte_values:
            return {'type': 'unknown', 'position': position}

        unique_values = set(byte_values)

        # 静态字节：只有一个值
        if len(unique_values) == 1:
            return {
                'type': 'static',
                'position': position,
                'value': list(unique_values)[0]
            }

        # 变化次数不足，暂定为变量
        if len(unique_values) < min_changes_for_variable:
            return {
                'type': 'variable',
                'position': position,
                'observed_values': sorted(list(unique_values)),
                'value_count': len(unique_values)
            }

        # 检测是否为计数器
        if self._is_counter_pattern(byte_values):
            return self._create_counter_profile(byte_values, position)

        # 其他情况为变量
        return {
            'type': 'variable',
            'position': position,
            'value_range': [min(byte_values), max(byte_values)],
            'unique_values': len(unique_values),
            'common_values': [v for v, c in Counter(byte_values).most_common(5)]
        }

    def _is_counter_pattern(self, byte_values: List[int]) -> bool:
        """
        检测是否为计数器模式

        Args:
            byte_values: 字节值列表

        Returns:
            True如果是计数器模式
        """
        if len(byte_values) < 3:
            return False

        # 计算相邻值的差值
        differences = []
        for i in range(1, len(byte_values)):
            diff = (byte_values[i] - byte_values[i - 1]) % 256  # 处理溢出
            differences.append(diff)

        # 检查差值的一致性
        diff_counter = Counter(differences)
        most_common_diff, most_common_count = diff_counter.most_common(1)[0]

        # 如果最常见的差值占比超过70%，认为是计数器
        consistency_ratio = most_common_count / len(differences)
        return consistency_ratio > 0.7 and most_common_diff in [1, 2, 4, 8, 16]  # 常见的计数器步长

    def _create_counter_profile(self, byte_values: List[int], position: int) -> Dict:
        """
        创建计数器配置

        Args:
            byte_values: 字节值列表
            position: 字节位置

        Returns:
            计数器配置字典
        """
        differences = []
        for i in range(1, len(byte_values)):
            diff = (byte_values[i] - byte_values[i - 1]) % 256
            differences.append(diff)

        step = Counter(differences).most_common(1)[0][0]

        return {
            'type': 'counter',
            'position': position,
            'step': step,
            'min_value': min(byte_values),
            'max_value': max(byte_values),
            'rollover_detected': max(byte_values) - min(byte_values) > 200,
            'initial_value': byte_values[0] if byte_values else 0
        }

    def get_current_baselines(self):
        """
        获取当前基线

        Returns:
            配置管理器引用
        """
        return self.config_manager

    def get_learning_progress(self) -> Dict:
        """
        获取学习进度信息

        Returns:
            学习进度字典
        """
        if not self.learning_start_time:
            return {'status': 'not_started'}

        elapsed_time = time.time() - self.learning_start_time
        progress_ratio = min(elapsed_time / self.learning_duration, 1.0)

        return {
            'status': 'completed' if self.learning_completed else 'active',
            'elapsed_time': elapsed_time,
            'total_duration': self.learning_duration,
            'progress_ratio': progress_ratio,
            'ids_learned': len(self.data_per_id),
            'total_frames': sum(data['frame_count'] for data in self.data_per_id.values())
        }

    def _log_learning_summary(self):
        """输出学习摘要"""
        total_frames = sum(data['frame_count'] for data in self.data_per_id.values())
        elapsed_time = time.time() - self.learning_start_time if self.learning_start_time else 0

        summary = f"""
Learning Summary:
- Duration: {elapsed_time:.2f} seconds
- IDs learned: {len(self.data_per_id)}
- Total frames: {total_frames}
- Average frames per ID: {total_frames / max(len(self.data_per_id), 1):.1f}
        """

        logger.info(summary)

        # 详细的每ID统计
        for can_id, data in self.data_per_id.items():
            logger.debug(f"ID {can_id}: {data['frame_count']} frames, DLCs: {sorted(data['dlcs'])}")

    def _compute_periodicity_baseline(self, can_id: str, data: Dict):
        """计算周期性基线模式"""
        timestamps = data['timestamps']
        if len(timestamps) < 10:  # 需要足够样本
            return

        # 计算IAT序列
        iats = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

        # 检测周期性模式
        periods = self._detect_dominant_periods(iats)
        periodicity_score = self._calculate_periodicity_score(iats, periods)

        # 分析载荷模式
        payload_patterns = self._analyze_payload_periodicity(data['payloads_for_entropy'])

        # 计算方差，优先使用numpy，否则使用statistics
        if HAS_NUMPY and iats:
            variance = float(np.var(iats))
        elif iats:
            variance = statistics.variance(iats) if len(iats) > 1 else 0
        else:
            variance = 0
            
        periodicity_baseline = {
            'dominant_periods': periods,
            'periodicity_score': periodicity_score,
            'expected_iat_variance': variance,
            'payload_patterns': payload_patterns,
            'is_periodic': periodicity_score > 0.7,  # 阈值可配置
            'period_tolerance': 0.1  # 10% 容差
        }

        self.config_manager.update_learned_data(can_id, 'periodicity_baseline', periodicity_baseline)

    def _detect_dominant_periods(self, iats: List[float]) -> List[float]:
        """使用FFT检测主要周期（如果可用），否则使用简单的统计方法"""
        if len(iats) < 20:
            return []

        # 如果有numpy和scipy，使用FFT方法
        if HAS_NUMPY and HAS_SCIPY:
            try:
                # 转换为numpy数组
                iat_array = np.array(iats)

                # 应用FFT
                fft_result = fft(iat_array)
                frequencies = np.fft.fftfreq(len(iat_array), d=1)

                # 找到主要频率
                power = np.abs(fft_result)
                dominant_freq_indices = np.argsort(power)[-3:]  # 取前3个主要频率

                periods = []
                for idx in dominant_freq_indices:
                    if frequencies[idx] != 0:
                        period = 1.0 / abs(frequencies[idx])
                        if 0.001 <= period <= 10.0:  # 合理的周期范围
                            periods.append(period)

                return sorted(periods)
            except:
                pass
        
        # 回退到简单的统计方法
        try:
            # 使用简单的统计方法检测周期
            mean_iat = statistics.mean(iats)
            median_iat = statistics.median(iats)
            
            # 返回平均值和中位数作为可能的周期
            periods = []
            if 0.001 <= mean_iat <= 10.0:
                periods.append(mean_iat)
            if 0.001 <= median_iat <= 10.0 and abs(median_iat - mean_iat) > 0.001:
                periods.append(median_iat)
                
            return sorted(periods)
        except:
            return []

    def _calculate_periodicity_score(self, iats: List[float], periods: List[float]) -> float:
        """计算周期性得分"""
        if not periods or not iats:
            return 0.0

        # 计算与主要周期的一致性
        if HAS_NUMPY:
            main_period = periods[0] if periods else float(np.mean(iats))
        else:
            main_period = periods[0] if periods else statistics.mean(iats)
            
        deviations = [abs(iat - main_period) / main_period for iat in iats]
        
        if HAS_NUMPY:
            avg_deviation = float(np.mean(deviations))
        else:
            avg_deviation = statistics.mean(deviations)

        # 周期性得分：偏差越小，得分越高
        return max(0, 1.0 - avg_deviation)

    def _analyze_payload_periodicity(self, payloads: List[bytes]) -> Dict:
        """分析载荷的周期性模式"""
        if not payloads:
            return {}

        payload_hashes = [hash_payload(p) for p in payloads]
        unique_payloads = len(set(payload_hashes))
        total_payloads = len(payload_hashes)

        # 计算载荷重复模式
        from collections import Counter
        payload_counter = Counter(payload_hashes)
        most_common = payload_counter.most_common(5)

        return {
            'unique_payload_ratio': unique_payloads / total_payloads,
            'most_common_payloads': most_common,
            'static_payload_threshold': 0.8,  # 如果80%以上是相同载荷，认为是静态
            'is_mostly_static': (unique_payloads / total_payloads) < 0.2
        }

    def get_learned_id_count(self) -> int:
        """
        获取已学习到的CAN ID数量

        Returns:
            已学习的CAN ID数量（整数）
        """
        return len(self.data_per_id)

    def get_learning_statistics(self) -> Dict:
        """
        获取详细的学习统计数据

        Returns:
            包含学习统计数据的字典，包括：
            - learning_status: 学习状态（'not_started', 'active', 'completed'）
            - elapsed_time: 已学习时间（秒）
            - total_duration: 总计划学习时间（秒）
            - progress_ratio: 学习进度比例（0.0-1.0）
            - learned_id_count: 已学习的ID数量
            - total_frame_count: 处理的总帧数
            - ids: 每个ID的详细统计数据字典
        """
        stats = {
            'learning_status': 'not_started',
            'elapsed_time': 0.0,
            'total_duration': self.learning_duration,
            'progress_ratio': 0.0,
            'learned_id_count': len(self.data_per_id),
            'total_frame_count': sum(data['frame_count'] for data in self.data_per_id.values()),
            'ids': {}
        }

        if self.learning_completed:
            stats['learning_status'] = 'completed'
        elif self.is_learning_active and self.learning_start_time:
            stats['learning_status'] = 'active'

        if self.learning_start_time:
            elapsed_time = time.time() - self.learning_start_time
            stats['elapsed_time'] = elapsed_time
            stats['progress_ratio'] = min(elapsed_time / self.learning_duration, 1.0)

        # 添加每个ID的详细统计
        for can_id, data in self.data_per_id.items():
            id_stats = {
                'frame_count': data['frame_count'],
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen'],
                'dlcs': sorted(list(data['dlcs'])),
                'payload_samples': len(data['payloads_for_entropy']),
                'byte_positions': {}
            }

            # 添加每个字节位置的统计数据
            for pos_idx, byte_data in enumerate(data['bytes_at_pos']):
                if 'values' in byte_data and byte_data['values']:
                    id_stats['byte_positions'][pos_idx] = {
                        'sample_count': len(byte_data['values']),
                        'unique_values': len(set(byte_data['values'])),
                        'min_value': min(byte_data['values']),
                        'max_value': max(byte_data['values'])
                    }

            stats['ids'][can_id] = id_stats

        return stats

    def get_baseline_for_id(self, can_id: str) -> Optional[Dict]:
        """
        获取特定ID的基线数据
        
        Args:
            can_id: CAN ID
            
        Returns:
            基线数据字典，如果ID不存在则返回None
        """
        if can_id not in self.data_per_id:
            return None
            
        return dict(self.data_per_id[can_id])

    def complete_learning(self) -> Dict:
        """
        手动完成学习过程
        
        Returns:
            基线数据字典
        """
        self.learning_completed = True
        self.is_learning_active = False
        self.finalize_baselines()
        return dict(self.data_per_id)
        
    def should_auto_add_id(self, can_id: str) -> bool:
        """
        判断是否应该自动添加ID到基线学习
        
        Args:
            can_id: CAN ID
            
        Returns:
            bool: 是否应该添加
        """
        # 如果ID已经在学习中，返回False
        if can_id in self.data_per_id:
            return False
            
        # 如果学习已完成，不再添加新ID
        if self.learning_completed:
            return False
            
        # 如果学习未开始或正在进行中，可以添加新ID
        return True

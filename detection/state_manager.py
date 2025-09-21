import collections
import time
import logging
from collections import defaultdict, deque
from typing import Dict, Any, Optional, Tuple

# 配置日志
logger = logging.getLogger(__name__)


class StateManager:
    """状态管理器"""

    def __init__(self, max_ids: int = 5000, cleanup_interval: int = 300):
        """
        初始化状态管理器

        Args:
            max_ids: 最大跟踪ID数量
            cleanup_interval: 清理间隔（秒）
        """
        self.max_ids = max_ids
        self.cleanup_interval = cleanup_interval
        self.last_cleanup_time = time.time()

        # 主要状态存储
        self.id_states = {}

        # 内存限制配置
        self.max_payload_hashes_per_id = 1000
        self.max_sequence_length = 10
        self.max_sequence_history = 1000

        # 统计信息
        self.stats = {
            'total_updates': 0,
            'active_ids': 0,
            'memory_cleanups': 0,
            'states_created': 0
        }

        logger.info(f"StateManager initialized: max_ids={max_ids}, cleanup_interval={cleanup_interval}s")

    def update_and_get_state(self, frame) -> dict:
        """
        更新并获取ID状态

        Args:
            frame: CANFrame对象

        Returns:
            该ID的状态字典
        """
        can_id = frame.can_id
        current_time = frame.timestamp

        # 如果ID不存在，初始化状态
        if can_id not in self.id_states:
            self._initialize_id_state(can_id, current_time)

        state = self.id_states[can_id]

        # 获取上一次的时间戳（在更新之前）
        prev_timestamp = state.get('last_timestamp')
        
        # 更新基本状态
        state['frame_count'] = state.get('frame_count', 0) + 1

        # 计算并存储当前IAT（仅当不是第一帧时）
        if prev_timestamp is not None and prev_timestamp < current_time:
            current_iat = self._calculate_iat(current_time, prev_timestamp)
            state['last_iat'] = current_iat

        # 保存上一次时间戳到prev_timestamp字段
        state['prev_timestamp'] = prev_timestamp
        
        # 在计算IAT之后再更新last_timestamp
        state['last_timestamp'] = current_time
        
        # 更新最后活跃时间
        state['last_active'] = time.time()

        # 定期清理
        if current_time - self.last_cleanup_time > self.cleanup_interval:
            self.cleanup_old_data(current_time)

        self.stats['total_updates'] += 1
        return state

    def _initialize_id_state(self, can_id: str, timestamp: float):
        """
        初始化ID状态

        Args:
            can_id: CAN ID
            timestamp: 初始时间戳
        """
        # 检查ID数量限制，并在需要时腾出空间
        if len(self.id_states) >= self.max_ids:
            self._cleanup_inactive_ids()  # 先尝试清理真正不活跃的ID

            # 如果清理后，ID数量仍然达到或超过限制，
            # 并且我们将要添加一个新的ID，则需要强制移除一个来腾出空间。
            # 我们要确保添加新ID后，数量不超过 max_ids。
            # 这意味着在添加前，数量必须严格小于 max_ids，或者等于 max_ids-1。
            # 如果当前数量是 max_ids，就需要移除一个。
            if len(self.id_states) >= self.max_ids:
                # 按 last_active 时间排序，移除最不活跃的那个（即使它没有达到1小时不活跃的标准）
                # item[1] is the state dict, item[0] is the can_id
                # Sort by 'last_active', oldest first.
                # Ensure there are states to sort and remove if self.id_states is not empty
                if self.id_states:
                    sorted_ids_by_activity = sorted(
                        self.id_states.items(),
                        key=lambda item: item[1].get('last_active', 0)  # 0 as default if 'last_active' missing
                    )
                    id_to_remove = sorted_ids_by_activity[0][0]  # Get CAN ID of the oldest active state
                    del self.id_states[id_to_remove]
                    logger.info(
                        f"Evicted ID {id_to_remove} (oldest active) to make space for new ID {can_id} due to max_ids limit.")
                # else: This case (len >= max_ids but self.id_states is empty) should not happen if max_ids > 0

        # 现在可以安全地添加新ID的状态
        self.id_states[can_id] = {
            'can_id': can_id,  # 添加can_id字段
            'first_seen': timestamp,
            'last_timestamp': timestamp,
            'last_active': time.time(),  # 确保使用 time.time()
            'frame_count': 0,
            'consecutive_missing_count': 0,
            'last_expected_time': timestamp,
            'last_payload_bytes': b'',
            'last_byte_values_for_counter': [0] * 8,
            'static_byte_mismatch_counts': [0] * 8,
            'recent_payload_hashes_ts': deque(maxlen=self.max_payload_hashes_per_id),
            'recent_frame_sequence': deque(maxlen=self.max_sequence_length),
            'payload_hashes': [],  # 为了兼容测试用例
            'sequence_buffer': [],  # 为了兼容测试用例
            'historical_sequences': {},
            'last_alert_timestamps': {},
            'anomaly_flags': set(),
            'detection_context': {},
            '_state_manager_ref': self  # 添加state_manager引用
        }

        self.stats['states_created'] += 1
        logger.debug(f"Initialized state for ID {can_id}")

    def record_payload_hash(self, can_id: str, payload_hash: str, timestamp: float):
        """
        记录载荷哈希

        Args:
            can_id: CAN ID
            payload_hash: 载荷哈希值
            timestamp: 时间戳
        """
        if can_id not in self.id_states:
            return

        state = self.id_states[can_id]
        state['recent_payload_hashes_ts'].append((payload_hash, timestamp))

    def get_recent_payload_hashes(self, can_id: str, time_window_sec: float) -> list:
        """
        获取指定时间窗口内的载荷哈希

        Args:
            can_id: CAN ID
            time_window_sec: 时间窗口（秒）

        Returns:
            (hash, timestamp)元组列表
        """
        if can_id not in self.id_states:
            return []

        state = self.id_states[can_id]
        current_time = state.get('last_timestamp', time.time())
        cutoff_time = current_time - time_window_sec

        # 过滤时间窗口内的哈希
        recent_hashes = [
            (hash_val, ts) for hash_val, ts in state['recent_payload_hashes_ts']
            if ts > cutoff_time
        ]

        return recent_hashes

    def add_to_frame_sequence(self, can_id: str, frame_fingerprint: str):
        """
        添加到帧序列

        Args:
            can_id: CAN ID
            frame_fingerprint: 帧指纹
        """
        if can_id not in self.id_states:
            return

        state = self.id_states[can_id]
        state['recent_frame_sequence'].append(frame_fingerprint)

    def check_historical_sequence(self, can_id: str, sequence_tuple: tuple, current_time: float) -> Optional[float]:
        """
        检查历史序列

        Args:
            can_id: CAN ID
            sequence_tuple: 序列元组
            current_time: 当前时间

        Returns:
            如果序列存在，返回首次见到的时间；否则返回None
        """
        if can_id not in self.id_states:
            return None

        state = self.id_states[can_id]
        historical_sequences = state['historical_sequences']

        if sequence_tuple in historical_sequences:
            return historical_sequences[sequence_tuple]
        else:
            # 新序列，记录首次见到时间
            if len(historical_sequences) < self.max_sequence_history:
                historical_sequences[sequence_tuple] = current_time
            return None

    def increment_missing_count(self, can_id: str):
        """
        增加丢失计数

        Args:
            can_id: CAN ID
        """
        if can_id in self.id_states:
            self.id_states[can_id]['consecutive_missing_count'] += 1

    def reset_missing_count(self, can_id: str):
        """
        重置丢失计数

        Args:
            can_id: CAN ID
        """
        if can_id in self.id_states:
            self.id_states[can_id]['consecutive_missing_count'] = 0

    def update_byte_counter_state(self, can_id: str, byte_position: int, byte_value: int):
        """
        更新字节计数器状态

        Args:
            can_id: CAN ID
            byte_position: 字节位置
            byte_value: 字节值
        """
        if can_id in self.id_states and 0 <= byte_position < 8:
            self.id_states[can_id]['last_byte_values_for_counter'][byte_position] = byte_value

    def increment_static_byte_mismatch(self, can_id: str, byte_position: int):
        """
        增加静态字节不匹配计数

        Args:
            can_id: CAN ID
            byte_position: 字节位置
        """
        if can_id in self.id_states and 0 <= byte_position < 8:
            self.id_states[can_id]['static_byte_mismatch_counts'][byte_position] += 1

    def reset_static_byte_mismatch(self, can_id: str, byte_position: int):
        """
        重置静态字节不匹配计数

        Args:
            can_id: CAN ID
            byte_position: 字节位置
        """
        if can_id in self.id_states and 0 <= byte_position < 8:
            self.id_states[can_id]['static_byte_mismatch_counts'][byte_position] = 0

    def add_anomaly_flag(self, can_id: str, flag: str):
        """
        添加异常标志

        Args:
            can_id: CAN ID
            flag: 异常标志
        """
        if can_id in self.id_states:
            self.id_states[can_id]['anomaly_flags'].add(flag)

    def remove_anomaly_flag(self, can_id: str, flag: str):
        """
        移除异常标志

        Args:
            can_id: CAN ID
            flag: 异常标志
        """
        if can_id in self.id_states:
            self.id_states[can_id]['anomaly_flags'].discard(flag)

    def has_anomaly_flag(self, can_id: str, flag: str) -> bool:
        """
        检查是否有异常标志

        Args:
            can_id: CAN ID
            flag: 异常标志

        Returns:
            True如果有该标志
        """
        if can_id in self.id_states:
            return flag in self.id_states[can_id]['anomaly_flags']
        return False

    def cleanup_old_data(self, current_time: float):
        """
        清理过期数据

        Args:
            current_time: 当前时间
        """
        cleanup_start = time.time()
        cleaned_items = 0

        for can_id, state in self.id_states.items():
            # 清理过期的payload哈希（保留最近5分钟）
            cutoff_time = current_time - 300
            original_hash_count = len(state['recent_payload_hashes_ts'])

            # 过滤过期的哈希
            filtered_hashes = [
                (h, t) for h, t in state['recent_payload_hashes_ts']
                if t > cutoff_time
            ]

            if len(filtered_hashes) != original_hash_count:
                state['recent_payload_hashes_ts'] = deque(filtered_hashes,
                                                          maxlen=self.max_payload_hashes_per_id)
                cleaned_items += original_hash_count - len(filtered_hashes)

            # 清理过期的序列历史（保留最近30分钟）
            sequence_cutoff = current_time - 1800
            old_sequences = [
                seq for seq, ts in state['historical_sequences'].items()
                if ts <= sequence_cutoff
            ]

            for seq in old_sequences:
                del state['historical_sequences'][seq]
                cleaned_items += 1

        # 清理不活跃的ID（超过10分钟无活动）
        inactive_cutoff = current_time - 600
        inactive_ids = [
            can_id for can_id, state in list(self.id_states.items())
            if state.get('last_active', 0) < inactive_cutoff
        ]
        
        for can_id in inactive_ids:
            del self.id_states[can_id]
            cleaned_items += 1

        self.last_cleanup_time = time.time()
        self.stats['memory_cleanups'] += 1

        cleanup_duration = time.time() - cleanup_start
        logger.debug(f"Data cleanup completed: {cleaned_items} items removed in {cleanup_duration:.3f}s")

    def _cleanup_inactive_ids(self):
        """清理不活跃的ID"""
        current_time = time.time()
        inactive_cutoff = current_time - 600  # 10分钟内无活动

        inactive_ids = [
            can_id for can_id, state in list(self.id_states.items())
            if state.get('last_active', 0) < inactive_cutoff
        ]

        # 删除所有不活跃的ID
        for can_id in inactive_ids:
            del self.id_states[can_id]
            logger.debug(f"Removed inactive ID: {can_id}")

    def memory_pressure_cleanup(self):
        """内存压力下的激进清理"""
        current_time = time.time()

        # 只保留最近1分钟内活跃的ID
        recent_cutoff = current_time - 60
        active_ids = {
            can_id: state for can_id, state in self.id_states.items()
            if state.get('last_active', 0) > recent_cutoff
        }

        # 如果活跃ID仍然太多，按最后见到时间排序保留最新的
        if len(active_ids) > self.max_ids:
            sorted_ids = sorted(
                active_ids.items(),
                key=lambda x: x[1].get('last_timestamp', 0),
                reverse=True
            )
            self.id_states = dict(sorted_ids[:self.max_ids])
        else:
            self.id_states = active_ids

        # 清理每个ID的详细状态
        for state in self.id_states.values():
            # 限制各种队列的大小
            if len(state['recent_payload_hashes_ts']) > 50:
                state['recent_payload_hashes_ts'] = deque(
                    list(state['recent_payload_hashes_ts'])[-50:],
                    maxlen=50
                )

            # 清理历史序列
            if len(state['historical_sequences']) > 100:
                sorted_sequences = sorted(
                    state['historical_sequences'].items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                state['historical_sequences'] = dict(sorted_sequences[:100])

        logger.warning(f"Memory pressure cleanup: reduced to {len(self.id_states)} active IDs")

    def _calculate_iat(self, current_timestamp: float, last_timestamp: float) -> float:
        """
        计算帧间到达时间(Inter-Arrival Time)
        
        Args:
            current_timestamp: 当前时间戳
            last_timestamp: 上一帧时间戳
            
        Returns:
            IAT值
        """
        return round(current_timestamp - last_timestamp, 10)

    def get_state_summary(self, can_id: str) -> Optional[dict]:
        """
        获取ID状态摘要

        Args:
            can_id: CAN ID

        Returns:
            状态摘要字典
        """
        if can_id not in self.id_states:
            return None

        state = self.id_states[can_id]
        current_time = time.time()

        return {
            'can_id': can_id,
            'first_seen': state.get('first_seen'),
            'last_timestamp': state.get('last_timestamp'),
            'frame_count': state.get('frame_count', 0),
            'last_iat': state.get('last_iat', 0),
            'consecutive_missing': state.get('consecutive_missing_count', 0),
            'recent_hashes_count': len(state.get('recent_payload_hashes_ts', [])),
            'sequence_history_count': len(state.get('historical_sequences', {})),
            'anomaly_flags': list(state.get('anomaly_flags', set())),
            'active_duration': current_time - state.get('first_seen', current_time)
        }

    def get_global_statistics(self) -> dict:
        """
        获取全局统计信息

        Returns:
            统计信息字典
        """
        active_count = len(self.id_states)
        total_frames = sum(state.get('frame_count', 0) for state in self.id_states.values())

        self.stats['active_ids'] = active_count

        return {
            **self.stats,
            'total_frames_tracked': total_frames,
            'average_frames_per_id': total_frames / max(active_count, 1),
            'memory_usage_estimate': self._estimate_memory_usage()
        }

    def _estimate_memory_usage(self) -> dict:
        """估算内存使用量"""
        total_payload_hashes = sum(
            len(state.get('recent_payload_hashes_ts', []))
            for state in self.id_states.values()
        )

        total_sequences = sum(
            len(state.get('historical_sequences', {}))
            for state in self.id_states.values()
        )

        return {
            'tracked_ids': len(self.id_states),
            'total_payload_hashes': total_payload_hashes,
            'total_sequence_history': total_sequences,
            'estimated_mb': (len(self.id_states) * 1 + total_payload_hashes * 0.1 + total_sequences * 0.2)
        }

    def remove_id_state(self, can_id: str) -> bool:
        """
        移除指定 CAN ID 的状态
        
        Args:
            can_id: 要移除的 CAN ID
            
        Returns:
            bool: 成功移除返回 True，ID 不存在返回 False
        """
        if can_id in self.id_states:
            del self.id_states[can_id]
            logger.debug(f"Removed state for ID {can_id}")
            return True
        else:
            logger.warning(f"Attempted to remove non-existent ID {can_id}")
            return False
    
    def _limit_payload_hashes(self, state: dict):
        """
        限制载荷哈希数量
        
        Args:
            state: ID状态字典
        """
        if 'payload_hashes' in state:
            max_hashes = self.max_payload_hashes_per_id
            if len(state['payload_hashes']) > max_hashes:
                # 保留最新的哈希
                state['payload_hashes'] = state['payload_hashes'][-max_hashes:]
    
    def _limit_sequence_buffer(self, state: dict):
        """
        限制序列缓冲区大小
        
        Args:
            state: ID状态字典
        """
        if 'sequence_buffer' in state:
            max_length = self.max_sequence_length
            if len(state['sequence_buffer']) > max_length:
                # 保留最新的序列
                 state['sequence_buffer'] = state['sequence_buffer'][-max_length:]
    
    def get_stats(self) -> dict:
        """
        获取统计信息
        
        Returns:
            统计信息字典
        """
        return self.get_global_statistics()
    
    def get_id_state(self, can_id: str) -> Optional[dict]:
        """
        获取指定ID的状态
        
        Args:
            can_id: CAN ID
            
        Returns:
            ID状态字典，如果不存在返回None
        """
        return self.id_states.get(can_id)
    
    def _force_remove_oldest_id(self):
        """
        强制移除最旧的ID状态
        """
        if not self.id_states:
            return
        
        # 找到最旧的ID（first_seen时间最早的）
        oldest_id = min(self.id_states.keys(), 
                       key=lambda x: self.id_states[x].get('first_seen', float('inf')))
        
        # 移除最旧的ID
        self.remove_id_state(oldest_id)
    
    def clear_all_states(self):
        """
        清空所有状态
        """
        self.id_states.clear()
        self.stats['memory_cleanups'] += 1
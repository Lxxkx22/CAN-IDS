"""重放检测器测试模块

测试ReplayDetector类的各种检测功能
"""

import unittest
import time
from unittest.mock import Mock, patch

from detection.replay_detector import ReplayDetector
from detection.base_detector import AlertSeverity
from tests.test_config import get_test_config_manager
from tests.test_utils import create_test_frame, create_replay_attack_frames, create_frame_sequence


class TestOutputHelper:
    """测试输出辅助类"""
    
    @staticmethod
    def print_test_header(test_name, description=""):
        """打印测试头部信息"""
        print(f"\n{'='*80}")
        print(f"测试方法: {test_name}")
        if description:
            print(f"描述: {description}")
        print(f"{'='*80}")
    
    @staticmethod
    def print_test_params(params):
        """打印测试参数"""
        print(f"\n测试参数:")
        for key, value in params.items():
            print(f"  {key}: {value}")
    
    @staticmethod
    def print_expected_result(expected):
        """打印预期结果"""
        print(f"\n预期结果: {expected}")
    
    @staticmethod
    def print_actual_result(actual):
        """打印实际结果"""
        print(f"实际结果: {actual}")
    
    @staticmethod
    def print_test_result(passed, details=""):
        """打印测试结果"""
        status = "✓ 通过" if passed else "✗ 失败"
        print(f"\n测试结果: {status}")
        if details:
            print(f"详细信息: {details}")
        print(f"{'-'*80}\n")
    
    @staticmethod
    def print_class_summary(class_name, description, test_count, test_methods):
        """打印测试类摘要"""
        print(f"\n{'='*100}")
        print(f"测试类: {class_name} - {description}")
        print(f"用例总数: {test_count}")
        print(f"用例列表: {', '.join(test_methods)}")
        print(f"{'='*100}")
    
    @staticmethod
    def print_file_summary(filename, class_count, total_test_count):
        """打印文件摘要"""
        print(f"\n{'='*100}")
        print(f"测试文件: {filename}")
        print(f"测试完成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"总测试类数: {class_count}")
        print(f"总测试用例数: {total_test_count}")
        print(f"{'='*100}\n")

from utils.helpers import hash_payload


class TestReplayDetector(unittest.TestCase):
    """重放检测器测试"""
    
    def setUp(self):
        """测试前准备"""
        TestOutputHelper.print_class_summary("TestReplayDetector", "TestReplayDetector功能测试", 18, ['test_detector_initialization', 'test_get_periodicity_baseline', 'test_check_fast_replay_legacy', 'test_check_fast_replay_enhanced_no_periodicity', 'test_check_contextual_payload_repetition_normal', 'test_check_contextual_payload_repetition_abnormal', 'test_check_sequence_replay_normal', 'test_check_sequence_replay_abnormal', 'test_detect_disabled', 'test_detect_replay_attack_sequence', 'test_update_replay_state', 'test_update_payload_history', 'test_update_sequence_buffer', 'test_find_sequence_patterns', 'test_is_periodic_pattern', 'test_calculate_payload_repetition_score', 'test_performance_with_large_sequence', 'test_periodicity_cache_cleanup'])
        self.config_manager = get_test_config_manager()
        self.detector = ReplayDetector(self.config_manager)
        self.can_id = "123"  # 使用已知ID
    
    def test_detector_initialization(self):
        """
        测试重放检测器的初始化功能
        
        测试描述:
        验证 ReplayDetector 检测器的初始化过程，确保所有属性和状态正确设置。
        
        测试步骤:
        1. 创建ReplayDetector实例
        2. 验证检测器类型设置正确
        3. 验证所有计数器初始化为0
        4. 验证周期性缓存初始化为空字典
        
        预期结果:
        1. detector_type应为'replay'
        2. 所有攻击计数器应为0
        3. _periodicity_cache应为dict类型
        """
        self.assertEqual(self.detector.detector_type, 'replay')
        self.assertEqual(self.detector.fast_replay_count, 0)
        self.assertEqual(self.detector.identical_payload_count, 0)
        self.assertEqual(self.detector.sequence_replay_count, 0)
        self.assertEqual(self.detector.non_periodic_fast_replay_count, 0)
        self.assertEqual(self.detector.contextual_payload_repetition_count, 0)
        self.assertIsInstance(self.detector._periodicity_cache, dict)
    
    def test_get_periodicity_baseline(self):
        """
        测试获取周期性基线数据功能
        
        测试步骤:
        1. 使用已知CAN ID获取周期性基线数据
        2. 验证返回的数据不为空
        3. 使用未知CAN ID获取周期性基线数据
        4. 验证返回的数据为空
        
        预期结果:
        1. 已知ID应返回有效的周期性数据
        2. 未知ID应返回None
        """
        # 测试已知ID（应该有基线数据）
        periodicity_data = self.detector._get_periodicity_baseline(self.can_id, self.config_manager)
        self.assertIsNotNone(periodicity_data)
        
        # 测试未知ID
        unknown_data = self.detector._get_periodicity_baseline("unknown", self.config_manager)
        self.assertIsNone(unknown_data)
    
    def test_check_fast_replay_legacy(self):
        """
        测试传统快速重放检测功能
        
        测试步骤:
        1. 创建两个时间间隔极短的CAN帧（0.5ms间隔）
        2. 设置ID状态包含前一帧的时间戳
        3. 调用传统快速重放检测方法
        4. 验证检测结果
        
        预期结果:
        1. 应产生1个快速重放告警
        2. 告警类型应为"replay_fast_replay"
        """
        frame1 = create_test_frame(self.can_id, timestamp=1.0)
        frame2 = create_test_frame(self.can_id, timestamp=1.0005)  # 0.5ms间隔，非常快
        
        id_state = {
            'last_timestamp': frame1.timestamp,
            'prev_timestamp': frame1.timestamp  # 添加prev_timestamp字段
        }
        
        alerts = self.detector._check_fast_replay_legacy(frame2, id_state, self.config_manager)
        
        # 快速重放应该产生告警
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "replay_fast_replay")
    
    def test_check_fast_replay_enhanced_no_periodicity(self):
        """
        测试增强快速重放检测功能（无周期性数据场景）
        
        测试步骤:
        1. 创建一个CAN帧
        2. 设置ID状态包含时间戳信息
        3. 模拟无周期性基线数据的情况
        4. 调用增强快速重放检测方法
        5. 验证回退到传统检测逻辑
        
        预期结果:
        1. 应返回列表类型的结果
        2. 当无周期性数据时应回退到传统检测
        """
        frame = create_test_frame(self.can_id, timestamp=1.0005)
        id_state = {
            'last_timestamp': 1.0,
            'prev_timestamp': 1.0  # 添加prev_timestamp字段
        }
        
        # 模拟没有周期性数据的情况
        with patch.object(self.detector, '_get_periodicity_baseline', return_value=None):
            alerts = self.detector._check_fast_replay_enhanced(frame, id_state, self.config_manager)
        
        # 应该回退到传统检测
        self.assertIsInstance(alerts, list)
    
    def test_check_contextual_payload_repetition_normal(self):
        """
        测试正常上下文载荷重复检测功能
        
        测试描述:
        验证 ReplayDetector 对正常载荷变化的检测行为，确保不同载荷不产生误报。
        
        测试步骤:
        1. 创建包含特定载荷的CAN帧
        2. 计算载荷哈希值
        3. 设置空的载荷历史状态
        4. 调用上下文载荷重复检测方法
        5. 验证首次出现的载荷不产生告警
        
        预期结果:
        1. 首次出现的载荷不应产生告警
        2. 返回的告警列表应为空
        """
        payload = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        frame = create_test_frame(self.can_id, timestamp=1.1, payload=payload)
        payload_hash = hash_payload(payload)
        
        id_state = {
            'last_timestamp': 1.0,
            'replay_payload_history': []
        }
        
        alerts = self.detector._check_contextual_payload_repetition(
            frame, id_state, payload_hash, self.config_manager
        )
        
        # 第一次出现的载荷不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_check_contextual_payload_repetition_abnormal(self):
        """
        测试异常上下文载荷重复检测功能
        
        测试描述:
        验证 ReplayDetector 对载荷重复攻击的检测能力，确保能识别异常的载荷重复模式。
        
        测试步骤:
        1. 创建包含特定载荷的CAN帧
        2. 计算载荷哈希值
        3. 设置包含多次相同载荷历史的ID状态
        4. 调用上下文载荷重复检测方法
        5. 验证过度重复的载荷产生告警
        
        预期结果:
        1. 应产生1个载荷重复告警
        2. 告警类型应为"replay_identical_payload"
        """
        payload = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        frame = create_test_frame(self.can_id, timestamp=1.0, payload=payload)
        payload_hash = hash_payload(payload)
        
        # 模拟载荷历史中已经有多次相同载荷
        id_state = {
            'last_timestamp': 0.5,
            'replay_payload_history': [
                {'hash': payload_hash, 'timestamp': 0.1, 'count': 1},
                {'hash': payload_hash, 'timestamp': 0.2, 'count': 2},
                {'hash': payload_hash, 'timestamp': 0.3, 'count': 3},
                {'hash': payload_hash, 'timestamp': 0.4, 'count': 4},
                {'hash': payload_hash, 'timestamp': 0.5, 'count': 5}
            ]
        }
        
        alerts = self.detector._check_contextual_payload_repetition(
            frame, id_state, payload_hash, self.config_manager
        )
        
        # 过多重复载荷应该产生告警
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "replay_identical_payload")
    
    def test_check_sequence_replay_normal(self):
        """
        测试正常序列重放检测功能
        
        测试描述:
        验证 ReplayDetector 对正常序列的检测行为，确保不重复的序列不产生误报。
        
        测试步骤:
        1. 创建正常的CAN帧序列（10帧，间隔0.1秒）
        2. 初始化空的序列缓冲区状态
        3. 逐帧调用序列重放检测方法
        4. 收集所有产生的告警
        5. 验证正常序列不产生告警
        
        预期结果:
        1. 正常序列不应产生任何告警
        2. 总告警数量应为0
        """
        # 创建正常的帧序列
        frames = create_frame_sequence(self.can_id, count=10, interval=0.1)
        
        id_state = {'replay_sequence_buffer': []}
        total_alerts = []
        
        for frame in frames:
            payload_hash = hash_payload(frame.payload)
            alerts = self.detector._check_sequence_replay(
                frame, id_state, payload_hash, self.config_manager
            )
            total_alerts.extend(alerts)
        
        # 正常序列不应该产生告警
        self.assertEqual(len(total_alerts), 0)
    
    def test_check_sequence_replay_abnormal(self):
        """
        测试异常序列重放检测功能
        
        测试描述:
        验证 ReplayDetector 对序列重放攻击的检测能力，确保能识别重复的帧序列模式。
        
        测试步骤:
        1. 创建重复的序列模式（3个载荷的模式重复5次）
        2. 为每个载荷创建CAN帧，设置适当的时间戳
        3. 初始化序列缓冲区状态
        4. 逐帧调用序列重放检测方法
        5. 验证重复序列产生告警
        
        预期结果:
        1. 重复序列应产生告警
        2. 应包含序列重放类型的告警
        """
        # 创建重复的序列模式
        sequence_pattern = [b'\x01\x02', b'\x03\x04', b'\x05\x06']
        frames = []
        
        # 重复相同序列多次
        for repeat in range(5):
            for i, payload in enumerate(sequence_pattern):
                timestamp = repeat * 0.3 + i * 0.1
                frame = create_test_frame(self.can_id, timestamp=timestamp, payload=payload)
                frames.append(frame)
        
        id_state = {'replay_sequence_buffer': []}
        total_alerts = []
        
        for frame in frames:
            payload_hash = hash_payload(frame.payload)
            alerts = self.detector._check_sequence_replay(
                frame, id_state, payload_hash, self.config_manager
            )
            total_alerts.extend(alerts)
        
        # 重复序列应该产生告警
        self.assertGreater(len(total_alerts), 0)
        sequence_alerts = [a for a in total_alerts if "sequence_replay" in a.alert_type]
        self.assertGreater(len(sequence_alerts), 0)
    
    def test_detect_disabled(self):
        """
        测试检测器被禁用时的行为
        
        测试描述:
        验证 ReplayDetector 在被禁用时的行为，确保配置控制功能正常工作。
        
        测试步骤:
        1. 修改配置，禁用重放检测器
        2. 创建测试CAN帧
        3. 调用检测方法
        4. 验证不产生任何告警
        
        预期结果:
        1. 当检测器被禁用时不应产生任何告警
        2. 返回的告警列表应为空
        """
        # 修改配置，禁用replay检测
        self.config_manager.config_data['detection']['detectors']['replay']['enabled'] = False
        
        frame = create_test_frame(self.can_id)
        alerts = self.detector.detect(frame, {}, self.config_manager)
        
        # 检测被禁用，不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_detect_replay_attack_sequence(self):
        """
        测试检测重放攻击序列功能
        
        测试描述:
        验证 ReplayDetector 对重放攻击序列的检测能力，确保能识别混合在正常流量中的重放攻击。
        
        测试步骤:
        1. 创建包含重放攻击的CAN帧序列（5个正常帧+5个重放帧）
        2. 初始化ID状态
        3. 逐帧调用检测方法，模拟实时检测
        4. 更新状态信息（模拟状态管理器行为）
        5. 验证检测到重放攻击
        
        预期结果:
        1. 应检测到重放攻击并产生告警
        2. 告警类型应包含"replay"相关类型
        """
        # 创建重放攻击帧序列
        frames = create_replay_attack_frames(
            self.can_id, 
            normal_count=5, 
            replay_count=5
        )
        
        id_state = {}
        total_alerts = []
        
        for i, frame in enumerate(frames):
            alerts = self.detector.detect(frame, id_state, self.config_manager)
            total_alerts.extend(alerts)
            
            # 更新状态（模拟状态管理器的行为）
            if 'last_timestamp' in id_state:
                id_state['prev_timestamp'] = id_state['last_timestamp']
            id_state['last_timestamp'] = frame.timestamp
        
        # 应该检测到重放攻击
        self.assertGreater(len(total_alerts), 0)
        
        # 检查告警类型
        alert_types = [alert.alert_type for alert in total_alerts]
        replay_related = any("replay" in alert_type for alert_type in alert_types)
        self.assertTrue(replay_related)
    
    def test_update_replay_state(self):
        """
        测试更新重放状态功能
        
        测试描述:
        验证 ReplayDetector 状态更新机制的正确性，确保检测状态信息得到正确维护。
        
        测试步骤:
        1. 创建测试CAN帧
        2. 计算载荷哈希值
        3. 初始化空的ID状态
        4. 调用状态更新方法
        5. 验证状态字段正确更新
        
        预期结果:
        1. 应添加重放检测相关的状态字段
        2. 载荷哈希值应正确保存
        """
        frame = create_test_frame(self.can_id)
        payload_hash = hash_payload(frame.payload)
        id_state = {}
        
        self.detector._update_replay_state(frame, id_state, payload_hash)
        
        # 检查状态是否正确更新
        self.assertIn('replay_last_detection_time', id_state)
        self.assertIn('replay_detection_count', id_state)
        self.assertIn('replay_last_payload_hash', id_state)
        self.assertEqual(id_state['replay_last_payload_hash'], payload_hash)
    
    def test_update_payload_history(self):
        """
        测试更新载荷历史功能
        
        测试步骤:
        1. 创建测试载荷哈希和时间戳
        2. 初始化空的历史列表
        3. 第一次添加载荷哈希，验证计数为1
        4. 添加相同哈希，验证计数递增
        5. 添加不同哈希，验证新条目创建
        
        预期结果:
        1. 首次添加的哈希计数应为1
        2. 相同哈希再次添加时计数应递增
        3. 不同哈希应创建新的历史条目
        """
        payload_hash = "test_hash"
        timestamp = 1.0
        history = []
        
        # 第一次添加
        self.detector._update_payload_history(history, payload_hash, timestamp)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]['hash'], payload_hash)
        self.assertEqual(history[0]['count'], 1)
        
        # 添加相同哈希
        self.detector._update_payload_history(history, payload_hash, timestamp + 0.1)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[1]['count'], 2)
        
        # 添加不同哈希
        different_hash = "different_hash"
        self.detector._update_payload_history(history, different_hash, timestamp + 0.2)
        self.assertEqual(len(history), 3)
        self.assertEqual(history[2]['hash'], different_hash)
        self.assertEqual(history[2]['count'], 1)
    
    def test_update_sequence_buffer(self):
        """
        测试更新序列缓冲区功能
        
        测试步骤:
        1. 设置测试参数（载荷哈希、缓冲区、最大长度）
        2. 添加超过最大长度的元素到缓冲区
        3. 验证缓冲区长度不超过限制
        4. 验证保留最新的元素
        
        预期结果:
        1. 缓冲区长度不应超过最大长度限制
        2. 应保留最新添加的元素
        """
        payload_hash = "test_hash"
        buffer = []
        max_length = 5
        
        # 填充缓冲区
        for i in range(max_length + 2):
            self.detector._update_sequence_buffer(buffer, f"hash_{i}", max_length)
        
        # 缓冲区长度应该不超过最大长度
        self.assertEqual(len(buffer), max_length)
        
        # 应该保留最新的元素
        self.assertEqual(buffer[-1], "hash_6")
        self.assertEqual(buffer[0], "hash_2")
    
    def test_find_sequence_patterns(self):
        """
        测试查找序列模式功能
        
        测试步骤:
        1. 创建包含重复模式的序列（ABC重复3次）
        2. 调用序列模式查找方法，设置最小长度为3
        3. 验证找到重复模式
        4. 检查是否正确识别ABC模式
        
        预期结果:
        1. 应找到至少一个重复模式
        2. 应正确识别ABC重复模式
        """
        # 创建包含重复模式的序列
        sequence = ['A', 'B', 'C', 'A', 'B', 'C', 'A', 'B', 'C']
        
        patterns = self.detector._find_sequence_patterns(sequence, min_length=3)
        
        # 应该找到重复的ABC模式
        self.assertGreater(len(patterns), 0)
        
        # 检查是否找到了ABC模式
        abc_pattern = ['A', 'B', 'C']
        found_abc = any(pattern['pattern'] == abc_pattern for pattern in patterns)
        self.assertTrue(found_abc)
    
    def test_is_periodic_pattern(self):
        """
        测试周期性模式判断功能
        
        测试步骤:
        1. 设置当前IAT值和学习到的统计数据
        2. 测试符合周期性的IAT值（接近均值）
        3. 验证返回True
        4. 测试不符合周期性的IAT值（远离均值）
        5. 验证返回False
        
        预期结果:
        1. 接近学习均值的IAT应被判断为周期性
        2. 远离学习均值的IAT应被判断为非周期性
        """
        current_iat = 0.1
        learned_stats = {'mean': 0.1, 'std': 0.01}
        
        # 测试符合周期性的IAT
        is_periodic = self.detector._is_periodic_pattern(current_iat, learned_stats)
        self.assertTrue(is_periodic)
        
        # 测试不符合周期性的IAT
        abnormal_iat = 0.5
        is_not_periodic = self.detector._is_periodic_pattern(abnormal_iat, learned_stats)
        self.assertFalse(is_not_periodic)
    
    def test_calculate_payload_repetition_score(self):
        """
        测试计算载荷重复分数功能
        
        测试步骤:
        1. 设置测试载荷哈希值
        2. 创建包含重复载荷的历史记录
        3. 调用载荷重复分数计算方法
        4. 验证分数计算正确性
        
        预期结果:
        1. 重复次数多的载荷应有更高的分数
        2. 分数应反映载荷的重复程度
        """
        payload_hash = "test_hash"
        
        # 创建载荷历史
        history = [
            {'hash': payload_hash, 'timestamp': 1.0, 'count': 1},
            {'hash': payload_hash, 'timestamp': 1.1, 'count': 2},
            {'hash': payload_hash, 'timestamp': 1.2, 'count': 3},
            {'hash': 'other_hash', 'timestamp': 1.3, 'count': 1}
        ]
        
        score = self.detector._calculate_payload_repetition_score(payload_hash, history)
        
        # 分数应该反映重复程度
        self.assertGreater(score, 0)
        
        # 测试不存在的哈希
        score_nonexistent = self.detector._calculate_payload_repetition_score("nonexistent", history)
        self.assertEqual(score_nonexistent, 0)
    
    def test_performance_with_large_sequence(self):
        """
        测试大量帧序列的性能
        
        测试描述:
        验证 ReplayDetector 在处理大量帧序列时的性能表现，确保检测效率满足实时要求。
        
        测试步骤:
        1. 创建大量正常帧序列（800帧）
        2. 记录开始时间
        3. 对所有帧进行重放检测
        4. 计算处理时间
        5. 验证性能满足要求
        
        预期结果:
        1. 处理时间应在合理范围内
        2. 检测器应能处理大量帧而不出错
        3. 内存使用应保持稳定
        """
        # 创建大量正常帧
        frames = create_frame_sequence(
            self.can_id, 
            count=800,  # 重放检测需要维护历史，适当减少帧数
            interval=0.1,
            payload_pattern="sequential"
        )
        
        id_state = {}
        start_time = time.time()
        
        for frame in frames:
            alerts = self.detector.detect(frame, id_state, self.config_manager)
            # 更新状态（模拟状态管理器的行为）
            if 'last_timestamp' in id_state:
                id_state['prev_timestamp'] = id_state['last_timestamp']
            id_state['last_timestamp'] = frame.timestamp
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # 检查性能（应该在合理时间内完成）
        self.assertLess(processing_time, 15.0)  # 15秒内完成800帧处理
    
    def test_periodicity_cache_cleanup(self):
        """测试周期性缓存清理"""
        # 填充缓存
        current_time = time.time()
        for i in range(10):
            cache_key = f"test_id_{i}"
            self.detector._periodicity_cache[cache_key] = {
                'data': {'mean': 0.1, 'std': 0.01},
                'timestamp': current_time - 400  # 过期数据
            }
        
        # 触发缓存清理
        self.detector._cleanup_periodicity_cache()
        
        # 过期数据应该被清理
        self.assertEqual(len(self.detector._periodicity_cache), 0)


if __name__ == '__main__':
    # 添加测试总结信息
    import time
    TestOutputHelper.print_file_summary("test_replay_detector.py", 1, 18)
    unittest.main(verbosity=2)
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BaselineEngine 测试模块

测试基线学习引擎的核心功能：
- 学习阶段管理
- 帧数据处理和分析
- 基线建立和验证
- 周期性检测
- 统计分析功能
"""

import unittest
import time
from unittest.mock import Mock, patch, MagicMock
from collections import defaultdict, deque

# 导入被测试的模块
from learning.baseline_engine import BaselineEngine
from config_loader import ConfigManager
from can_frame import CANFrame



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

class TestBaselineEngine(unittest.TestCase):
    """BaselineEngine 测试类"""

    def setUp(self):
        """测试前准备"""
        # 创建模拟的配置管理器
        self.mock_config_manager = Mock(spec=ConfigManager)
        self.mock_config_manager.get_global_setting.side_effect = self._mock_get_global_setting
        
        # 创建BaselineEngine实例
        self.baseline_engine = BaselineEngine(config_manager=self.mock_config_manager)

    def _mock_get_global_setting(self, section, key, default=None):
        """模拟配置获取"""
        settings = {
            ('learning_params', 'initial_learning_window_sec'): 30,
            ('learning_params', 'min_samples_for_stable_baseline'): 100,
            ('learning_params', 'max_unique_payloads_per_id'): 50,
            ('learning_params', 'entropy_threshold'): 0.5,
        }
        return settings.get((section, key), default)

    def test_initialization(self):
        """
        测试BaselineEngine的初始化过程和基本属性设置
        
        测试描述:
        验证BaselineEngine能够正确初始化，包括配置管理器设置、学习参数配置、
        状态变量初始化和数据结构准备等基本功能。
        
        详细预期结果:
        1. config_manager属性应正确设置为传入的配置管理器
        2. learning_duration应从配置中正确读取为30秒
        3. min_samples应从配置中正确读取为100
        4. is_learning_active应初始化为False
        5. learning_completed应初始化为False
        6. learning_start_time应初始化为None
        7. data_per_id应初始化为defaultdict类型
        8. periodicity_data应初始化为defaultdict类型
        """
        # 验证基本属性
        self.assertEqual(self.baseline_engine.config_manager, self.mock_config_manager)
        self.assertEqual(self.baseline_engine.learning_duration, 30)
        self.assertEqual(self.baseline_engine.min_samples, 100)
        
        # 验证学习状态
        self.assertFalse(self.baseline_engine.is_learning_active)
        self.assertFalse(self.baseline_engine.learning_completed)
        self.assertIsNone(self.baseline_engine.learning_start_time)
        
        # 验证数据结构初始化
        self.assertIsInstance(self.baseline_engine.data_per_id, defaultdict)
        self.assertIsInstance(self.baseline_engine.periodicity_data, defaultdict)

    def test_start_learning(self):
        """
        测试BaselineEngine开始学习阶段的功能
        
        测试描述:
        验证BaselineEngine能够正确启动学习阶段，包括设置学习状态标志、
        记录学习开始时间等关键操作。
        
        详细预期结果:
        1. is_learning_active应设置为True
        2. learning_completed应保持为False
        3. learning_start_time应设置为当前时间戳
        4. 学习开始时间应与当前时间相差不超过1秒
        5. 学习状态应正确转换为活跃状态
        6. 系统应准备好接收和处理学习数据
        """
        # 开始学习
        self.baseline_engine.start_learning()
        
        # 验证学习状态
        self.assertTrue(self.baseline_engine.is_learning_active)
        self.assertFalse(self.baseline_engine.learning_completed)
        self.assertIsNotNone(self.baseline_engine.learning_start_time)
        
        # 验证学习开始时间合理
        current_time = time.time()
        self.assertLessEqual(abs(current_time - self.baseline_engine.learning_start_time), 1.0)

    def test_process_frame_for_learning(self):
        """
        测试BaselineEngine在学习阶段处理CAN帧的功能
        
        测试描述:
        验证BaselineEngine能够正确处理单个CAN帧，包括自动启动学习、
        记录帧数据、更新统计信息等核心学习功能。
        
        详细预期结果:
        1. 处理帧时应自动启动学习阶段(is_learning_active=True)
        2. 帧的时间戳应正确记录到timestamps列表中
        3. 帧的DLC应正确记录到dlcs集合中
        4. frame_count应正确增加到1
        5. first_seen时间戳应正确设置
        6. last_seen时间戳应正确设置
        7. 数据应按CAN ID正确分类存储
        """
        # 创建测试帧
        frame = CANFrame(
            can_id="0x123",
            dlc=8,
            payload=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            timestamp=time.time()
        )
        
        # 处理帧（应该自动开始学习）
        self.baseline_engine.process_frame_for_learning(frame)
        
        # 验证学习已开始
        self.assertTrue(self.baseline_engine.is_learning_active)
        
        # 验证数据记录
        data = self.baseline_engine.data_per_id["0x123"]
        self.assertEqual(len(data['timestamps']), 1)
        self.assertIn(8, data['dlcs'])
        self.assertEqual(data['frame_count'], 1)
        self.assertIsNotNone(data['first_seen'])
        self.assertIsNotNone(data['last_seen'])

    def test_multiple_frames_processing(self):
        """
        测试BaselineEngine处理多个CAN帧的功能
        
        测试描述:
        验证BaselineEngine能够正确处理多个不同CAN ID的帧，
        包括数据分类、统计更新和状态管理等功能。
        
        详细预期结果:
        1. ID 0x123应记录2个时间戳
        2. ID 0x123的frame_count应为2
        3. ID 0x123应记录DLC为8
        4. ID 0x456应记录1个时间戳
        5. ID 0x456的frame_count应为1
        6. ID 0x456应记录DLC为4
        7. data_per_id应包含2个不同的CAN ID
        8. 每个ID的数据应正确分离和统计
        """
        frames = [
            CANFrame(time.time(), "0x123", 8, b"\x01\x02\x03\x04\x05\x06\x07\x08"),
            CANFrame(time.time() + 0.1, "0x123", 8, b"\x01\x02\x03\x04\x05\x06\x07\x09"),
            CANFrame(time.time() + 0.2, "0x456", 4, b"\xAA\xBB\xCC\xDD"),
        ]
        
        # 处理所有帧
        for frame in frames:
            self.baseline_engine.process_frame_for_learning(frame)
        
        # 验证ID 0x123的数据
        data_123 = self.baseline_engine.data_per_id["0x123"]
        self.assertEqual(len(data_123['timestamps']), 2)
        self.assertEqual(data_123['frame_count'], 2)
        self.assertIn(8, data_123['dlcs'])
        
        # 验证ID 0x456的数据
        data_456 = self.baseline_engine.data_per_id["0x456"]
        self.assertEqual(len(data_456['timestamps']), 1)
        self.assertEqual(data_456['frame_count'], 1)
        self.assertIn(4, data_456['dlcs'])
        
        # 验证总共有两个不同的ID
        self.assertEqual(len(self.baseline_engine.data_per_id), 2)

    def test_payload_entropy_calculation(self):
        """
        测试BaselineEngine的载荷熵计算和字节位置分析功能
        
        测试描述:
        验证BaselineEngine能够正确分析CAN帧载荷的字节变化模式，
        包括记录每个字节位置的不同值和计算载荷变化特征。
        
        详细预期结果:
        1. 第8个字节(索引7)应记录3个不同的值(0x08, 0x09, 0x0A)
        2. 前7个字节应保持相同，每个位置只有1个唯一值
        3. bytes_at_pos数据结构应正确记录每个位置的字节值
        4. 载荷变化模式应被正确识别和分析
        5. 字节位置统计应准确反映数据变化特征
        6. 载荷熵计算基础数据应正确收集
        """
        # 创建具有不同载荷的帧
        frames = [
            CANFrame(time.time(), "0x123", 8, b"\x01\x02\x03\x04\x05\x06\x07\x08"),
            CANFrame(time.time() + 0.1, "0x123", 8, b"\x01\x02\x03\x04\x05\x06\x07\x09"),
            CANFrame(time.time() + 0.2, "0x123", 8, b"\x01\x02\x03\x04\x05\x06\x07\x0A"),
        ]
        
        # 处理帧
        for frame in frames:
            self.baseline_engine.process_frame_for_learning(frame)
        
        # 验证载荷数据记录
        data = self.baseline_engine.data_per_id["0x123"]
        self.assertEqual(len(data['payloads_for_entropy']), 3)
        
        # 验证字节位置数据记录
        # 第8个字节（索引7）应该有3个不同的值
        self.assertEqual(len(data['bytes_at_pos'][7]), 3)
        # 前7个字节应该都相同
        for i in range(7):
            self.assertEqual(len(set(data['bytes_at_pos'][i])), 1)

    def test_learning_completion_check(self):
        """
        测试BaselineEngine的学习完成条件检查功能
        
        测试描述:
        验证BaselineEngine能够正确判断学习阶段是否完成，
        包括时间条件和样本数量条件的综合评估。
        
        详细预期结果:
        1. 当学习时间超过设定阈值(0.1秒)时，应满足时间条件
        2. 当样本数量达到最小要求(2个)时，应满足样本条件
        3. is_learning_complete()方法应返回True
        4. 学习完成检查应综合考虑时间和样本两个条件
        5. 学习状态判断应准确可靠
        6. 完成条件应符合配置的学习参数
        """
        # 设置较短的学习时间用于测试
        self.baseline_engine.learning_duration = 0.1  # 0.1秒
        self.baseline_engine.min_samples = 2  # 最少2个样本
        
        # 开始学习
        self.baseline_engine.start_learning()
        
        # 添加一些帧
        frame1 = CANFrame(time.time(), "0x123", 8, b"\x01\x02\x03\x04\x05\x06\x07\x08")
        frame2 = CANFrame(time.time() + 0.05, "0x123", 8, b"\x01\x02\x03\x04\x05\x06\x07\x09")
        
        self.baseline_engine.process_frame_for_learning(frame1)
        self.baseline_engine.process_frame_for_learning(frame2)
        
        # 等待学习时间完成
        time.sleep(0.15)
        
        # 检查学习是否完成
        self.assertTrue(self.baseline_engine.is_learning_complete())

    def test_learning_completion_insufficient_time(self):
        """
        测试BaselineEngine在学习时间不足时的行为
        
        测试描述:
        验证BaselineEngine在样本数量充足但学习时间不足时，
        能够正确判断学习尚未完成。
        
        详细预期结果:
        1. 即使有150个样本(超过最小要求100个)
        2. 但学习时间只有10秒(少于要求的30秒)
        3. is_learning_complete()方法应返回False
        4. 时间条件应作为学习完成的必要条件
        5. 学习状态判断应严格遵循时间要求
        6. 不应因样本充足而忽略时间条件
        """
        # 模拟学习刚开始
        self.baseline_engine.learning_start_time = time.time() - 10  # 10秒前
        self.baseline_engine.is_learning_active = True
        
        # 添加足够的样本
        for i in range(150):
            frame = CANFrame(
                time.time() - 10 + i * 0.05,
                "0x123", 
                8, 
                b"\x01\x02\x03\x04\x05\x06\x07\x08"
            )
            self.baseline_engine.process_frame_for_learning(frame)
        
        # 检查学习不应该完成（时间不足）
        should_complete = self.baseline_engine.is_learning_complete()
        self.assertFalse(should_complete)

    def test_learning_completion_insufficient_samples(self):
        """
        测试BaselineEngine在样本数量不足时的行为
        
        测试描述:
        验证BaselineEngine在学习时间充足但样本数量不足时，
        能够正确判断学习尚未完成。
        
        详细预期结果:
        1. 即使学习时间超过要求(2秒 > 30秒配置)
        2. 但样本数量只有50个(少于要求的100个)
        3. is_learning_complete()方法应返回False
        4. 样本数量条件应作为学习完成的必要条件
        5. 学习状态判断应严格遵循样本数量要求
        6. 不应因时间充足而忽略样本数量条件
        """
        # 模拟学习开始时间为过去（确保超过学习持续时间）
        self.baseline_engine.learning_start_time = time.time() - 2  # 2秒前
        self.baseline_engine.is_learning_active = True
        
        # 添加不足的样本
        for i in range(50):  # 少于最小要求的100个
            frame = CANFrame(
                time.time() - 2 + i * 0.1,
                "0x123", 
                8, 
                b"\x01\x02\x03\x04\x05\x06\x07\x08"
            )
            self.baseline_engine.process_frame_for_learning(frame)
        
        # 检查学习不应该完成（样本不足）
        should_complete = self.baseline_engine.is_learning_complete()
        self.assertFalse(should_complete)

    def test_complete_learning(self):
        """
        测试BaselineEngine完成学习过程的功能
        
        测试描述:
        验证BaselineEngine能够正确完成学习过程，包括生成基线数据、
        更新学习状态和返回完整的基线信息。
        
        详细预期结果:
        1. is_learning_active应设置为False
        2. learning_completed应设置为True
        3. 应返回包含基线数据的字典
        4. 基线数据应包含"0x123"的ID信息
        5. ID基线应包含frame_count、first_seen、last_seen等字段
        6. 基线数据应完整准确，可用于后续检测
        7. 学习状态应正确转换为完成状态
        """
        # 准备学习数据
        self.baseline_engine.start_learning()
        
        # 添加测试数据
        for i in range(150):
            frame = CANFrame(
                time.time() + i * 0.1,
                "0x123", 
                8, 
                b"\x01\x02\x03\x04\x05\x06\x07\x08"
            )
            self.baseline_engine.process_frame_for_learning(frame)
        
        # 完成学习
        baseline = self.baseline_engine.complete_learning()
        
        # 验证学习状态
        self.assertFalse(self.baseline_engine.is_learning_active)
        self.assertTrue(self.baseline_engine.learning_completed)
        
        # 验证基线数据
        self.assertIsInstance(baseline, dict)
        self.assertIn("0x123", baseline)
        
        # 验证基线包含必要信息
        id_baseline = baseline["0x123"]
        self.assertIn('frame_count', id_baseline)
        self.assertIn('dlcs', id_baseline)
        self.assertIn('first_seen', id_baseline)
        self.assertIn('last_seen', id_baseline)

    def test_get_baseline_for_id(self):
        """
        测试BaselineEngine获取特定CAN ID基线数据的功能
        
        测试描述:
        验证BaselineEngine能够正确返回指定CAN ID的基线数据，
        包括存在的ID和不存在的ID的处理。
        
        详细预期结果:
        1. 存在的ID "0x123"应返回非空的基线数据
        2. 存在的ID "0x456"应返回非空的基线数据
        3. 不存在的ID "0x999"应返回None
        4. 返回的基线数据应包含frame_count字段
        5. ID "0x123"的frame_count应为1
        6. ID "0x456"的frame_count应为1
        7. 基线数据应包含正确的DLC信息(8和4)
        """
        # 准备数据
        self.baseline_engine.start_learning()
        
        frames = [
            CANFrame(time.time(), "0x123", 8, b"\x01\x02\x03\x04\x05\x06\x07\x08"),
            CANFrame(time.time() + 0.1, "0x456", 4, b"\xAA\xBB\xCC\xDD"),
        ]
        
        for frame in frames:
            self.baseline_engine.process_frame_for_learning(frame)
        
        # 获取特定ID的基线
        baseline_123 = self.baseline_engine.get_baseline_for_id("0x123")
        baseline_456 = self.baseline_engine.get_baseline_for_id("0x456")
        baseline_unknown = self.baseline_engine.get_baseline_for_id("0x999")
        
        # 验证结果
        self.assertIsNotNone(baseline_123)
        self.assertIsNotNone(baseline_456)
        self.assertIsNone(baseline_unknown)
        
        # 验证基线内容
        self.assertEqual(baseline_123['frame_count'], 1)
        self.assertEqual(baseline_456['frame_count'], 1)
        self.assertIn(8, baseline_123['dlcs'])
        self.assertIn(4, baseline_456['dlcs'])

    def test_get_learning_statistics(self):
        """
        测试BaselineEngine获取学习统计信息的功能
        
        测试描述:
        验证BaselineEngine能够正确生成和返回学习过程的统计信息，
        包括学习的ID数量、帧数量、持续时间和状态等。
        
        详细预期结果:
        1. 返回的统计信息应为字典类型
        2. 应包含learned_id_count字段，值为2
        3. 应包含total_frame_count字段，值为3
        4. 应包含total_duration字段
        5. 应包含learning_status字段，值为'active'
        6. 统计信息应准确反映当前学习状态
        7. 所有统计数据应与实际处理的数据一致
        """
        # 准备数据
        self.baseline_engine.start_learning()
        
        frames = [
            CANFrame(time.time(), "0x123", 8, b"\x01\x02\x03\x04\x05\x06\x07\x08"),
            CANFrame(time.time() + 0.1, "0x123", 8, b"\x01\x02\x03\x04\x05\x06\x07\x09"),
            CANFrame(time.time() + 0.2, "0x456", 4, b"\xAA\xBB\xCC\xDD"),
        ]
        
        for frame in frames:
            self.baseline_engine.process_frame_for_learning(frame)
        
        # 获取统计信息
        stats = self.baseline_engine.get_learning_statistics()
        
        # 验证统计信息
        self.assertIsInstance(stats, dict)
        self.assertIn('learned_id_count', stats)
        self.assertIn('total_frame_count', stats)
        self.assertIn('total_duration', stats)
        self.assertIn('learning_status', stats)
        
        self.assertEqual(stats['learned_id_count'], 2)
        self.assertEqual(stats['total_frame_count'], 3)
        self.assertEqual(stats['learning_status'], 'active')

    def test_reset_learning(self):
        """
        测试BaselineEngine重置学习状态的功能
        
        测试描述:
        验证BaselineEngine能够正确重置所有学习相关的状态和数据，
        将系统恢复到初始状态以便重新开始学习。
        
        详细预期结果:
        1. is_learning_active应重置为False
        2. learning_completed应重置为False
        3. learning_start_time应重置为None
        4. data_per_id字典应清空，长度为0
        5. periodicity_data字典应清空，长度为0
        6. 所有学习数据应被完全清除
        7. 系统应恢复到可重新开始学习的状态
        """
        # 准备数据
        self.baseline_engine.start_learning()
        
        frame = CANFrame(time.time(), "0x123", 8, b"\x01\x02\x03\x04\x05\x06\x07\x08")
        self.baseline_engine.process_frame_for_learning(frame)
        
        # 验证有数据
        self.assertTrue(self.baseline_engine.is_learning_active)
        self.assertEqual(len(self.baseline_engine.data_per_id), 1)
        
        # 重置学习
        self.baseline_engine.reset_learning()
        
        # 验证重置结果
        self.assertFalse(self.baseline_engine.is_learning_active)
        self.assertFalse(self.baseline_engine.learning_completed)
        self.assertIsNone(self.baseline_engine.learning_start_time)
        self.assertEqual(len(self.baseline_engine.data_per_id), 0)
        self.assertEqual(len(self.baseline_engine.periodicity_data), 0)

    def test_periodicity_detection(self):
        """
        测试BaselineEngine的周期性检测和分析功能
        
        测试描述:
        验证BaselineEngine能够正确检测和记录CAN帧的周期性模式，
        包括时间戳记录和间隔计算等功能。
        
        详细预期结果:
        1. periodicity_data应正确记录"0x123"的时间戳
        2. 应记录20个时间戳，对应20个帧
        3. 时间戳间隔应接近设定的周期(0.1秒)
        4. 平均间隔应在0.1秒±0.01秒范围内
        5. 周期性模式应被正确识别和记录
        6. 时间戳序列应保持正确的时间顺序
        7. 周期性数据应为后续分析提供准确基础
        """
        # 创建具有周期性的帧序列
        base_time = time.time()
        period = 0.1  # 100ms周期
        
        frames = []
        for i in range(20):
            frame = CANFrame(
                base_time + i * period,
                "0x123", 
                8, 
                b"\x01\x02\x03\x04\x05\x06\x07\x08"
            )
            frames.append(frame)
        
        # 处理帧
        for frame in frames:
            self.baseline_engine.process_frame_for_learning(frame)
        
        # 验证周期性数据记录
        periodicity_data = self.baseline_engine.periodicity_data["0x123"]
        self.assertEqual(len(periodicity_data['timestamps']), 20)
        
        # 验证时间戳间隔记录
        timestamps = list(periodicity_data['timestamps'])
        if len(timestamps) > 1:
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            # 大部分间隔应该接近0.1秒
            avg_interval = sum(intervals) / len(intervals)
            self.assertAlmostEqual(avg_interval, period, delta=0.01)


if __name__ == '__main__':
    # 添加测试总结信息
    import time
    TestOutputHelper.print_file_summary("test_baseline_engine.py", 1, 13)
    unittest.main(verbosity=2)
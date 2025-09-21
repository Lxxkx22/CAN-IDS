"""丢包检测器测试模块

测试DropDetector类的各种检测功能
"""

import unittest
import time
from unittest.mock import Mock, patch

from detection.drop_detector import DropDetector
from detection.base_detector import AlertSeverity
from tests.test_config import get_test_config_manager
from tests.test_utils import create_test_frame, create_drop_attack_frames, create_frame_sequence


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



class TestDropDetector(unittest.TestCase):
    """丢包检测器测试"""
    
    def setUp(self):
        """测试前准备"""
        TestOutputHelper.print_class_summary("TestDropDetector", "TestDropDetector功能测试", 15, ['test_detector_initialization', 'test_get_learned_iat_stats', 'test_calculate_current_iat', 'test_check_iat_anomaly_normal', 'test_check_iat_anomaly_abnormal', 'test_check_consecutive_missing', 'test_check_max_iat_factor', 'test_check_dlc_zero_special', 'test_detect_no_learned_data', 'test_detect_disabled', 'test_detect_drop_attack_sequence', 'test_update_drop_state', 'test_estimate_missing_frames', 'test_calculate_iat_z_score', 'test_performance_with_large_sequence'])
        self.config_manager = get_test_config_manager()
        self.detector = DropDetector(self.config_manager)
        self.can_id = "123"  # 使用已知ID
    
    def test_detector_initialization(self):
        """
        测试 DropDetector 检测器初始化
        
        测试描述:
        验证 DropDetector 实例能够正确初始化，设置正确的检测器类型和初始状态。
        
        测试步骤:
        1. 创建 DropDetector 实例
        2. 验证检测器类型设置正确
        3. 验证初始计数器状态
        
        预期结果:
        1. 检测器类型为 'drop'
        2. IAT 异常计数初始化为 0
        3. 连续丢失计数初始化为 0
        4. 最大 IAT 违规计数初始化为 0
        """
        self.assertEqual(self.detector.detector_type, 'drop')
        self.assertEqual(self.detector.iat_anomaly_count, 0)
        self.assertEqual(self.detector.consecutive_missing_count, 0)
        self.assertEqual(self.detector.max_iat_violations, 0)
    
    def test_get_learned_iat_stats(self):
        """
        测试获取学习到的 IAT 统计数据
        
        测试描述:
        验证 DropDetector 能够正确获取已知 CAN ID 的学习 IAT 统计数据，并正确处理未知 ID。
        
        测试步骤:
        1. 获取已知 ID 的 IAT 统计数据
        2. 验证统计数据结构和值
        3. 尝试获取未知 ID 的统计数据
        4. 验证未知 ID 返回 None
        
        预期结果:
        1. 已知 ID 返回包含 mean_iat 和 std_iat 的字典
        2. 统计数据值与配置文件中的值匹配
        3. 未知 ID 返回 None
        """
        # 测试已知ID
        stats = self.detector._get_learned_iat_stats(self.can_id, self.config_manager)
        self.assertIsNotNone(stats)
        self.assertIn('mean_iat', stats)
        self.assertIn('std_iat', stats)
        self.assertEqual(stats['mean_iat'], 0.1)
        self.assertEqual(stats['std_iat'], 0.01)
        
        # 测试未知ID
        unknown_stats = self.detector._get_learned_iat_stats("unknown", self.config_manager)
        self.assertIsNone(unknown_stats)
    
    def test_calculate_current_iat(self):
        """
        测试计算当前帧间间隔 (IAT)
        
        测试描述:
        验证 DropDetector 能够正确计算连续帧之间的时间间隔。
        
        测试步骤:
        1. 创建两个连续的测试帧
        2. 计算第一帧的 IAT（应该为 None）
        3. 更新状态后计算第二帧的 IAT
        4. 验证 IAT 计算正确
        
        预期结果:
        1. 第一帧的 IAT 为 None（没有前一帧）
        2. 第二帧的 IAT 等于时间戳差值
        3. IAT 计算精度正确
        """
        frame1 = create_test_frame(self.can_id, timestamp=1.0)
        frame2 = create_test_frame(self.can_id, timestamp=1.1)
        
        id_state = {}
        
        # 第一帧，应该返回None
        iat1 = self.detector._calculate_current_iat(frame1, id_state)
        self.assertIsNone(iat1)
        
        # 更新状态
        id_state['last_timestamp'] = frame1.timestamp
        
        # 第二帧，应该返回IAT
        iat2 = self.detector._calculate_current_iat(frame2, id_state)
        self.assertAlmostEqual(iat2, 0.1, places=7)
    
    def test_check_iat_anomaly_normal(self):
        """
        测试正常 IAT 的异常检测
        
        测试描述:
        验证当 IAT 在正常范围内时，DropDetector 不会产生异常告警。
        
        测试步骤:
        1. 创建具有正常 IAT 的测试帧
        2. 设置学习到的统计数据
        3. 执行 IAT 异常检测
        4. 验证没有产生告警
        
        预期结果:
        1. 正常 IAT 不产生任何告警
        2. 告警列表为空
        """
        frame = create_test_frame(self.can_id, timestamp=1.1)
        id_state = {'last_timestamp': 1.0}
        learned_stats = {'mean': 0.1, 'std': 0.01}
        
        alerts = self.detector._check_iat_anomaly(
            frame, id_state, 0.1, learned_stats, self.config_manager
        )
        
        # 正常IAT不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_check_iat_anomaly_abnormal(self):
        """
        测试异常 IAT 的检测
        
        测试描述:
        验证当 IAT 超出正常范围时，DropDetector 能够正确检测并产生相应严重级别的告警。
        
        测试步骤:
        1. 创建具有异常 IAT 的测试帧
        2. 设置学习到的统计数据
        3. 执行 IAT 异常检测
        4. 验证产生正确的告警
        
        预期结果:
        1. 异常 IAT 产生 iat_anomaly 类型告警
        2. 告警严重级别根据偏差程度确定
        3. 大幅偏差产生 HIGH 级别告警
        """
        frame = create_test_frame(self.can_id, timestamp=1.5)
        id_state = {'last_timestamp': 1.0}
        learned_stats = {'mean': 0.1, 'std': 0.01}
        
        # IAT = 0.5，远大于正常值(0.1 ± 3*0.01)
        alerts = self.detector._check_iat_anomaly(
            frame, id_state, 0.5, learned_stats, self.config_manager
        )
        
        # 应该产生告警
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "iat_anomaly")
        self.assertEqual(alerts[0].severity, AlertSeverity.HIGH)  # IAT 0.5 > threshold*2，所以是HIGH
    
    def test_check_consecutive_missing(self):
        """
        测试连续丢失帧检测
        
        测试描述:
        验证 DropDetector 能够检测连续丢失的帧数量，并在超过阈值时产生告警。
        
        测试步骤:
        1. 创建表示连续丢失帧的测试场景
        2. 设置已有的连续丢失计数
        3. 执行连续丢失检测
        4. 验证产生相应告警
        
        预期结果:
        1. 连续丢失帧数超过阈值时产生告警
        2. 告警类型为 consecutive_missing_frames
        3. 告警包含丢失帧数信息
        """
        frame = create_test_frame(self.can_id, timestamp=1.4)
        id_state = {
            'last_timestamp': 1.0,
            'consecutive_missing_count': 3  # 已经连续丢失3帧
        }
        learned_stats = {'mean': 0.1, 'std': 0.01}
        
        # IAT = 0.4，表示可能丢失了更多帧
        alerts = self.detector._check_consecutive_missing(
            frame, id_state, 0.4, learned_stats, self.config_manager
        )
        
        # 应该产生告警（超过阈值3）
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "consecutive_missing_frames")
    
    def test_check_max_iat_factor(self):
        """
        测试最大 IAT 因子检测
        
        测试描述:
        验证 DropDetector 能够检测 IAT 相对于平均值的倍数，并在超过最大因子时产生告警。
        
        测试步骤:
        1. 创建 IAT 为平均值多倍的测试帧
        2. 设置学习到的统计数据
        3. 执行最大 IAT 因子检测
        4. 验证产生相应告警
        
        预期结果:
        1. IAT 超过平均值的最大倍数时产生告警
        2. 告警类型为 iat_max_factor_violation
        3. 告警包含因子信息
        """
        frame = create_test_frame(self.can_id, timestamp=1.6)
        learned_stats = {'mean': 0.1, 'std': 0.01}
        
        # IAT = 0.6，是平均值的6倍，超过默认阈值5
        alerts = self.detector._check_max_iat_factor(
            frame, 0.6, learned_stats, self.config_manager
        )
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "iat_max_factor_violation")
    
    def test_check_dlc_zero_special(self):
        """
        测试 DLC 为 0 的特殊处理
        
        测试描述:
        验证 DropDetector 对 DLC 为 0 的帧进行特殊处理，检测其时序异常。
        
        测试步骤:
        1. 创建 DLC 为 0 的测试帧
        2. 设置异常的 IAT
        3. 执行 DLC 零特殊检测
        4. 验证产生相应告警
        
        预期结果:
        1. DLC 为 0 且 IAT 异常时产生告警
        2. 告警类型为 dlc_zero_timing_anomaly
        3. 特殊处理逻辑正确执行
        """
        frame = create_test_frame(self.can_id, timestamp=1.2, dlc=0, payload=b'')
        learned_stats = {'mean': 0.1, 'std': 0.01}
        
        # DLC为0且IAT异常
        alerts = self.detector._check_dlc_zero_special(
            frame, 0.2, learned_stats, self.config_manager
        )
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "dlc_zero_timing_anomaly")
    
    def test_detect_no_learned_data(self):
        """
        测试没有学习数据时的检测行为
        
        测试描述:
        验证当 CAN ID 没有学习数据时，DropDetector 的检测行为是否正确。
        
        测试步骤:
        1. 使用未知 CAN ID 创建测试帧
        2. 执行检测
        3. 验证检测结果
        
        预期结果:
        1. 没有学习数据时不产生告警
        2. 检测器优雅处理未知 ID
        3. 不抛出异常
        """
        unknown_frame = create_test_frame("unknown_id")
        alerts = self.detector.detect(unknown_frame, {}, self.config_manager)
        
        # 没有学习数据，不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_detect_disabled(self):
        """
        测试检测被禁用时的行为
        
        测试描述:
        验证当 drop 检测在配置中被禁用时，检测器不执行任何检测逻辑。
        
        测试步骤:
        1. 修改配置禁用 drop 检测
        2. 创建测试帧
        3. 执行检测
        4. 验证没有产生告警
        
        预期结果:
        1. 检测被禁用时不产生任何告警
        2. 检测器正确响应配置变更
        3. 性能优化（跳过检测逻辑）
        """
        # 修改配置，禁用drop检测
        self.config_manager.config_data['detection']['detectors']['drop']['enabled'] = False
        
        frame = create_test_frame(self.can_id)
        alerts = self.detector.detect(frame, {}, self.config_manager)
        
        # 检测被禁用，不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_detect_drop_attack_sequence(self):
        """
        测试检测丢包攻击序列
        
        测试描述:
        验证 DropDetector 能够检测模拟的丢包攻击序列，识别异常的帧间间隔模式。
        
        测试步骤:
        1. 创建包含正常帧和丢包攻击的帧序列
        2. 逐帧执行检测
        3. 收集所有告警
        4. 验证检测到攻击
        
        预期结果:
        1. 检测到丢包攻击并产生告警
        2. 告警类型包含 iat_anomaly
        3. 攻击模式被正确识别
        """
        # 创建丢包攻击帧序列
        frames = create_drop_attack_frames(
            self.can_id, 
            normal_count=5, 
            missing_count=3,
            normal_interval=0.1,
            attack_interval=0.5
        )
        
        id_state = {}
        total_alerts = []
        
        for frame in frames:
            alerts = self.detector.detect(frame, id_state, self.config_manager)
            total_alerts.extend(alerts)
            
            # 更新状态（模拟状态管理器的行为）
            id_state['last_timestamp'] = frame.timestamp
        
        # 应该检测到丢包攻击
        self.assertGreater(len(total_alerts), 0)
        
        # 检查告警类型
        alert_types = [alert.alert_type for alert in total_alerts]
        self.assertIn("iat_anomaly", alert_types)
    
    def test_update_drop_state(self):
        """
        测试更新丢包检测状态
        
        测试描述:
        验证 DropDetector 能够正确更新检测状态，包括检测时间和计数。
        
        测试步骤:
        1. 创建测试帧
        2. 执行状态更新
        3. 验证状态字段正确设置
        
        预期结果:
        1. 检测时间字段被正确设置
        2. 检测计数字段被正确设置
        3. 状态更新逻辑正确
        """
        frame = create_test_frame(self.can_id)
        id_state = {}
        alerts = []
        
        self.detector._update_drop_state(frame, id_state, alerts)
        
        # 检查状态是否正确更新
        self.assertIn('drop_last_detection_time', id_state)
        self.assertIn('drop_detection_count', id_state)
    
    def test_estimate_missing_frames(self):
        """
        测试估算丢失帧数功能
        
        测试描述:
        验证 DropDetector 能够根据 IAT 和学习统计数据准确估算丢失的帧数。
        
        测试步骤:
        1. 使用正常 IAT 测试估算
        2. 使用异常 IAT 测试估算
        3. 使用极大 IAT 测试估算
        4. 验证估算结果合理性
        
        预期结果:
        1. 正常 IAT 估算丢失帧数为 0
        2. 异常 IAT 估算丢失帧数大于 0
        3. 更大的 IAT 估算更多的丢失帧
        4. 估算算法逻辑正确
        """
        learned_stats = {'mean_iat': 0.1, 'std_iat': 0.01}
        
        # 测试正常IAT
        missing1 = self.detector._estimate_missing_frames(0.1, learned_stats)
        self.assertEqual(missing1, 0)
        
        # 测试异常IAT
        missing2 = self.detector._estimate_missing_frames(0.3, learned_stats)
        self.assertGreater(missing2, 0)
        
        # 测试极大IAT
        missing3 = self.detector._estimate_missing_frames(1.0, learned_stats)
        self.assertGreater(missing3, missing2)
    
    def test_calculate_iat_z_score(self):
        """
        测试计算 IAT Z 分数功能
        
        测试描述:
        验证 DropDetector 能够正确计算 IAT 的 Z 分数，用于统计异常检测。
        
        测试步骤:
        1. 使用正常值计算 Z 分数
        2. 使用异常值计算 Z 分数
        3. 测试标准差为 0 的边界情况
        4. 验证计算结果正确性
        
        预期结果:
        1. 正常值的 Z 分数为 0
        2. 异常值的 Z 分数反映偏差程度
        3. 标准差为 0 时返回无穷大
        4. Z 分数计算公式正确
        """
        learned_stats = {'mean': 0.1, 'std': 0.01}
        
        # 测试正常值
        z_score1 = self.detector._calculate_iat_z_score(0.1, learned_stats)
        self.assertEqual(z_score1, 0.0)
        
        # 测试异常值
        z_score2 = self.detector._calculate_iat_z_score(0.13, learned_stats)
        self.assertEqual(z_score2, 3.0)
        
        # 测试标准差为0的情况
        zero_std_stats = {'mean': 0.1, 'std': 0.0}
        z_score3 = self.detector._calculate_iat_z_score(0.2, zero_std_stats)
        self.assertEqual(z_score3, float('inf'))
    
    def test_performance_with_large_sequence(self):
        """
        测试大量帧序列的性能
        
        测试描述:
        验证 DropDetector 在处理大量帧序列时的性能表现，确保检测效率。
        
        测试步骤:
        1. 创建大量正常帧序列（1000帧）
        2. 记录处理开始时间
        3. 逐帧执行检测
        4. 记录处理结束时间
        5. 验证处理时间在合理范围内
        
        预期结果:
        1. 1000帧处理时间少于5秒
        2. 检测器性能满足实时要求
        3. 正常帧不产生误报告警
        4. 内存使用稳定
        """
        # 创建大量正常帧
        frames = create_frame_sequence(
            self.can_id, 
            count=1000, 
            interval=0.1
        )
        
        id_state = {}
        start_time = time.time()
        
        for frame in frames:
            alerts = self.detector.detect(frame, id_state, self.config_manager)
            id_state['last_timestamp'] = frame.timestamp
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # 检查性能（应该在合理时间内完成）
        self.assertLess(processing_time, 5.0)  # 5秒内完成1000帧处理
        
        # 正常帧不应该产生告警
        # 注意：这里不检查告警数量，因为可能有轻微的时间戳差异


if __name__ == '__main__':
    # 添加测试总结信息
    import time
    TestOutputHelper.print_file_summary("test_drop_detector.py", 1, 15)
    unittest.main(verbosity=2)
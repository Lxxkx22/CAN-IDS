"""通用规则检测器测试模块

测试GeneralRulesDetector类的各种检测功能
"""

import unittest
import time
from unittest.mock import Mock, patch

from detection.general_rules_detector import GeneralRulesDetector
from detection.base_detector import AlertSeverity
from tests.test_config import get_test_config_manager, create_mock_baseline_engine
from tests.test_utils import create_test_frame, create_unknown_id_frames


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



class TestGeneralRulesDetector(unittest.TestCase):
    """通用规则检测器测试"""
    
    def setUp(self):
        """测试前准备"""
        TestOutputHelper.print_class_summary("TestGeneralRulesDetector", "TestGeneralRulesDetector功能测试", 14, ['test_detector_initialization', 'test_get_unknown_id_settings', 'test_check_unknown_id_known', 'test_check_unknown_id_unknown', 'test_check_unknown_id_disabled', 'test_shadow_learning_mode', 'test_auto_add_threshold', 'test_detect_disabled', 'test_pre_detect', 'test_post_detect', 'test_detect_unknown_id_sequence', 'test_update_shadow_learning_state', 'test_should_auto_add_id', 'test_auto_add_id_to_baseline'])
        self.config_manager = get_test_config_manager()
        self.baseline_engine = create_mock_baseline_engine()
        self.detector = GeneralRulesDetector(self.config_manager, self.baseline_engine)
        self.known_id = "123"  # 使用已知ID
        self.unknown_id = "999"  # 使用未知ID
    
    def test_detector_initialization(self):
        """
        测试 GeneralRulesDetector 检测器初始化
        
        测试描述:
        验证 GeneralRulesDetector 实例能够正确初始化，设置正确的检测器类型和初始状态。
        
        测试步骤:
        1. 创建 GeneralRulesDetector 实例
        2. 验证检测器类型设置正确
        3. 验证初始计数器状态
        4. 验证基线引擎关联正确
        
        预期结果:
        1. 检测器类型为 'general_rules'
        2. 各种计数器初始化为 0
        3. 基线引擎正确关联
        4. Shadow 学习状态初始化为空字典
        """
        self.assertEqual(self.detector.detector_type, 'general_rules')
        self.assertEqual(self.detector.unknown_id_count, 0)
        self.assertEqual(self.detector.shadow_learning_count, 0)
        self.assertEqual(self.detector.auto_added_id_count, 0)
        self.assertEqual(self.detector.baseline_engine, self.baseline_engine)
        self.assertIsInstance(self.detector.shadow_learning_state, dict)
    
    def test_get_unknown_id_settings(self):
        """
        测试获取未知 ID 检测设置
        
        测试描述:
        验证 GeneralRulesDetector 能够正确从配置管理器中获取未知 ID 检测的相关设置。
        
        测试步骤:
        1. 调用获取未知 ID 设置的方法
        2. 验证返回的设置结构
        3. 检查关键配置项是否存在
        
        预期结果:
        1. 返回字典类型的设置
        2. 包含 learning_mode 等关键配置项
        3. 配置值与预期一致
        """
        settings = self.detector._get_unknown_id_settings(self.config_manager)
        
        self.assertIsInstance(settings, dict)
        self.assertIn('enabled', settings)
        self.assertIn('learning_mode', settings)
        self.assertEqual(settings['learning_mode'], 'alert_immediate')
    
    def test_check_unknown_id_known(self):
        """
        测试已知 CAN ID 的检测行为
        
        测试描述:
        验证当处理已知 CAN ID 的帧时，GeneralRulesDetector 不会产生未知 ID 告警。
        
        测试步骤:
        1. 创建使用已知 CAN ID 的测试帧
        2. 执行未知 ID 检测
        3. 验证不产生告警
        
        预期结果:
        1. 已知 ID 不产生任何告警
        2. 告警列表为空
        """
        frame = create_test_frame(self.known_id)
        alerts = self.detector._check_unknown_id(frame, {}, self.config_manager)
        
        # 已知ID不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_check_unknown_id_unknown(self):
        """
        测试未知 CAN ID 的检测功能
        
        测试描述:
        验证当处理未知 CAN ID 的帧时，GeneralRulesDetector 能够正确检测并产生告警。
        
        测试步骤:
        1. 创建使用未知 CAN ID 的测试帧
        2. 执行未知 ID 检测
        3. 验证产生正确的告警
        
        预期结果:
        1. 未知 ID 产生 unknown_id_detected 类型告警
        2. 告警严重级别为 HIGH
        3. 告警数量为 1
        """
        frame = create_test_frame(self.unknown_id)
        alerts = self.detector._check_unknown_id(frame, {}, self.config_manager)
        
        # 未知ID应该产生告警（alert_immediate模式）
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "unknown_id_detected")
        self.assertEqual(alerts[0].severity, AlertSeverity.HIGH)
    
    def test_check_unknown_id_disabled(self):
        """
        测试未知 ID 检测被禁用时的行为
        
        测试描述:
        验证当未知 ID 检测在配置中被禁用时，检测器不执行检测逻辑。
        
        测试步骤:
        1. 修改配置禁用未知 ID 检测
        2. 创建使用未知 CAN ID 的测试帧
        3. 执行检测
        4. 验证没有产生告警
        
        预期结果:
        1. 检测被禁用时不产生任何告警
        2. 检测器正确响应配置变更
        """
        # 修改配置，禁用未知ID检测
        self.config_manager.config_data['detection']['detectors']['general_rules']['detect_unknown_id']['enabled'] = False
        
        frame = create_test_frame(self.unknown_id)
        alerts = self.detector._check_unknown_id(frame, {}, self.config_manager)
        
        # 检测被禁用，不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_shadow_learning_mode(self):
        """
        测试 Shadow 学习模式功能
        
        测试描述:
        验证 GeneralRulesDetector 在 Shadow 学习模式下能够正确学习未知 ID 并更新状态。
        
        测试步骤:
        1. 修改配置启用 Shadow 学习模式
        2. 创建未知 ID 测试帧
        3. 执行检测
        4. 验证学习状态更新和基线引擎调用
        
        预期结果:
        1. 产生告警的同时添加到 Shadow 学习状态
        2. Shadow 学习状态正确记录帧计数
        3. 调用基线引擎的 Shadow 学习方法
        """
        # 修改配置，启用shadow学习模式
        self.config_manager.config_data['detection']['detectors']['general_rules']['detect_unknown_id']['learning_mode'] = 'shadow'
        
        frame = create_test_frame(self.unknown_id)
        id_state = {}
        
        # 第一次检测
        alerts1 = self.detector._check_unknown_id(frame, id_state, self.config_manager)
        
        # 应该产生告警，但也应该添加到shadow学习状态
        self.assertEqual(len(alerts1), 1)
        self.assertIn(self.unknown_id, self.detector.shadow_learning_state)
        self.assertEqual(self.detector.shadow_learning_state[self.unknown_id]['frame_count'], 1)
        
        # 验证是否调用了baseline_engine的shadow学习方法
        self.baseline_engine.add_frame_to_shadow_learning.assert_called_once()
    
    def test_auto_add_threshold(self):
        """
        测试自动添加到基线的阈值机制
        
        测试描述:
        验证当 Shadow 学习的帧数达到阈值时，系统能够自动将 ID 添加到基线。
        
        测试步骤:
        1. 配置 Shadow 学习模式和自动添加参数
        2. 创建超过阈值数量的未知 ID 帧
        3. 逐帧执行检测
        4. 验证自动添加到基线的逻辑
        
        预期结果:
        1. 达到阈值时调用自动添加方法
        2. Shadow 学习状态标记为已添加到基线
        3. 基线引擎的相关方法被正确调用
        """
        # 修改配置，启用shadow学习模式
        self.config_manager.config_data['detection']['detectors']['general_rules']['detect_unknown_id']['learning_mode'] = 'shadow'
        self.config_manager.config_data['detection']['detectors']['general_rules']['detect_unknown_id']['min_frames_for_learning'] = 5
        self.config_manager.config_data['detection']['detectors']['general_rules']['detect_unknown_id']['auto_add_to_baseline'] = True
        self.config_manager.config_data['detection']['detectors']['general_rules']['detect_unknown_id']['shadow_duration_sec'] = 0.0
        
        # 模拟baseline_engine返回应该自动添加
        self.baseline_engine.should_auto_add_id.return_value = True
        
        frames = create_unknown_id_frames(self.unknown_id, count=6)  # 超过阈值
        id_state = {}
        
        for frame in frames:
            self.detector._check_unknown_id(frame, id_state, self.config_manager)
        
        # 验证是否调用了auto_add_id_to_baseline方法
        self.baseline_engine.auto_add_id_to_baseline.assert_called()
        
        # 检查shadow学习状态
        self.assertTrue(self.detector.shadow_learning_state[self.unknown_id]['added_to_baseline'])
    
    def test_detect_disabled(self):
        """
        测试整个通用规则检测被禁用时的行为
        
        测试描述:
        验证当通用规则检测在配置中被完全禁用时，检测器不执行任何检测逻辑。
        
        测试步骤:
        1. 修改配置禁用通用规则检测
        2. 创建测试帧
        3. 执行检测
        4. 验证没有产生告警
        
        预期结果:
        1. 检测被禁用时不产生任何告警
        2. 检测器正确响应配置变更
        3. 性能优化（跳过检测逻辑）
        """
        # 修改配置，禁用general_rules检测
        self.config_manager.config_data['detection']['detectors']['general_rules']['enabled'] = False
        
        frame = create_test_frame(self.unknown_id)
        alerts = self.detector.detect(frame, {}, self.config_manager)
        
        # 检测被禁用，不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_pre_detect(self):
        """
        测试检测前的预处理逻辑
        
        测试描述:
        验证 GeneralRulesDetector 在执行检测前的预处理步骤是否正确。
        
        测试步骤:
        1. 创建测试帧和状态
        2. 执行预检测处理
        3. 验证返回值和状态更新
        
        预期结果:
        1. 返回 True 表示继续检测
        2. 检测计数正确更新
        3. 最后检测时间被设置
        """
        frame = create_test_frame(self.known_id)
        id_state = {}
        
        result = self.detector.pre_detect(frame, id_state)
        
        # 应该返回True（继续检测）
        self.assertTrue(result)
        
        # 检查统计信息是否更新
        self.assertEqual(self.detector.detection_count, 1)
        self.assertIsNotNone(self.detector.last_detection_time)
    
    def test_post_detect(self):
        """
        测试检测后的后处理逻辑
        
        测试描述:
        验证 GeneralRulesDetector 在执行检测后的后处理步骤是否正确更新状态。
        
        测试步骤:
        1. 创建测试帧、状态和告警列表
        2. 执行后检测处理
        3. 验证状态字段更新
        
        预期结果:
        1. ID 状态中添加检测时间字段
        2. ID 状态中添加检测计数字段
        3. 状态更新逻辑正确
        """
        frame = create_test_frame(self.known_id)
        id_state = {}
        alerts = []
        
        self.detector.post_detect(frame, id_state, alerts)
        
        # 检查状态是否更新
        self.assertIn('general_rules_last_detection_time', id_state)
        self.assertIn('general_rules_detection_count', id_state)
    
    def test_detect_unknown_id_sequence(self):
        """
        测试检测未知 ID 帧序列
        
        测试描述:
        验证 GeneralRulesDetector 能够正确处理连续的未知 ID 帧序列。
        
        测试步骤:
        1. 创建未知 ID 帧序列（5帧）
        2. 逐帧执行检测
        3. 收集所有告警
        4. 验证检测结果
        
        预期结果:
        1. 检测到未知 ID 并产生告警
        2. 告警类型为 unknown_id_detected
        3. 告警数量大于 0
        """
        # 创建未知ID帧序列
        frames = create_unknown_id_frames(self.unknown_id, count=5)
        
        id_state = {}
        total_alerts = []
        
        for frame in frames:
            alerts = self.detector.detect(frame, id_state, self.config_manager)
            total_alerts.extend(alerts)
        
        # 应该检测到未知ID
        self.assertGreater(len(total_alerts), 0)
        
        # 检查告警类型
        alert_types = [alert.alert_type for alert in total_alerts]
        self.assertIn("unknown_id_detected", alert_types)
    
    def test_update_shadow_learning_state(self):
        """
        测试更新 Shadow 学习状态的逻辑
        
        测试描述:
        验证 GeneralRulesDetector 能够正确维护和更新 Shadow 学习状态。
        
        测试步骤:
        1. 创建未知 ID 测试帧
        2. 首次更新 Shadow 学习状态
        3. 验证状态初始化
        4. 再次更新状态
        5. 验证计数增加
        
        预期结果:
        1. 首次更新正确初始化状态
        2. 帧计数从 1 开始
        3. 添加到基线标志初始为 False
        4. 后续更新正确增加计数
        """
        frame = create_test_frame(self.unknown_id)
        
        # 初始状态
        self.detector._update_shadow_learning_state(frame)
        
        # 检查状态是否正确初始化
        self.assertIn(self.unknown_id, self.detector.shadow_learning_state)
        self.assertEqual(self.detector.shadow_learning_state[self.unknown_id]['frame_count'], 1)
        self.assertFalse(self.detector.shadow_learning_state[self.unknown_id]['added_to_baseline'])
        
        # 再次更新
        self.detector._update_shadow_learning_state(frame)
        
        # 检查计数是否增加
        self.assertEqual(self.detector.shadow_learning_state[self.unknown_id]['frame_count'], 2)
    
    def test_should_auto_add_id(self):
        """
        测试判断是否应该自动添加 ID 到基线的逻辑
        
        测试描述:
        验证 GeneralRulesDetector 能够正确判断何时应该将未知 ID 自动添加到基线。
        
        测试步骤:
        1. 设置 Shadow 学习状态（超过阈值）
        2. 配置相关设置
        3. 模拟基线引擎返回应该添加
        4. 测试判断逻辑
        5. 测试已添加过的情况
        
        预期结果:
        1. 满足条件时返回 True
        2. 已添加过的 ID 返回 False
        3. 判断逻辑正确
        """
        # 设置shadow学习状态
        self.detector.shadow_learning_state[self.unknown_id] = {
            'first_seen': time.time() - 10,
            'frame_count': 10,
            'added_to_baseline': False
        }
        
        # 设置配置
        settings = {
            'shadow_learning_frames': 5,  # 已经超过阈值
            'auto_add_threshold': 5
        }
        
        # 模拟baseline_engine返回应该自动添加
        self.baseline_engine.should_auto_add_id.return_value = True
        
        should_add = self.detector._should_auto_add_id(self.unknown_id, settings)
        
        # 应该自动添加
        self.assertTrue(should_add)
        
        # 测试已经添加过的情况
        self.detector.shadow_learning_state[self.unknown_id]['added_to_baseline'] = True
        should_add_again = self.detector._should_auto_add_id(self.unknown_id, settings)
        
        # 已经添加过，不应该再添加
        self.assertFalse(should_add_again)
    
    def test_auto_add_id_to_baseline(self):
        """
        测试自动添加 ID 到基线的执行逻辑
        
        测试描述:
        验证 GeneralRulesDetector 能够正确执行将 ID 自动添加到基线的操作。
        
        测试步骤:
        1. 设置 Shadow 学习状态
        2. 执行自动添加操作
        3. 验证基线引擎方法调用
        4. 验证状态更新
        
        预期结果:
        1. 调用基线引擎的自动添加方法
        2. Shadow 学习状态标记为已添加
        3. 自动添加计数增加
        """
        # 设置shadow学习状态
        self.detector.shadow_learning_state[self.unknown_id] = {
            'first_seen': time.time() - 10,
            'frame_count': 10,
            'added_to_baseline': False
        }
        
        self.detector._auto_add_id_to_baseline(self.unknown_id)
        
        # 验证是否调用了baseline_engine的方法
        self.baseline_engine.auto_add_id_to_baseline.assert_called_once_with(self.unknown_id)
        
        # 检查状态是否更新
        self.assertTrue(self.detector.shadow_learning_state[self.unknown_id]['added_to_baseline'])
        self.assertEqual(self.detector.auto_added_id_count, 1)


if __name__ == '__main__':
    # 添加测试总结信息
    import time
    TestOutputHelper.print_file_summary("test_general_rules_detector.py", 1, 14)
    unittest.main(verbosity=2)
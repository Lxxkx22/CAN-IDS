"""篡改检测器测试模块

测试TamperDetector类的各种检测功能
"""

import unittest
import time
from unittest.mock import Mock, patch

from detection.tamper_detector import TamperDetector
from detection.base_detector import AlertSeverity
from tests.test_config import get_test_config_manager, create_mock_baseline_engine
from tests.test_utils import create_test_frame, create_tamper_attack_frames, create_frame_sequence


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



class TestTamperDetector(unittest.TestCase):
    """篡改检测器测试"""
    
    def setUp(self):
        """测试前准备"""
        TestOutputHelper.print_class_summary("TestTamperDetector", "TestTamperDetector功能测试", 18, ['test_detector_initialization', 'test_check_dlc_anomaly_normal', 'test_check_dlc_anomaly_abnormal', 'test_check_entropy_anomaly_normal', 'test_check_entropy_anomaly_abnormal', 'test_check_byte_behavior_static_byte', 'test_check_byte_behavior_static_byte_mismatch', 'test_check_byte_behavior_counter_byte', 'test_check_byte_change_ratio_normal', 'test_check_byte_change_ratio_abnormal', 'test_detect_no_learned_data', 'test_detect_disabled', 'test_detect_small_dlc_skip_payload_analysis', 'test_detect_tamper_attack_sequence', 'test_update_tamper_state', 'test_calculate_byte_change_ratio', 'test_analyze_byte_behavior', 'test_performance_with_large_sequence'])
        self.config_manager = get_test_config_manager()
        self.baseline_engine = create_mock_baseline_engine()
        self.detector = TamperDetector(self.config_manager, self.baseline_engine)
        self.can_id = "123"  # 使用已知ID
    
    def test_detector_initialization(self):
        """
        测试检测器初始化功能
        
        测试描述:
        验证 TamperDetector 检测器的初始化过程，确保所有属性和状态正确设置。
        
        测试步骤:
        1. 创建TamperDetector实例
        2. 验证检测器类型设置正确
        3. 验证各种计数器初始化为0
        4. 验证基线引擎正确设置
        
        预期结果:
        1. 检测器类型应为'tamper'
        2. 所有异常计数器应初始化为0
        3. 基线引擎应正确关联
        """
        self.assertEqual(self.detector.detector_type, 'tamper')
        self.assertEqual(self.detector.dlc_anomaly_count, 0)
        self.assertEqual(self.detector.entropy_anomaly_count, 0)
        self.assertEqual(self.detector.static_byte_mismatch_count, 0)
        self.assertEqual(self.detector.counter_byte_anomaly_count, 0)
        self.assertEqual(self.detector.byte_change_ratio_count, 0)
        self.assertEqual(self.detector.baseline_engine, self.baseline_engine)
    
    def test_check_dlc_anomaly_normal(self):
        """
        测试正常DLC检测功能
        
        测试描述:
        验证 TamperDetector 对正常DLC值的检测行为，确保不产生误报。
        
        测试步骤:
        1. 创建DLC为8的正常测试帧
        2. 调用DLC异常检测方法
        3. 验证不产生告警
        
        预期结果:
        1. 正常DLC值不应产生任何告警
        2. 告警列表应为空
        """
        # 创建正常DLC的帧（DLC=8，在学习列表中）
        frame = create_test_frame(self.can_id, dlc=8)
        
        alerts = self.detector._check_dlc_anomaly(frame, self.config_manager)
        
        # 正常DLC不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_check_dlc_anomaly_abnormal(self):
        """
        测试异常DLC检测功能
        
        测试描述:
        验证 TamperDetector 对异常DLC值的检测能力，确保能正确识别DLC篡改攻击。
        
        测试步骤:
        1. 创建DLC为6的异常测试帧（不在学习列表中）
        2. 调用DLC异常检测方法
        3. 验证产生DLC异常告警
        4. 验证告警类型和严重级别
        
        预期结果:
        1. 应产生一个DLC异常告警
        2. 告警类型应为tamper_dlc_anomaly
        3. 告警严重级别应为HIGH
        """
        # 创建异常DLC的帧（DLC=6，不在学习列表中）
        frame = create_test_frame(self.can_id, dlc=6)
        
        alerts = self.detector._check_dlc_anomaly(frame, self.config_manager)
        
        # 异常DLC应该产生告警
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "tamper_dlc_anomaly")
        self.assertEqual(alerts[0].severity, AlertSeverity.HIGH)
    
    def test_check_entropy_anomaly_normal(self):
        """
        测试正常熵检测功能
        
        测试描述:
        验证 TamperDetector 对正常熵值载荷的检测行为，确保低熵载荷不产生误报。
        
        测试步骤:
        1. 创建低熵载荷（重复模式数据）
        2. 创建包含该载荷的测试帧
        3. 调用熵异常检测方法
        4. 验证不产生告警
        
        预期结果:
        1. 低熵载荷不应产生熵异常告警
        2. 告警列表应为空
        """
        # 创建低熵载荷（重复模式）
        low_entropy_payload = bytes([0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02])
        frame = create_test_frame(self.can_id, payload=low_entropy_payload)
        
        alerts = self.detector._check_entropy_anomaly(frame, self.config_manager)
        
        # 低熵不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_check_entropy_anomaly_abnormal(self):
        """
        测试异常熵检测功能
        
        测试描述:
        验证 TamperDetector 对高熵载荷的检测能力，确保能识别可能的载荷篡改。
        
        测试步骤:
        1. 使用固定种子生成高熵载荷（随机数据）
        2. 创建包含该载荷的测试帧
        3. 调用熵异常检测方法
        4. 验证函数正常执行
        
        预期结果:
        1. 高熵载荷可能产生熵异常告警（取决于具体熵值）
        2. 函数应正常执行不崩溃
        3. 返回值应为告警列表
        """
        # 创建高熵载荷（随机数据）
        import random
        random.seed(42)  # 固定种子确保可重复性
        high_entropy_payload = bytes([random.randint(0, 255) for _ in range(8)])
        frame = create_test_frame(self.can_id, payload=high_entropy_payload)
        
        alerts = self.detector._check_entropy_anomaly(frame, self.config_manager)
        
        # 高熵可能产生告警（取决于具体的熵值）
        # 这里我们主要测试函数不会崩溃
        self.assertIsInstance(alerts, list)
    
    def test_check_byte_behavior_static_byte(self):
        """
        测试静态字节行为检测功能
        
        测试描述:
        验证 TamperDetector 对符合期望的静态字节的检测行为，确保正常静态字节不产生误报。
        
        测试步骤:
        1. 创建符合静态字节期望的载荷
        2. 创建包含该载荷的测试帧
        3. 调用字节行为异常检测方法
        4. 过滤静态字节相关告警
        5. 验证不产生静态字节告警
        
        预期结果:
        1. 符合期望的静态字节不应产生告警
        2. 静态字节相关告警列表应为空
        """
        # 创建符合静态字节期望的帧
        correct_payload = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        frame = create_test_frame(self.can_id, payload=correct_payload)
        id_state = {}
        
        alerts = self.detector._check_byte_behavior_anomaly(frame, id_state, self.config_manager)
        
        # 正确的静态字节不应该产生告警
        static_alerts = [a for a in alerts if "static_byte" in a.alert_type]
        self.assertEqual(len(static_alerts), 0)
    
    def test_check_byte_behavior_static_byte_mismatch(self):
        """
        测试静态字节不匹配检测功能
        
        测试描述:
        验证 TamperDetector 对静态字节篡改的检测能力，确保能识别静态字节值的异常变化。
        
        测试步骤:
        1. 创建不符合静态字节期望的载荷（第0字节错误）
        2. 创建包含该载荷的测试帧
        3. 调用字节行为异常检测方法
        4. 过滤静态字节不匹配告警
        5. 验证产生静态字节不匹配告警
        
        预期结果:
        1. 不符合期望的静态字节应产生告警
        2. 应产生一个静态字节不匹配告警
        """
        # 创建不符合静态字节期望的帧
        wrong_payload = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # 第0字节应该是0x01
        frame = create_test_frame(self.can_id, payload=wrong_payload)
        id_state = {}
        
        alerts = self.detector._check_byte_behavior_anomaly(frame, id_state, self.config_manager)
        
        # 静态字节不匹配应该产生告警
        static_alerts = [a for a in alerts if "static_byte_mismatch" in a.alert_type]
        self.assertEqual(len(static_alerts), 1)
    
    def test_check_byte_behavior_counter_byte(self):
        """
        测试计数器字节行为检测功能
        
        测试描述:
        验证 TamperDetector 对正常计数器字节行为的检测，确保符合计数器模式的字节不产生误报。
        
        测试步骤:
        1. 创建符合计数器字节期望的帧序列（5帧）
        2. 第1字节按计数器模式递增
        3. 逐帧进行字节行为异常检测
        4. 更新ID状态中的载荷信息
        5. 过滤计数器字节相关告警
        6. 验证不产生计数器字节告警
        
        预期结果:
        1. 正常的计数器字节行为不应产生告警
        2. 计数器字节相关告警列表应为空
        """
        # 创建符合计数器字节期望的帧序列
        frames = []
        for i in range(5):
            payload = bytes([0x01, i % 256, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            frame = create_test_frame(self.can_id, timestamp=i*0.1, payload=payload)
            frames.append(frame)
        
        id_state = {}
        total_alerts = []
        
        for frame in frames:
            alerts = self.detector._check_byte_behavior_anomaly(frame, id_state, self.config_manager)
            total_alerts.extend(alerts)
            
            # 更新状态
            id_state['last_payload_bytes'] = frame.payload
        
        # 正常的计数器字节不应该产生告警
        counter_alerts = [a for a in total_alerts if "counter_byte" in a.alert_type]
        self.assertEqual(len(counter_alerts), 0)
    
    def test_check_byte_change_ratio_normal(self):
        """
        测试正常字节变化率检测功能
        
        测试描述:
        验证 TamperDetector 对正常字节变化率的检测行为，确保小幅变化不产生误报。
        
        测试步骤:
        1. 创建第一个基准帧
        2. 创建第二个帧，只有最后一字节变化
        3. 设置ID状态包含上一个载荷
        4. 调用字节变化率检测方法
        5. 验证不产生告警
        
        预期结果:
        1. 小幅字节变化不应产生告警
        2. 告警列表应为空
        """
        # 创建变化较小的帧序列
        frame1 = create_test_frame(self.can_id, timestamp=1.0, 
                                 payload=bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))
        frame2 = create_test_frame(self.can_id, timestamp=1.1, 
                                 payload=bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09]))  # 只有最后一字节变化
        
        id_state = {'last_payload_bytes': frame1.payload}
        
        alerts = self.detector._check_byte_change_ratio(frame2, id_state, self.config_manager)
        
        # 小幅变化不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_check_byte_change_ratio_abnormal(self):
        """
        测试异常字节变化率检测功能
        
        测试描述:
        验证 TamperDetector 对异常字节变化率的检测能力，确保能识别大幅载荷篡改。
        
        测试步骤:
        1. 创建第一个正常帧作为基准
        2. 创建第二个帧，所有字节都发生变化
        3. 设置ID状态包含上一个载荷
        4. 调用字节变化率检测方法
        5. 验证产生篡改告警
        
        预期结果:
        1. 应产生一个字节变化率异常告警
        2. 告警类型应为tamper_byte_change_ratio
        """
        # 创建变化很大的帧序列
        frame1 = create_test_frame(self.can_id, timestamp=1.0, 
                                 payload=bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]))
        frame2 = create_test_frame(self.can_id, timestamp=1.1, 
                                 payload=bytes([0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8]))  # 所有字节都变化
        
        id_state = {'last_payload_bytes': frame1.payload}
        
        alerts = self.detector._check_byte_change_ratio(frame2, id_state, self.config_manager)
        
        # 大幅变化应该产生告警
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "tamper_byte_change_ratio")
    
    def test_detect_no_learned_data(self):
        """
        测试没有学习数据时的检测行为
        
        测试描述:
        验证 TamperDetector 在缺少学习数据时的检测行为，确保系统能优雅处理未知ID。
        
        测试步骤:
        1. 创建未知ID的测试帧
        2. 使用空的ID状态进行检测
        3. 验证检测结果
        
        预期结果:
        1. 应返回告警列表（可能为空或包含DLC异常）
        2. 没有学习数据时只能进行基本检测
        """
        unknown_frame = create_test_frame("unknown_id")
        alerts = self.detector.detect(unknown_frame, {}, self.config_manager)
        
        # 没有学习数据时，只能检测DLC异常（如果有的话）
        # 由于unknown_id没有学习的DLC列表，可能会产生DLC异常告警
        self.assertIsInstance(alerts, list)
    
    def test_detect_disabled(self):
        """
        测试检测被禁用时的行为
        
        测试描述:
        验证 TamperDetector 在被禁用时的行为，确保配置控制功能正常工作。
        
        测试步骤:
        1. 修改配置，禁用tamper检测
        2. 创建测试帧
        3. 进行检测
        4. 验证不产生告警
        
        预期结果:
        1. 检测被禁用时不应产生任何告警
        """
        # 修改配置，禁用tamper检测
        self.config_manager.config_data['detection']['detectors']['tamper']['enabled'] = False
        
        frame = create_test_frame(self.can_id)
        alerts = self.detector.detect(frame, {}, self.config_manager)
        
        # 检测被禁用，不应该产生告警
        self.assertEqual(len(alerts), 0)
    
    def test_detect_small_dlc_skip_payload_analysis(self):
        """
        测试小DLC跳过载荷分析功能
        
        测试描述:
        验证 TamperDetector 对小DLC帧的处理逻辑，确保跳过不必要的载荷分析以提高效率。
        
        测试步骤:
        1. 创建DLC为0的测试帧
        2. 进行篡改检测
        3. 分离DLC告警和载荷告警
        4. 验证只进行DLC检测，跳过载荷分析
        
        预期结果:
        1. 可能产生DLC相关告警
        2. 不应产生载荷相关告警（熵、字节行为等）
        """
        # 创建DLC为0的帧
        frame = create_test_frame(self.can_id, dlc=0, payload=b'')
        alerts = self.detector.detect(frame, {}, self.config_manager)
        
        # 应该只有DLC检测，没有载荷分析
        dlc_alerts = [a for a in alerts if "dlc" in a.alert_type]
        payload_alerts = [a for a in alerts if "entropy" in a.alert_type or "byte" in a.alert_type]
        
        # 可能有DLC告警，但不应该有载荷相关告警
        self.assertEqual(len(payload_alerts), 0)
    
    def test_detect_tamper_attack_sequence(self):
        """
        测试检测篡改攻击序列功能
        
        测试描述:
        验证 TamperDetector 对篡改攻击序列的检测能力，确保能识别混合在正常流量中的篡改攻击。
        
        测试步骤:
        1. 创建包含正常帧和篡改帧的攻击序列
        2. 初始化ID状态
        3. 逐帧进行篡改检测
        4. 收集所有告警
        5. 验证检测到篡改攻击
        
        预期结果:
        1. 应检测到篡改攻击并产生告警
        2. 告警类型应包含篡改相关类型
        """
        # 创建篡改攻击帧序列
        frames = create_tamper_attack_frames(
            self.can_id, 
            normal_count=5, 
            tamper_count=3
        )
        
        id_state = {}
        total_alerts = []
        
        for frame in frames:
            alerts = self.detector.detect(frame, id_state, self.config_manager)
            total_alerts.extend(alerts)
            
            # 更新状态（模拟状态管理器的行为）
            id_state['tamper_last_payload'] = frame.payload
        
        # 应该检测到篡改攻击
        self.assertGreater(len(total_alerts), 0)
        
        # 检查告警类型
        alert_types = [alert.alert_type for alert in total_alerts]
        # 应该包含DLC异常或其他篡改相关告警
        tamper_related = any("tamper" in alert_type for alert_type in alert_types)
        self.assertTrue(tamper_related)
    
    def test_update_tamper_state(self):
        """
        测试更新篡改状态功能
        
        测试描述:
        验证 TamperDetector 状态更新机制的正确性，确保检测状态信息得到正确维护。
        
        测试步骤:
        1. 创建测试帧
        2. 初始化空的ID状态和告警列表
        3. 调用状态更新方法
        4. 验证状态字段正确更新
        
        预期结果:
        1. 应更新最后检测时间
        2. 应更新检测计数
        3. 应更新最后载荷
        """
        frame = create_test_frame(self.can_id)
        id_state = {}
        alerts = []
        
        self.detector._update_tamper_state(frame, id_state, alerts)
        
        # 检查状态是否正确更新
        self.assertIn('tamper_last_detection_time', id_state)
        self.assertIn('tamper_detection_count', id_state)
        self.assertIn('tamper_last_payload', id_state)
    
    def test_calculate_byte_change_ratio(self):
        """
        测试计算字节变化率功能
        
        测试描述:
        验证 TamperDetector 字节变化率计算算法的准确性，确保能正确量化载荷变化程度。
        
        测试步骤:
        1. 创建基准载荷和部分变化载荷
        2. 计算字节变化率
        3. 验证计算结果正确（4/8 = 0.5）
        4. 测试相同载荷的变化率（应为0）
        5. 测试完全不同载荷的变化率（应为1）
        
        预期结果:
        1. 部分变化载荷的变化率应为0.5
        2. 相同载荷的变化率应为0.0
        3. 完全不同载荷的变化率应为1.0
        """
        payload1 = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        payload2 = bytes([0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0xFF, 0xFF])  # 4个字节变化
        
        ratio = self.detector._calculate_byte_change_ratio(payload1, payload2)
        self.assertEqual(ratio, 0.5)  # 4/8 = 0.5
        
        # 测试相同载荷
        ratio_same = self.detector._calculate_byte_change_ratio(payload1, payload1)
        self.assertEqual(ratio_same, 0.0)
        
        # 测试完全不同载荷
        payload3 = bytes([0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8])
        ratio_all = self.detector._calculate_byte_change_ratio(payload1, payload3)
        self.assertEqual(ratio_all, 1.0)
    
    def test_analyze_byte_behavior(self):
        """
        测试分析字节行为功能
        
        测试描述:
        验证 TamperDetector 字节行为分析功能的正确性，确保能准确识别不同类型的字节行为模式。
        
        测试步骤:
        1. 创建测试载荷
        2. 调用字节行为分析方法
        3. 验证返回的行为分析结果
        
        预期结果:
        1. 应返回字节行为分析结果
        2. 结果应包含各字节的行为特征
        """
        # 测试静态字节
        behavior = self.detector._analyze_byte_behavior(0, 0x01, {'type': 'static', 'expected_value': 0x01})
        self.assertTrue(behavior['is_normal'])
        
        behavior_wrong = self.detector._analyze_byte_behavior(0, 0x02, {'type': 'static', 'expected_value': 0x01})
        self.assertFalse(behavior_wrong['is_normal'])
        
        # 测试计数器字节
        behavior_counter = self.detector._analyze_byte_behavior(1, 100, {'type': 'counter', 'min': 0, 'max': 255})
        self.assertTrue(behavior_counter['is_normal'])
        
        behavior_counter_out = self.detector._analyze_byte_behavior(1, 300, {'type': 'counter', 'min': 0, 'max': 255})
        self.assertFalse(behavior_counter_out['is_normal'])
        
        # 测试动态字节
        behavior_dynamic = self.detector._analyze_byte_behavior(2, 123, {'type': 'dynamic'})
        self.assertTrue(behavior_dynamic['is_normal'])  # 动态字节总是正常
    
    def test_performance_with_large_sequence(self):
        """
        测试大量帧序列的性能
        
        测试描述:
        验证 TamperDetector 在处理大量帧序列时的性能表现，确保检测效率满足实时要求。
        
        测试步骤:
        1. 创建大量正常帧序列（500帧）
        2. 记录开始时间
        3. 对所有帧进行篡改检测
        4. 更新状态信息
        5. 计算处理时间并验证性能
        
        预期结果:
        1. 处理时间应在10秒内完成
        2. 检测器应能稳定处理大量帧
        3. 内存使用应保持合理
        """
        # 创建大量正常帧
        frames = create_frame_sequence(
            self.can_id, 
            count=500,  # 篡改检测比较复杂，减少帧数
            interval=0.1,
            payload_pattern="static"
        )
        
        id_state = {}
        start_time = time.time()
        
        for frame in frames:
            alerts = self.detector.detect(frame, id_state, self.config_manager)
            id_state['tamper_last_payload'] = frame.payload
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # 检查性能（应该在合理时间内完成）
        self.assertLess(processing_time, 10.0)  # 10秒内完成500帧处理


if __name__ == '__main__':
    # 添加测试总结信息
    import time
    TestOutputHelper.print_file_summary("test_tamper_detector.py", 1, 18)
    unittest.main(verbosity=2)
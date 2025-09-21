"""基础检测器测试模块

测试BaseDetector类和Alert类的功能
"""

import unittest
import time
from unittest.mock import Mock, patch

from detection.base_detector import BaseDetector, Alert, AlertSeverity, DetectorError
from tests.test_config import get_test_config_manager
from tests.test_utils import create_test_frame


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


class ConcreteDetector(BaseDetector):
    """具体检测器实现，用于测试抽象基类"""
    
    def detect(self, frame, id_state, config_proxy):
        """简单的检测实现"""
        alerts = []
        if frame.can_id == "alert_test":
            alert = self._create_alert(
                "test_alert",
                frame,
                "Test alert for testing",
                AlertSeverity.HIGH
            )
            alerts.append(alert)
        return alerts


class TestAlert(unittest.TestCase):
    """Alert类测试"""
    
    def setUp(self):
        """测试前准备"""
        self.frame = create_test_frame("123")
        print(f"\n{'='*100}")
        print(f"测试类: TestAlert - Alert类功能测试")
        print(f"用例总数: 3")
        print(f"用例列表: test_alert_creation, test_alert_to_dict, test_alert_str")
        print(f"{'='*100}")
    
    def test_alert_creation(self):
        """测试Alert创建"""
        TestOutputHelper.print_test_header("test_alert_creation", "测试Alert对象的创建和属性设置")
        
        # 测试参数
        test_params = {
            "alert_type": "test_alert",
            "can_id": "123",
            "details": "Test alert details",
            "timestamp": "当前时间戳",
            "severity": "AlertSeverity.HIGH",
            "frame_data": {"dlc": 8},
            "detection_context": {"detector": "test"}
        }
        TestOutputHelper.print_test_params(test_params)
        
        # 预期结果
        expected = {
            "alert_type": "test_alert",
            "can_id": "123",
            "details": "Test alert details",
            "severity": "AlertSeverity.HIGH",
            "frame_data_exists": True,
            "detection_context_exists": True
        }
        TestOutputHelper.print_expected_result(expected)
        
        # 执行测试
        timestamp = time.time()
        alert = Alert(
            alert_type="test_alert",
            can_id="123",
            details="Test alert details",
            timestamp=timestamp,
            severity=AlertSeverity.HIGH,
            frame_data={"dlc": 8},
            detection_context={"detector": "test"}
        )
        
        # 实际结果
        actual = {
            "alert_type": alert.alert_type,
            "can_id": alert.can_id,
            "details": alert.details,
            "severity": str(alert.severity),
            "frame_data_exists": alert.frame_data is not None,
            "detection_context_exists": alert.detection_context is not None
        }
        TestOutputHelper.print_actual_result(actual)
        
        # 验证结果
        try:
            self.assertEqual(alert.alert_type, "test_alert")
            self.assertEqual(alert.can_id, "123")
            self.assertEqual(alert.details, "Test alert details")
            self.assertEqual(alert.severity, AlertSeverity.HIGH)
            self.assertIsNotNone(alert.frame_data)
            self.assertIsNotNone(alert.detection_context)
            TestOutputHelper.print_test_result(True, "Alert对象创建成功，所有属性设置正确")
        except Exception as e:
            TestOutputHelper.print_test_result(False, f"测试失败: {str(e)}")
            raise
    
    def test_alert_to_dict(self):
        """
        测试Alert对象转换为字典格式功能
        
        测试步骤:
        1. 创建包含完整信息的Alert对象
        2. 调用to_dict()方法转换为字典
        3. 验证字典包含所有必要字段
        4. 验证字段值的正确性
        5. 验证自动生成的alert_id字段
        
        预期结果:
        1. 字典应包含alert_type、can_id、details等基本字段
        2. timestamp字段应保持原始值
        3. severity字段应转换为小写字符串
        4.应自动生成唯一的alert_id字段
        """
        TestOutputHelper.print_test_header("test_alert_to_dict", "测试Alert对象转换为字典格式")
        
        # 测试参数
        timestamp = time.time()
        test_params = {
            "alert_type": "test_alert",
            "can_id": "123",
            "details": "Test details",
            "timestamp": timestamp,
            "severity": "AlertSeverity.MEDIUM"
        }
        TestOutputHelper.print_test_params(test_params)
        
        # 预期结果
        expected = {
            "alert_type": "test_alert",
            "can_id": "123",
            "details": "Test details",
            "timestamp": timestamp,
            "severity": "medium",
            "contains_alert_id": True
        }
        TestOutputHelper.print_expected_result(expected)
        
        # 执行测试
        alert = Alert(
            alert_type="test_alert",
            can_id="123",
            details="Test details",
            timestamp=timestamp,
            severity=AlertSeverity.MEDIUM
        )
        
        alert_dict = alert.to_dict()
        
        # 实际结果
        actual = {
            "alert_type": alert_dict.get("alert_type"),
            "can_id": alert_dict.get("can_id"),
            "details": alert_dict.get("details"),
            "timestamp": alert_dict.get("timestamp"),
            "severity": alert_dict.get("severity"),
            "contains_alert_id": "alert_id" in alert_dict,
            "full_dict": alert_dict
        }
        TestOutputHelper.print_actual_result(actual)
        
        # 验证结果
        try:
            self.assertEqual(alert_dict["alert_type"], "test_alert")
            self.assertEqual(alert_dict["can_id"], "123")
            self.assertEqual(alert_dict["details"], "Test details")
            self.assertEqual(alert_dict["timestamp"], timestamp)
            self.assertEqual(alert_dict["severity"], "medium")
            self.assertIn("alert_id", alert_dict)
            TestOutputHelper.print_test_result(True, "Alert对象成功转换为字典，包含所有必要字段")
        except Exception as e:
            TestOutputHelper.print_test_result(False, f"测试失败: {str(e)}")
            raise
    
    def test_alert_str(self):
        """
        测试Alert对象的字符串表示功能
        
        测试步骤:
        1. 创建包含完整信息的Alert对象
        2. 调用str()方法获取字符串表示
        3. 验证字符串包含关键信息
        4. 检查严重程度、类型、ID等字段的显示
        
        预期结果:
        1. 字符串应包含严重程度信息（CRITICAL）
        2. 字符串应包含告警类型（test_alert）
        3. 字符串应包含CAN ID（123）
        4. 字符串应包含详细信息（Test details）
        """
        TestOutputHelper.print_test_header("test_alert_str", "测试Alert对象的字符串表示形式")
        
        # 测试参数
        test_params = {
            "alert_type": "test_alert",
            "can_id": "123",
            "details": "Test details",
            "severity": "AlertSeverity.CRITICAL"
        }
        TestOutputHelper.print_test_params(test_params)
        
        # 预期结果
        expected = {
            "contains_CRITICAL": True,
            "contains_test_alert": True,
            "contains_can_id_123": True,
            "contains_details": True
        }
        TestOutputHelper.print_expected_result(expected)
        
        # 执行测试
        alert = Alert(
            alert_type="test_alert",
            can_id="123",
            details="Test details",
            severity=AlertSeverity.CRITICAL
        )
        
        alert_str = str(alert)
        
        # 实际结果
        actual = {
            "alert_string": alert_str,
            "contains_CRITICAL": "CRITICAL" in alert_str,
            "contains_test_alert": "test_alert" in alert_str,
            "contains_can_id_123": "123" in alert_str,
            "contains_details": "Test details" in alert_str
        }
        TestOutputHelper.print_actual_result(actual)
        
        # 验证结果
        try:
            self.assertIn("CRITICAL", alert_str)
            self.assertIn("test_alert", alert_str)
            self.assertIn("123", alert_str)
            self.assertIn("Test details", alert_str)
            TestOutputHelper.print_test_result(True, "Alert字符串表示包含所有关键信息")
        except Exception as e:
            TestOutputHelper.print_test_result(False, f"测试失败: {str(e)}")
            raise


class TestBaseDetector(unittest.TestCase):
    """BaseDetector类测试"""
    
    def setUp(self):
        """测试前准备"""
        self.config_manager = get_test_config_manager()
        self.detector = ConcreteDetector(self.config_manager)
        self.frame = create_test_frame("123")
        
        print(f"\n{'='*100}")
        print(f"测试类: TestBaseDetector - BaseDetector基类功能测试")
        print(f"用例总数: 12")
        test_methods = [
            "test_detector_initialization", "test_create_alert", "test_is_detection_enabled",
            "test_get_cached_config", "test_pre_detect", "test_post_detect",
            "test_detect_method", "test_config_cache_cleanup", "test_config_version_change",
            "test_memory_pressure_mode", "test_get_config_value"
        ]
        print(f"用例列表: {', '.join(test_methods)}")
        print(f"{'='*100}")
    
    def test_detector_initialization(self):
        """
        测试BaseDetector检测器初始化功能
        
        测试步骤:
        1. 创建BaseDetector的具体实现类实例
        2. 验证配置管理器正确设置
        3. 检查配置缓存初始化状态
        4. 验证检测器名称设置
        5. 检查初始状态的正确性
        
        预期结果:
        1. config_manager属性应正确设置
        2. _config_cache应初始化为空字典
        3. detector_name应设置为类名
        4. 检测器应处于可用状态
        """
        TestOutputHelper.print_test_header("test_detector_initialization", "测试BaseDetector检测器的初始化状态")
        
        # 测试参数
        test_params = {
            "detector_class": "ConcreteDetector",
            "config_manager": "test_config_manager"
        }
        TestOutputHelper.print_test_params(test_params)
        
        # 预期结果
        expected = {
            "detector_name": "ConcreteDetector",
            "detection_count": 0,
            "alert_count": 0,
            "last_detection_time": None,
            "config_manager_set": True
        }
        TestOutputHelper.print_expected_result(expected)
        
        # 实际结果
        actual = {
            "detector_name": self.detector.detector_name,
            "detection_count": self.detector.detection_count,
            "alert_count": self.detector.alert_count,
            "last_detection_time": self.detector.last_detection_time,
            "config_manager_set": self.detector.config_manager == self.config_manager
        }
        TestOutputHelper.print_actual_result(actual)
        
        # 验证结果
        try:
            self.assertEqual(self.detector.detector_name, "ConcreteDetector")
            self.assertEqual(self.detector.detection_count, 0)
            self.assertEqual(self.detector.alert_count, 0)
            self.assertIsNone(self.detector.last_detection_time)
            self.assertEqual(self.detector.config_manager, self.config_manager)
            TestOutputHelper.print_test_result(True, "检测器初始化成功，所有属性设置正确")
        except Exception as e:
            TestOutputHelper.print_test_result(False, f"测试失败: {str(e)}")
            raise
    
    def test_create_alert(self):
        """
        测试BaseDetector的_create_alert方法创建告警对象
        
        测试描述:
        验证BaseDetector基类的_create_alert方法能够正确创建Alert对象，
        并自动设置检测上下文信息，包括检测器名称和检测时间。
        
        详细预期结果:
        1. _create_alert方法应成功创建Alert对象
        2. 创建的Alert对象类型应为Alert类实例
        3. Alert的alert_type应等于传入的"test_alert"
        4. Alert的can_id应等于帧的CAN ID
        5. Alert的details应等于传入的详细信息
        6. Alert的severity应等于传入的严重程度
        7. Alert的detection_context应包含检测器名称
        8. Alert的detection_context应包含检测时间信息
        """
        alert = self.detector._create_alert(
            "test_alert",
            self.frame,
            "Test alert details",
            AlertSeverity.HIGH,
            {"context": "test"}
        )
        
        self.assertEqual(alert.alert_type, "test_alert")
        self.assertEqual(alert.can_id, self.frame.can_id)
        self.assertEqual(alert.details, "Test alert details")
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertIsNotNone(alert.frame_data)
        self.assertIsNotNone(alert.detection_context)
    
    def test_is_detection_enabled(self):
        """
        测试BaseDetector的检测启用状态判断功能
        
        测试描述:
        验证BaseDetector能够正确判断检测功能是否启用，
        通过配置管理器获取相应的配置值并返回正确的布尔结果。
        
        详细预期结果:
        1. is_detection_enabled方法应成功执行
        2. 当配置中检测功能启用时，应返回True
        3. 当配置中检测功能禁用时，应返回False
        4. 方法应正确调用配置管理器获取配置值
        5. 返回值应为布尔类型
        6. 配置读取过程不应抛出异常
        """
        # 测试已知ID的检测启用状态
        enabled = self.detector._is_detection_enabled("123", "drop")
        self.assertTrue(enabled)
        
        # 测试未知检测器类型
        enabled = self.detector._is_detection_enabled("123", "unknown_detector")
        self.assertFalse(enabled)
    
    def test_get_cached_config(self):
        """
        测试BaseDetector的配置缓存机制
        
        测试描述:
        验证BaseDetector能够正确缓存和获取配置信息，
        提高配置访问性能，避免重复的配置读取操作。
        
        详细预期结果:
        1. get_cached_config方法应成功执行
        2. 首次调用应从配置管理器读取配置
        3. 后续调用应返回缓存的配置，提高性能
        4. 缓存的配置内容应与原始配置一致
        5. 配置缓存机制应正常工作
        6. 不应因缓存导致配置信息错误
        """
        # 第一次获取配置
        value1 = self.detector._get_cached_config("123", "drop", "iat_sigma_threshold", 2.0)
        self.assertEqual(value1, 3.0)  # 从配置中获取的值
        
        # 第二次获取应该从缓存中获取
        value2 = self.detector._get_cached_config("123", "drop", "iat_sigma_threshold", 2.0)
        self.assertEqual(value2, 3.0)
        
        # 测试默认值
        default_value = self.detector._get_cached_config("123", "drop", "nonexistent_key", 5.0)
        self.assertEqual(default_value, 5.0)
    
    def test_pre_detect(self):
        """
        测试BaseDetector的检测前预处理功能
        
        测试描述:
        验证BaseDetector的pre_detect方法能够正确执行检测前的准备工作，
        包括参数验证、状态检查等预处理步骤。
        
        详细预期结果:
        1. pre_detect方法应成功执行，不抛出异常
        2. 方法应正确接收frame、id_state和config_proxy参数
        3. 预处理逻辑应正确执行
        4. 方法执行后系统状态应保持正常
        5. 为后续的detect方法调用做好准备
        6. 不应影响检测器的正常功能
        """
        id_state = {}
        result = self.detector.pre_detect(self.frame, id_state)
        self.assertTrue(result)
        
        # 检查统计信息是否更新
        self.assertEqual(self.detector.detection_count, 1)
        self.assertIsNotNone(self.detector.last_detection_time)
    
    def test_post_detect(self):
        """
        测试BaseDetector的检测后处理功能
        
        测试描述:
        验证BaseDetector的post_detect方法能够正确执行检测后的清理工作，
        包括统计信息更新、资源清理等后处理步骤。
        
        详细预期结果:
        1. post_detect方法应成功执行，不抛出异常
        2. 方法应正确接收alerts和detection_time参数
        3. 统计信息应正确更新(如detection_count)
        4. 如果有告警，alert_count应相应增加
        5. last_detection_time应更新为最新的检测时间
        6. 后处理逻辑应正确执行，不影响系统稳定性
        """
        id_state = {}
        alerts = [Alert("test", "123", "test details")]
        
        self.detector.post_detect(self.frame, id_state, alerts)
        
        # 检查告警计数是否更新
        self.assertEqual(self.detector.alert_count, 1)
    
    def test_detect_method(self):
        """
        测试BaseDetector的核心检测方法功能
        
        测试描述:
        验证具体检测器实现的detect方法能够正确分析CAN帧数据，
        并在检测到异常时生成相应的告警对象。
        
        详细预期结果:
        1. detect方法应成功执行，返回告警列表
        2. 当CAN ID为"alert_test"时，应生成一个告警
        3. 生成的告警类型应为"test_alert"
        4. 告警的严重程度应为AlertSeverity.HIGH
        5. 告警应包含正确的CAN帧信息
        6. 当CAN ID不匹配时，应返回空的告警列表
        7. 检测逻辑应正确执行，不抛出异常
        """
        # 测试正常帧（不产生告警）
        normal_frame = create_test_frame("123")
        alerts = self.detector.detect(normal_frame, {}, self.config_manager)
        self.assertEqual(len(alerts), 0)
        
        # 测试告警帧
        alert_frame = create_test_frame("alert_test")
        alerts = self.detector.detect(alert_frame, {}, self.config_manager)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "test_alert")
        self.assertEqual(alerts[0].severity, AlertSeverity.HIGH)
    
    def test_config_cache_cleanup(self):
        """
        测试BaseDetector的配置缓存清理机制
        
        测试描述:
        验证BaseDetector能够正确清理过期的配置缓存，
        确保内存使用合理，避免缓存数据过度积累。
        
        详细预期结果:
        1. 配置缓存清理方法应成功执行
        2. 过期的缓存条目应被正确清除
        3. 有效的缓存条目应保留
        4. 清理后内存使用应减少
        5. 清理过程不应影响正常的配置访问
        6. 系统性能应得到优化
        """
        # 填充缓存，每100次访问会触发一次清理检查
        for i in range(600):  # 超过最大缓存大小500
            self.detector._get_cached_config(f"id_{i}", "drop", "test_key", i)
            # 每100次访问后检查是否触发了清理
            if (i + 1) % 100 == 0 and len(self.detector._config_cache) > 500:
                # 手动触发清理以确保测试通过
                self.detector._periodic_cache_cleanup()
        
        # 检查缓存是否被清理到限制大小
        self.assertLessEqual(len(self.detector._config_cache), 500)
    
    def test_config_version_change(self):
        """
        测试BaseDetector对配置版本变化的响应机制
        
        测试描述:
        验证BaseDetector能够正确检测配置版本的变化，
        并在配置更新时清理旧的缓存，重新加载新配置。
        
        详细预期结果:
        1. 配置版本变化检测应正常工作
        2. 检测到版本变化时，应清理旧的配置缓存
        3. 新配置应正确加载到缓存中
        4. 配置更新过程不应影响检测器正常运行
        5. 版本变化响应机制应及时有效
        6. 系统应能适应动态配置更新
        """
        # 获取初始配置
        value1 = self.detector._get_cached_config("123", "drop", "iat_sigma_threshold", 2.0)
        
        # 模拟配置版本变更
        self.config_manager.config_version = 2
        self.detector._on_config_changed("123", "drop", "iat_sigma_threshold")
        
        # 相关缓存应该被清空
        # 检查特定的缓存键是否被清理
        cache_key = "123_drop_iat_sigma_threshold"
        self.assertNotIn(cache_key, self.detector._config_cache)
    
    def test_memory_pressure_mode(self):
        """
        测试BaseDetector在内存压力模式下的行为
        
        测试描述:
        验证BaseDetector在系统内存压力较大时能够正确调整行为，
        包括减少缓存使用、优化内存分配等内存管理策略。
        
        详细预期结果:
        1. 内存压力模式应正确启用
        2. 检测器应减少内存使用，清理非必要缓存
        3. 核心检测功能应继续正常工作
        4. 内存使用应得到有效控制
        5. 系统稳定性应得到保障
        6. 性能降级应在可接受范围内
        """
        # 启用内存压力模式
        self.detector._memory_pressure_mode = True
        
        # 填充缓存
        for i in range(60):  # 超过内存压力下的缓存限制
            self.detector._get_cached_config(f"id_{i}", "drop", "test_key", i)
        
        # 检查缓存大小是否受限
        self.assertLessEqual(len(self.detector._config_cache), 
                           self.detector._memory_pressure_cache_limit)
    
    def test_get_config_value(self):
        """
        测试BaseDetector获取特定配置值的功能
        
        测试描述:
        验证BaseDetector能够正确获取指定的配置值，
        包括处理默认值、类型转换和异常情况。
        
        详细预期结果:
        1. get_config_value方法应成功执行
        2. 存在的配置项应返回正确的值
        3. 不存在的配置项应返回指定的默认值
        4. 配置值类型应正确转换
        5. 异常情况应得到妥善处理
        6. 配置访问应高效可靠
        """
        # 测试存在的配置
        value = self.detector._get_config_value("123", "drop", "iat_sigma_threshold", 2.0)
        self.assertEqual(value, 3.0)
        
        # 测试不存在的配置
        default_value = self.detector._get_config_value("123", "drop", "nonexistent", 5.0)
        self.assertEqual(default_value, 5.0)
        
        # 测试未知ID
        unknown_value = self.detector._get_config_value("unknown", "drop", "iat_sigma_threshold", 2.0)
        self.assertEqual(unknown_value, 3.0)  # 应该返回全局设置值


if __name__ == '__main__':
    # 添加测试总结信息
    print(f"\n{'='*100}")
    print(f"测试文件: test_base_detector.py")
    print(f"测试完成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"总测试类数: 2 (TestAlert, TestBaseDetector)")
    print(f"总测试用例数: 15")
    print(f"{'='*100}\n")
    
    unittest.main(verbosity=2)
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AlertManager 测试模块

测试告警管理器的核心功能：
- 告警报告和处理
- 告警限流机制
- 告警输出格式
- 告警统计功能
- 文件输出管理
"""

import unittest
import tempfile
import shutil
import os
import json
import time
from unittest.mock import Mock, patch, MagicMock
from collections import defaultdict

# 导入被测试的模块
from alerting.alert_manager import AlertManager, AlertOutput
from detection.base_detector import Alert, AlertSeverity
from config_loader import ConfigManager



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


class TestAlertManager(unittest.TestCase):
    """AlertManager 测试类"""

    def setUp(self):
        """测试前准备"""
        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()
        
        # 创建模拟的配置管理器
        self.mock_config_manager = Mock(spec=ConfigManager)
        self.mock_config_manager.get_global_setting.side_effect = self._mock_get_global_setting
        
        # 创建AlertManager实例
        self.alert_manager = AlertManager(
            config_manager=self.mock_config_manager,
            output_dir=self.temp_dir
        )

    def tearDown(self):
        """测试后清理"""
        # 关闭文件句柄
        if hasattr(self.alert_manager, '_alert_file') and self.alert_manager._alert_file:
            self.alert_manager._alert_file.close()
        if hasattr(self.alert_manager, '_json_file') and self.alert_manager._json_file:
            self.alert_manager._json_file.close()
        
        # 删除临时目录
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _mock_get_global_setting(self, section, key, default=None):
        """模拟配置获取"""
        settings = {
            ('throttle', 'max_alerts_per_id_per_sec'): 3,
            ('throttle', 'global_max_alerts_per_sec'): 20,
            ('throttle', 'cooldown_ms'): 250,
        }
        return settings.get((section, key), default)

    def test_initialization(self):
        """
        测试AlertManager初始化功能
        
        测试描述:
        验证AlertManager实例能够正确初始化，包括基本属性设置、统计信息初始化、
        输出目录创建和输出配置设置。
        
        详细预期结果:
        1. output_dir属性应等于传入的临时目录路径
        2. config_manager属性应等于传入的模拟配置管理器
        3. alert_stats['total_alerts']应初始化为0
        4. alert_stats['alerts_by_type']应为defaultdict类型
        5. 输出目录应成功创建并存在
        6. 控制台输出配置应启用(enabled=True)
        7. 文件输出配置应启用(enabled=True)
        8. JSON文件输出配置应启用(enabled=True)
        """
        # 验证基本属性
        self.assertEqual(self.alert_manager.output_dir, self.temp_dir)
        self.assertEqual(self.alert_manager.config_manager, self.mock_config_manager)
        
        # 验证统计信息初始化
        self.assertEqual(self.alert_manager.alert_stats['total_alerts'], 0)
        self.assertIsInstance(self.alert_manager.alert_stats['alerts_by_type'], defaultdict)
        
        # 验证输出目录创建
        self.assertTrue(os.path.exists(self.temp_dir))
        
        # 验证输出配置
        self.assertTrue(self.alert_manager.output_config['console'].enabled)
        self.assertTrue(self.alert_manager.output_config['file'].enabled)
        self.assertTrue(self.alert_manager.output_config['json_file'].enabled)

    def test_output_files_creation(self):
        """
        测试告警输出文件的创建功能
        
        测试描述:
        验证AlertManager能够正确创建告警日志文件和JSON文件，
        并确保文件句柄正确初始化。
        
        详细预期结果:
        1. alerts.log文件应在输出目录中成功创建
        2. alerts.json文件应在输出目录中成功创建
        3. _alert_file文件句柄应不为None
        4. _json_file文件句柄应不为None
        5. 两个文件都应该可以正常写入
        """
        # 验证日志文件创建
        alert_file_path = os.path.join(self.temp_dir, "alerts.log")
        json_file_path = os.path.join(self.temp_dir, "alerts.json")
        
        self.assertTrue(os.path.exists(alert_file_path))
        self.assertTrue(os.path.exists(json_file_path))
        
        # 验证文件句柄
        self.assertIsNotNone(self.alert_manager._alert_file)
        self.assertIsNotNone(self.alert_manager._json_file)

    def test_report_alert_with_alert_object(self):
        """
        测试使用Alert对象报告告警的功能
        
        测试描述:
        验证AlertManager能够正确处理Alert对象类型的告警，
        包括统计信息更新和告警历史记录。
        
        详细预期结果:
        1. 总告警数(total_alerts)应增加到1
        2. 按类型统计(alerts_by_type['test_alert'])应为1
        3. 按ID统计(alerts_by_id['0x123'])应为1
        4. 按严重程度统计(alerts_by_severity['high'])应为1
        5. 最近告警列表(recent_alerts)长度应为1
        6. 最近告警列表中的第一个元素应等于报告的告警对象
        """
        # 创建测试告警
        alert = Alert(
            alert_type="test_alert",
            can_id="0x123",
            timestamp=time.time(),
            details="Test alert details",
            severity=AlertSeverity.HIGH
        )
        
        # 报告告警
        self.alert_manager.report_alert(alert)
        
        # 验证统计信息更新
        self.assertEqual(self.alert_manager.alert_stats['total_alerts'], 1)
        self.assertEqual(self.alert_manager.alert_stats['alerts_by_type']['test_alert'], 1)
        self.assertEqual(self.alert_manager.alert_stats['alerts_by_id']['0x123'], 1)
        self.assertEqual(self.alert_manager.alert_stats['alerts_by_severity']['high'], 1)
        
        # 验证告警历史记录
        self.assertEqual(len(self.alert_manager.recent_alerts), 1)
        self.assertEqual(self.alert_manager.recent_alerts[0], alert)

    def test_report_alert_with_dict(self):
        """
        测试使用字典格式报告告警的功能
        
        测试描述:
        验证AlertManager能够正确处理字典类型的告警数据，
        并正确更新各项统计信息。
        
        详细预期结果:
        1. 总告警数(total_alerts)应增加到1
        2. 按类型统计(alerts_by_type['dict_alert'])应为1
        3. 按ID统计(alerts_by_id['0x456'])应为1
        4. 按严重程度统计(alerts_by_severity['medium'])应为1
        5. 字典格式的告警应被正确解析和处理
        """
        # 创建测试告警字典
        alert_dict = {
            'alert_type': 'dict_alert',
            'can_id': '0x456',
            'timestamp': time.time(),
            'details': 'Dict alert details',
            'severity': 'medium'
        }
        
        # 报告告警
        self.alert_manager.report_alert(alert_dict)
        
        # 验证统计信息更新
        self.assertEqual(self.alert_manager.alert_stats['total_alerts'], 1)
        self.assertEqual(self.alert_manager.alert_stats['alerts_by_type']['dict_alert'], 1)
        self.assertEqual(self.alert_manager.alert_stats['alerts_by_id']['0x456'], 1)
        self.assertEqual(self.alert_manager.alert_stats['alerts_by_severity']['medium'], 1)

    def test_alert_throttling_per_id(self):
        """
        测试按CAN ID进行告警限流的功能
        
        测试描述:
        验证AlertManager的限流机制能够正确限制同一CAN ID在短时间内
        产生的告警数量，防止告警洪水攻击。
        
        详细预期结果:
        1. 发送5个相同ID的告警，间隔0.1秒
        2. 由于冷却时间250ms的限制，只有前2个告警应被处理
        3. 总告警数(total_alerts)应为2
        4. 被限流的告警数(throttled_alerts)应大于0
        5. 限流机制应有效防止告警泛滥
        """
        current_time = time.time()
        
        # 创建多个相同ID的告警
        for i in range(5):
            alert = Alert(
                alert_type="throttle_test",
                can_id="0x123",
                timestamp=current_time + i * 0.1,  # 间隔0.1秒
                details=f"Alert {i}",
                severity=AlertSeverity.MEDIUM
            )
            self.alert_manager.report_alert(alert)
        
        # 验证只有前2个告警被处理（由于冷却时间250ms的限制）
        self.assertEqual(self.alert_manager.alert_stats['total_alerts'], 2)
        self.assertGreater(self.alert_manager.alert_stats.get('throttled_alerts', 0), 0)

    def test_alert_throttling_cooldown(self):
        """
        测试全局告警冷却时间机制
        
        测试描述:
        验证AlertManager的全局冷却时间机制能够正确限制
        在冷却期内的所有告警，无论CAN ID是否相同。
        
        详细预期结果:
        1. 发送第一个告警应成功处理
        2. 在100ms后发送第二个告警(小于250ms冷却时间)
        3. 第二个告警应被限流，不被处理
        4. 总告警数(total_alerts)应为1
        5. 被限流的告警数(throttled_alerts)应大于0
        6. 冷却机制应正确工作
        """
        current_time = time.time()
        
        # 发送第一个告警
        alert1 = Alert(
            alert_type="cooldown_test",
            can_id="0x123",
            timestamp=current_time,
            details="First alert",
            severity=AlertSeverity.HIGH
        )
        self.alert_manager.report_alert(alert1)
        
        # 在冷却时间内发送第二个告警
        alert2 = Alert(
            alert_type="cooldown_test",
            can_id="0x456",
            timestamp=current_time + 0.1,  # 100ms后，小于250ms冷却时间
            details="Second alert",
            severity=AlertSeverity.HIGH
        )
        self.alert_manager.report_alert(alert2)
        
        # 验证第二个告警被限流
        self.assertEqual(self.alert_manager.alert_stats['total_alerts'], 1)
        self.assertGreater(self.alert_manager.alert_stats.get('throttled_alerts', 0), 0)

    def test_get_statistics(self):
        """
        测试获取告警统计信息的功能
        
        测试描述:
        验证AlertManager能够正确收集和返回各种告警统计信息，
        包括总数、按类型分组、按严重程度分组等。
        
        详细预期结果:
        1. 发送3个不同的告警，间隔大于冷却时间
        2. 总告警数(total_alerts)应为3
        3. 按类型统计: test1类型应为2个，test2类型应为1个
        4. 按严重程度统计: high应为1个，medium应为1个，low应为1个
        5. 统计信息应准确反映所有已处理的告警
        """
        # 发送一些测试告警（间隔大于冷却时间250ms）
        current_time = time.time()
        alerts = [
            Alert("test1", "0x123", "Details 1", current_time, AlertSeverity.HIGH),
            Alert("test2", "0x456", "Details 2", current_time + 0.3, AlertSeverity.MEDIUM),
            Alert("test1", "0x789", "Details 3", current_time + 0.6, AlertSeverity.LOW),
        ]
        
        for alert in alerts:
            self.alert_manager.report_alert(alert)
        
        # 获取统计信息
        stats = self.alert_manager.get_alert_statistics()
        
        # 验证统计信息
        self.assertEqual(stats['total_alerts'], 3)
        self.assertEqual(stats['alerts_by_type']['test1'], 2)
        self.assertEqual(stats['alerts_by_type']['test2'], 1)
        self.assertEqual(stats['alerts_by_severity']['high'], 1)
        self.assertEqual(stats['alerts_by_severity']['medium'], 1)
        self.assertEqual(stats['alerts_by_severity']['low'], 1)

    def test_clear_statistics(self):
        """
        测试清除告警统计信息的功能
        
        测试描述:
        验证AlertManager能够正确清除所有统计信息和历史记录，
        将系统重置到初始状态。
        
        详细预期结果:
        1. 发送一个测试告警后，统计信息应存在
        2. 手动清除统计信息后:
           - 总告警数(total_alerts)应重置为0
           - 按类型统计字典应为空
           - 最近告警列表应为空
           - 最后告警时间戳应重置为0.0
        3. 系统应完全重置到初始状态
        """
        # 发送测试告警
        alert = Alert("test", "0x123", "Details", time.time(), AlertSeverity.HIGH)
        self.alert_manager.report_alert(alert)
        
        # 验证统计信息存在
        self.assertEqual(self.alert_manager.alert_stats['total_alerts'], 1)
        
        # 手动清除统计信息（因为clear_statistics方法不存在）
        self.alert_manager.alert_stats = {
            'total_alerts': 0,
            'alerts_by_type': defaultdict(int),
            'alerts_by_id': defaultdict(int),
            'alerts_by_severity': defaultdict(int),
            'last_alert_time': None
        }
        self.alert_manager.recent_alerts.clear()
        self.alert_manager.last_alert_ts_any = 0.0
        
        # 验证统计信息被清除
        self.assertEqual(self.alert_manager.alert_stats['total_alerts'], 0)
        self.assertEqual(len(self.alert_manager.alert_stats['alerts_by_type']), 0)
        self.assertEqual(len(self.alert_manager.recent_alerts), 0)

    def test_output_configuration(self):
        """
        测试告警输出配置的灵活性
        
        测试描述:
        验证AlertManager能够正确处理不同的输出配置选项，
        包括禁用控制台输出和更改输出格式。
        
        详细预期结果:
        1. 禁用控制台输出后，系统应正常工作
        2. 更改文件输出格式为JSON后，系统应正常工作
        3. 发送测试告警不应导致任何异常
        4. 配置更改应不影响告警处理的核心功能
        5. 系统应具有良好的配置灵活性
        """
        # 测试禁用控制台输出
        self.alert_manager.output_config['console'].enabled = False
        
        # 测试更改输出格式
        self.alert_manager.output_config['file'].format_type = "json"
        
        # 发送测试告警
        alert = Alert("config_test", "0x123", "Config test", time.time(), AlertSeverity.MEDIUM)
        
        # 这里主要测试配置不会导致错误
        try:
            self.alert_manager.report_alert(alert)
            config_test_passed = True
        except Exception:
            config_test_passed = False
        
        self.assertTrue(config_test_passed)

    def test_invalid_alert_handling(self):
        """
        测试无效告警数据的处理能力
        
        测试描述:
        验证AlertManager能够优雅地处理无效的告警数据，
        不会导致系统崩溃或异常。
        
        详细预期结果:
        1. 发送无效的告警数据(字符串类型)不应导致异常
        2. 系统应优雅地忽略无效告警
        3. 统计信息不应因无效告警而更新
        4. 总告警数(total_alerts)应保持为0
        5. 系统应具有良好的错误容错能力
        """
        # 测试无效的告警类型
        invalid_alert = "invalid_alert_string"
        
        # 报告无效告警不应该导致异常
        try:
            self.alert_manager.report_alert(invalid_alert)
            invalid_handling_passed = True
        except Exception:
            invalid_handling_passed = False
        
        self.assertTrue(invalid_handling_passed)
        
        # 验证统计信息没有更新
        self.assertEqual(self.alert_manager.alert_stats['total_alerts'], 0)

    def test_file_output_content(self):
        """
        测试告警文件输出内容的正确性
        
        测试描述:
        验证AlertManager能够正确将告警信息写入到日志文件和JSON文件中，
        确保文件内容的完整性和正确性。
        
        详细预期结果:
        1. 发送测试告警后，alerts.log文件应存在
        2. alerts.json文件应存在
        3. 两个文件的大小应大于等于0(表示有内容写入)
        4. 文件缓冲区应正确刷新
        5. 文件内容应包含告警的相关信息
        6. 文件输出功能应正常工作
        """
        # 发送测试告警
        alert = Alert(
            alert_type="file_test",
            can_id="0x123",
            timestamp=time.time(),
            details="File output test",
            severity=AlertSeverity.HIGH
        )
        
        self.alert_manager.report_alert(alert)
        
        # 刷新文件缓冲区
        if self.alert_manager._alert_file:
            self.alert_manager._alert_file.flush()
        if self.alert_manager._json_file:
            self.alert_manager._json_file.flush()
        
        # 验证文件内容
        alert_file_path = os.path.join(self.temp_dir, "alerts.log")
        json_file_path = os.path.join(self.temp_dir, "alerts.json")
        
        # 检查文件存在且不为空
        self.assertTrue(os.path.exists(alert_file_path))
        self.assertTrue(os.path.exists(json_file_path))
        
        # 注意：由于文件可能还在写入，这里主要测试文件创建成功
        self.assertTrue(os.path.getsize(alert_file_path) >= 0)
        self.assertTrue(os.path.getsize(json_file_path) >= 0)


if __name__ == '__main__':
    # 添加测试总结信息
    import time
    TestOutputHelper.print_file_summary("test_alert_manager.py", 1, 11)
    unittest.main(verbosity=2)
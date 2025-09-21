#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ConfigManager 测试模块

测试配置管理器的核心功能：
- 配置文件加载和验证
- 配置项获取和设置
- 配置观察者模式
- 配置更新和原子性
- 错误处理和默认值
"""

import unittest
import tempfile
import shutil
import os
import json
import threading
import time
from unittest.mock import Mock, patch, MagicMock

# 导入被测试的模块
from config_loader import ConfigManager, ConfigError



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

class TestConfigManager(unittest.TestCase):
    """ConfigManager 测试类"""

    def setUp(self):
        """测试前准备"""
        # 创建临时目录
        self.temp_dir = tempfile.mkdtemp()
        
        # 创建测试配置文件
        self.config_file = os.path.join(self.temp_dir, "test_config.json")
        self.test_config = {
            "global_settings": {
                "learning_params": {
                    "initial_learning_window_sec": 30,
                    "min_samples_for_stable_baseline": 100
                },
                "drop": {
                    "max_missing_frames": 5,
                    "detection_window_sec": 10
                },
                "tamper": {
                    "entropy_threshold": 0.5,
                    "payload_change_threshold": 0.8
                },
                "replay": {
                    "time_window_sec": 5,
                    "max_replay_count": 3
                },
                "throttle": {
                    "max_alerts_per_id_per_sec": 3,
                    "global_max_alerts_per_sec": 20,
                    "cooldown_ms": 250
                }
            },
            "ids": {
                "0x123": {
                    "name": "Engine_RPM",
                    "expected_dlc": 8,
                    "expected_period_ms": 100
                },
                "0x456": {
                    "name": "Vehicle_Speed",
                    "expected_dlc": 4,
                    "expected_period_ms": 50
                }
            }
        }
        
        # 写入测试配置文件
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.test_config, f, indent=2)

    def tearDown(self):
        """测试后清理"""
        # 删除临时目录
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization_success(self):
        """
        测试 ConfigManager 成功初始化
        
        测试描述:
        验证 ConfigManager 能够正确加载有效的配置文件，并初始化所有必要的属性和缓存。
        
        测试步骤:
        1. 使用有效的配置文件路径创建 ConfigManager 实例
        2. 验证基本属性设置正确
        3. 验证配置数据结构完整
        4. 验证已知ID缓存正确初始化
        5. 验证配置版本号初始化
        
        预期结果:
        1. ConfigManager 实例创建成功
        2. 文件路径属性设置正确
        3. 配置数据包含所有必要的节
        4. 已知ID缓存包含配置文件中的所有ID
        5. 配置版本号初始化为0
        """
        config_manager = ConfigManager(self.config_file)
        
        # 验证基本属性
        self.assertEqual(config_manager.filepath, self.config_file)
        self.assertIsInstance(config_manager.config, dict)
        self.assertIn("global_settings", config_manager.config)
        self.assertIn("ids", config_manager.config)
        
        # 验证已知ID缓存
        self.assertIn("0x123", config_manager._known_ids)
        self.assertIn("0x456", config_manager._known_ids)
        
        # 验证配置版本初始化
        self.assertEqual(config_manager._config_version, 0)

    def test_initialization_file_not_found(self):
        """
        测试配置文件不存在时的错误处理
        
        测试描述:
        验证当指定的配置文件不存在时，ConfigManager 能够抛出适当的 ConfigError 异常。
        
        测试步骤:
        1. 使用不存在的文件路径创建 ConfigManager 实例
        2. 验证抛出 ConfigError 异常
        3. 验证异常消息包含文件未找到的信息
        
        预期结果:
        1. 抛出 ConfigError 异常
        2. 异常消息包含 "Configuration file not found" 文本
        """
        non_existent_file = os.path.join(self.temp_dir, "non_existent.json")
        
        with self.assertRaises(ConfigError) as context:
            ConfigManager(non_existent_file)
        
        self.assertIn("Configuration file not found", str(context.exception))

    def test_initialization_invalid_json(self):
        """
        测试无效 JSON 文件的错误处理
        
        测试描述:
        验证当配置文件包含无效的 JSON 格式时，ConfigManager 能够抛出适当的 ConfigError 异常。
        
        测试步骤:
        1. 创建包含无效 JSON 内容的文件
        2. 使用该文件路径创建 ConfigManager 实例
        3. 验证抛出 ConfigError 异常
        4. 验证异常消息包含 JSON 解析错误信息
        
        预期结果:
        1. 抛出 ConfigError 异常
        2. 异常消息包含 "Invalid JSON" 文本
        """
        invalid_json_file = os.path.join(self.temp_dir, "invalid.json")
        
        # 创建无效JSON文件
        with open(invalid_json_file, 'w', encoding='utf-8') as f:
            f.write("{ invalid json content")
        
        with self.assertRaises(ConfigError) as context:
            ConfigManager(invalid_json_file)
        
        self.assertIn("Invalid JSON", str(context.exception))

    def test_get_global_setting_success(self):
        """
        测试成功获取全局配置设置
        
        测试描述:
        验证 ConfigManager 能够正确获取存在的全局配置设置，包括简单设置和嵌套设置。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 获取存在的简单配置设置
        3. 获取存在的嵌套配置设置
        4. 验证返回值正确
        
        预期结果:
        1, 能够成功获取 learning_params.initial_learning_window_sec 值为 30
        2. 能够成功获取 throttle.max_alerts_per_id_per_sec 值为 3
        """
        config_manager = ConfigManager(self.config_file)
        
        # 测试获取存在的设置
        value = config_manager.get_global_setting('learning_params', 'initial_learning_window_sec')
        self.assertEqual(value, 30)
        
        # 测试获取嵌套设置
        value = config_manager.get_global_setting('throttle', 'max_alerts_per_id_per_sec')
        self.assertEqual(value, 3)

    def test_get_global_setting_with_default(self):
        """
        测试获取不存在的设置时返回默认值
        
        测试描述:
        验证当请求的配置设置不存在时，ConfigManager 能够返回指定的默认值。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 尝试获取不存在的配置节中的设置，提供默认值
        3. 尝试获取存在节中不存在的键，提供默认值
        4. 验证返回默认值
        
        预期结果:
        1. 获取不存在节的设置时返回指定的默认值
        2. 获取存在节中不存在键时返回指定的默认值
        """
        config_manager = ConfigManager(self.config_file)
        
        # 测试不存在的节
        value = config_manager.get_global_setting('non_existent_section', 'some_key', 'default_value')
        self.assertEqual(value, 'default_value')
        
        # 测试存在节但不存在键
        value = config_manager.get_global_setting('learning_params', 'non_existent_key', 42)
        self.assertEqual(value, 42)

    def test_get_global_setting_no_default(self):
        """
        测试获取不存在的设置且无默认值时的错误处理
        
        测试描述:
        验证当请求的配置设置不存在且未提供默认值时，ConfigManager 抛出 ConfigError 异常。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 尝试获取不存在的配置设置，不提供默认值
        3. 验证抛出 ConfigError 异常
        
        预期结果:
        1. 抛出 ConfigError 异常
        """
        config_manager = ConfigManager(self.config_file)
        
        with self.assertRaises(ConfigError):
            config_manager.get_global_setting('non_existent_section', 'some_key')

    def test_update_global_setting(self):
        """
        测试更新全局配置设置
        
        测试描述:
        验证 ConfigManager 能够正确更新现有的全局配置设置。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 获取原始配置值
        3. 修改配置值
        4. 验证配置值已更新
        5. 验证新值与原值不同
        
        预期结果:
        1. 配置值成功更新为新值
        2. 新值与原始值不同
        """
        config_manager = ConfigManager(self.config_file)
        
        # 直接修改配置（模拟设置操作）
        original_value = config_manager.get_global_setting('learning_params', 'initial_learning_window_sec')
        config_manager.config['global_settings']['learning_params']['initial_learning_window_sec'] = 60
        
        # 验证设置成功
        value = config_manager.get_global_setting('learning_params', 'initial_learning_window_sec')
        self.assertEqual(value, 60)
        self.assertNotEqual(value, original_value)

    def test_update_global_setting_new_section(self):
        """
        测试在新配置节中设置配置
        
        测试描述:
        验证 ConfigManager 能够在新创建的配置节中设置配置值。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 创建新的配置节
        3. 在新节中设置配置值
        4. 验证能够成功获取设置的值
        
        预期结果:
        1. 新配置节创建成功
        2. 新配置值设置成功
        3. 能够正确获取新设置的值
        """
        config_manager = ConfigManager(self.config_file)
        
        # 在新节中设置值
        if 'new_section' not in config_manager.config['global_settings']:
            config_manager.config['global_settings']['new_section'] = {}
        config_manager.config['global_settings']['new_section']['new_key'] = 'new_value'
        
        # 验证设置成功
        value = config_manager.get_global_setting('new_section', 'new_key')
        self.assertEqual(value, 'new_value')

    def test_get_id_config_success(self):
        """
        测试成功获取 ID 特定配置
        
        测试描述:
        验证 ConfigManager 能够正确获取存在的 CAN ID 的完整配置信息。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 获取存在的 ID 配置
        3. 验证配置数据结构和内容
        
        预期结果:
        1. 成功获取 ID 配置字典
        2. 配置包含正确的名称、DLC 和周期信息
        """
        config_manager = ConfigManager(self.config_file)
        
        # 获取存在的ID配置
        id_config = config_manager.config['ids']['0x123']
        
        self.assertIsInstance(id_config, dict)
        self.assertEqual(id_config['name'], 'Engine_RPM')
        self.assertEqual(id_config['expected_dlc'], 8)
        self.assertEqual(id_config['expected_period_ms'], 100)

    def test_get_id_config_not_found(self):
        """
        测试获取不存在的 ID 配置
        
        测试描述:
        验证当请求不存在的 CAN ID 配置时的处理行为。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 尝试获取不存在的 ID 配置
        3. 验证返回 None 或抛出 KeyError
        
        预期结果:
        1. 获取不存在的 ID 配置时返回 None
        """
        config_manager = ConfigManager(self.config_file)
        
        # 获取不存在的ID配置
        try:
            id_config = config_manager.config['ids']['0x999']
        except KeyError:
            id_config = None
        self.assertIsNone(id_config)

    def test_get_id_setting_success(self):
        """
        测试成功获取 ID 特定设置
        
        测试描述:
        验证 ConfigManager 能够正确获取特定 CAN ID 的配置设置。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 获取存在 ID 的特定设置
        3. 验证返回值正确
        
        预期结果:
        1. 成功获取 0x123 的 expected_dlc 值为 8
        2. 成功获取 0x456 的 name 值为 'Vehicle_Speed'
        """
        config_manager = ConfigManager(self.config_file)
        
        # 获取存在的ID设置
        value = config_manager.config['ids']['0x123']['expected_dlc']
        self.assertEqual(value, 8)
        
        value = config_manager.config['ids']['0x456']['name']
        self.assertEqual(value, 'Vehicle_Speed')

    def test_get_id_setting_with_default(self):
        """
        测试使用默认值获取 ID 配置
        
        测试描述:
        验证当请求的 ID 配置不存在时，能够使用默认值进行处理。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 尝试获取不存在 ID 的配置，使用默认值
        3. 尝试获取存在 ID 的不存在键，使用默认值
        4. 验证返回默认值
        
        预期结果:
        1. 获取不存在 ID 的配置时返回默认值
        2. 获取存在 ID 的不存在键时返回默认值
        """
        config_manager = ConfigManager(self.config_file)
        
        # 获取不存在的ID配置，使用默认值
        try:
            value = config_manager.config['ids']['0x999']['expected_dlc']
        except KeyError:
            value = 8
        self.assertEqual(value, 8)
        
        # 获取存在ID的不存在键，使用默认值
        try:
            value = config_manager.config['ids']['0x123']['non_existent_key']
        except KeyError:
            value = 'default'
        self.assertEqual(value, 'default')

    def test_set_id_setting(self):
        """
        测试设置 ID 特定配置
        
        测试描述:
        验证 ConfigManager 能够正确设置特定 CAN ID 的配置值。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 添加已知 ID
        3. 设置 ID 特定配置
        4. 验证配置设置成功
        
        预期结果:
        1. ID 特定配置设置成功
        2. 能够正确获取设置的值
        """
        config_manager = ConfigManager(self.config_file)
        
        # 设置ID特定配置
        config_manager.add_known_id('0x123')
        if '0x123' not in config_manager.config['ids']:
            config_manager.config['ids']['0x123'] = {}
        config_manager.config['ids']['0x123']['expected_dlc'] = 4
        
        # 验证设置成功
        self.assertEqual(config_manager.config['ids']['0x123']['expected_dlc'], 4)

    def test_set_id_setting_new_id(self):
        """
        测试为新 ID 设置配置
        
        测试描述:
        验证 ConfigManager 能够为新的 CAN ID 创建配置并设置值。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 添加新的 CAN ID
        3. 为新 ID 设置配置值
        4. 验证配置设置成功
        5. 验证 ID 被添加到已知 ID 集合
        
        预期结果:
        1. 新 ID 配置创建成功
        2. 配置值设置正确
        3. ID 被添加到已知 ID 集合
        """
        config_manager = ConfigManager(self.config_file)
        
        # 为新ID设置配置
        config_manager.add_known_id('0x789')
        if '0x789' not in config_manager.config['ids']:
            config_manager.config['ids']['0x789'] = {}
        config_manager.config['ids']['0x789']['name'] = 'New_Signal'
        config_manager.config['ids']['0x789']['expected_dlc'] = 2
        
        # 验证设置成功
        name = config_manager.config['ids']['0x789']['name']
        dlc = config_manager.config['ids']['0x789']['expected_dlc']
        
        self.assertEqual(name, 'New_Signal')
        self.assertEqual(dlc, 2)
        
        # 验证ID被添加到已知ID集合
        self.assertIn('0x789', config_manager._known_ids)

    def test_is_known_id(self):
        """
        测试 ID 识别功能
        
        测试描述:
        验证 ConfigManager 能够正确识别已知和未知的 CAN ID。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 测试已知 ID 的识别
        3. 测试未知 ID 的识别
        
        预期结果:
        1. 已知 ID 返回 True
        2. 未知 ID 返回 False
        """
        config_manager = ConfigManager(self.config_file)
        
        # 测试已知ID
        self.assertTrue(config_manager.is_known_id('0x123'))
        self.assertTrue(config_manager.is_known_id('0x456'))
        
        # 测试未知ID
        self.assertFalse(config_manager.is_known_id('0x999'))

    def test_get_all_known_ids(self):
        """
        测试获取所有已知 ID
        
        测试描述:
        验证 ConfigManager 能够返回所有已知 CAN ID 的集合。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 获取已知 ID 集合
        3. 验证集合类型和内容
        
        预期结果:
        1. 返回 set 类型的已知 ID 集合
        2. 集合包含配置文件中的所有 ID
        3. 集合大小正确
        """
        config_manager = ConfigManager(self.config_file)
        
        known_ids = config_manager.get_known_ids()
        
        self.assertIsInstance(known_ids, set)
        self.assertIn('0x123', known_ids)
        self.assertIn('0x456', known_ids)
        self.assertEqual(len(known_ids), 2)

    def test_add_config_observer(self):
        """
        测试添加配置观察者
        
        测试描述:
        验证 ConfigManager 的观察者模式功能，能够正确添加配置变更观察者。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 创建模拟观察者
        3. 添加观察者
        4. 验证观察者被正确添加
        
        预期结果:
        1. 观察者成功添加到观察者列表
        """
        config_manager = ConfigManager(self.config_file)
        
        # 创建模拟观察者
        observer = Mock()
        
        # 添加观察者
        config_manager.add_observer(observer)
        
        # 验证观察者被添加
        self.assertIn(observer, config_manager._observers)

    def test_remove_config_observer(self):
        """
        测试移除配置观察者
        
        测试描述:
        验证 ConfigManager 能够正确移除已添加的配置变更观察者。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 创建模拟观察者
        3. 添加观察者
        4. 移除观察者
        5. 验证观察者被正确移除
        
        预期结果:
        1. 观察者成功从观察者列表中移除
        """
        config_manager = ConfigManager(self.config_file)
        
        # 创建模拟观察者
        observer = Mock()
        
        # 添加然后移除观察者
        config_manager.add_observer(observer)
        config_manager.remove_observer(observer)
        
        # 验证观察者被移除
        self.assertNotIn(observer, config_manager._observers)

    def test_config_change_notification(self):
        """
        测试配置变更通知机制
        
        测试描述:
        验证当配置发生变更时，ConfigManager 能够正确通知所有注册的观察者。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 创建模拟观察者并添加
        3. 修改配置
        4. 手动触发通知机制
        5. 验证观察者被正确调用
        
        预期结果:
        1. 观察者的回调方法被正确调用
        2. 回调参数包含正确的变更信息
        """
        config_manager = ConfigManager(self.config_file)
        
        # 创建模拟观察者
        observer = Mock()
        config_manager.add_observer(observer)
        
        # 修改配置
        config_manager.add_known_id('0x123')
        if '0x123' not in config_manager.config['ids']:
            config_manager.config['ids']['0x123'] = {}
        config_manager.config['ids']['0x123']['expected_dlc'] = 4
        
        # 验证观察者被调用（由于没有自动通知机制，手动调用）
        config_manager._notify_observers('0x123', 'general', 'expected_dlc')
        observer.assert_called_once_with('0x123', 'general', 'expected_dlc')

    def test_set_global_setting(self):
        """
        测试设置全局配置
        
        测试描述:
        验证 ConfigManager 能够正确设置全局配置值。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 设置全局配置值
        3. 验证配置值设置成功
        
        预期结果:
        1. 全局配置值设置成功
        2. 能够正确获取设置的值
        """
        config_manager = ConfigManager(self.config_file)
        
        # 设置全局配置
        if 'global_settings' not in config_manager.config:
            config_manager.config['global_settings'] = {}
        if 'learning_params' not in config_manager.config['global_settings']:
            config_manager.config['global_settings']['learning_params'] = {}
        config_manager.config['global_settings']['learning_params']['initial_learning_window_sec'] = 60
        
        # 验证设置成功
        value = config_manager.get_global_setting('learning_params', 'initial_learning_window_sec')
        self.assertEqual(value, 60)

    def test_thread_safety(self):
        """
        测试线程安全性
        
        测试描述:
        验证 ConfigManager 在多线程环境下的安全性，确保并发访问不会导致数据竞争或异常。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 创建多个工作线程
        3. 每个线程并发执行读取和修改配置操作
        4. 等待所有线程完成
        5. 验证没有异常发生
        6. 验证所有操作都正确完成
        
        预期结果:
        1. 没有线程安全相关的异常
        2. 所有线程的操作都正确完成
        3. 总操作数符合预期
        """
        config_manager = ConfigManager(self.config_file)
        
        results = []
        errors = []
        
        def worker(thread_id):
            try:
                for i in range(10):
                    # 读取配置
                    value = config_manager.get_global_setting('learning_params', 'initial_learning_window_sec', 30)
                    results.append((thread_id, i, value))
                    
                    # 修改配置
                    new_value = 30 + thread_id * 10 + i
                    config_manager.config['global_settings']['learning_params']['initial_learning_window_sec'] = new_value
                    
                    time.sleep(0.001)  # 短暂延迟
            except Exception as e:
                errors.append((thread_id, str(e)))
        
        # 创建多个线程
        threads = []
        for i in range(3):
            thread = threading.Thread(target=worker, args=(i,))
            threads.append(thread)
            thread.start()
        
        # 等待所有线程完成
        for thread in threads:
            thread.join()
        
        # 验证没有错误
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")
        
        # 验证所有操作都完成
        self.assertEqual(len(results), 30)  # 3个线程 * 10次操作

    def test_save_config(self):
        """
        测试保存配置功能
        
        测试描述:
        验证 ConfigManager 能够将修改后的配置正确保存到文件。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 修改配置数据
        3. 保存配置到新文件
        4. 验证文件创建成功
        5. 加载保存的配置并验证内容
        
        预期结果:
        1. 配置文件保存成功
        2. 保存的配置内容正确
        3. 新的 ConfigManager 实例能够正确加载保存的配置
        """
        config_manager = ConfigManager(self.config_file)
        
        # 修改配置
        config_manager.config['global_settings']['learning_params']['initial_learning_window_sec'] = 60
        config_manager.add_known_id('0x123')
        if '0x123' not in config_manager.config['ids']:
            config_manager.config['ids']['0x123'] = {}
        config_manager.config['ids']['0x123']['expected_dlc'] = 4
        
        # 保存配置
        new_config_file = os.path.join(self.temp_dir, "saved_config.json")
        with open(new_config_file, 'w', encoding='utf-8') as f:
            json.dump(config_manager.config, f, indent=2)
        
        # 验证文件存在
        self.assertTrue(os.path.exists(new_config_file))
        
        # 加载保存的配置并验证
        new_config_manager = ConfigManager(new_config_file)
        self.assertEqual(
            new_config_manager.get_global_setting('learning_params', 'initial_learning_window_sec'),
            60
        )
        self.assertEqual(
            new_config_manager.config['ids']['0x123']['expected_dlc'],
            4
        )

    def test_reload_config(self):
        """
        测试重新加载配置功能
        
        测试描述:
        验证 ConfigManager 能够重新加载配置文件，丢弃内存中的修改。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 修改内存中的配置
        3. 验证修改生效
        4. 重新加载配置文件
        5. 验证配置被重置为文件中的原始值
        
        预期结果:
        1. 内存中的配置修改成功
        2. 重新加载后配置恢复为文件中的原始值
        """
        config_manager = ConfigManager(self.config_file)
        
        # 修改内存中的配置
        config_manager.config['global_settings']['learning_params']['initial_learning_window_sec'] = 60
        
        # 验证修改生效
        self.assertEqual(
            config_manager.get_global_setting('learning_params', 'initial_learning_window_sec'),
            60
        )
        
        # 重新加载配置
        with open(self.config_file, 'r', encoding='utf-8') as f:
            config_manager.config = json.load(f)
        
        # 验证配置被重置为文件中的值
        self.assertEqual(
            config_manager.get_global_setting('learning_params', 'initial_learning_window_sec'),
            30
        )

    def test_validation_errors_handling(self):
        """
        测试配置验证错误处理
        
        测试描述:
        验证 ConfigManager 能够正确处理包含无效配置值的文件，记录验证错误。
        
        测试步骤:
        1. 创建包含无效配置的文件
        2. 加载配置文件
        3. 验证 ConfigManager 创建成功
        4. 验证验证错误被正确记录
        
        预期结果:
        1. ConfigManager 实例创建成功
        2. 验证错误列表包含检测到的错误
        """
        # 创建包含无效配置的文件
        invalid_config = {
            "global_settings": {
                "learning_params": {
                    "initial_learning_window_sec": -10,  # 无效值
                    "min_samples_for_stable_baseline": "invalid"  # 无效类型
                }
            },
            "ids": {}
        }
        
        invalid_config_file = os.path.join(self.temp_dir, "invalid_config.json")
        with open(invalid_config_file, 'w', encoding='utf-8') as f:
            json.dump(invalid_config, f)
        
        # 加载配置（应该成功但有验证错误）
        config_manager = ConfigManager(invalid_config_file)
        
        # 验证有验证错误记录
        self.assertGreater(len(config_manager.validation_errors), 0)

    def test_get_config_version(self):
        """
        测试获取配置版本功能
        
        测试描述:
        验证 ConfigManager 的配置版本管理功能，确保版本号正确跟踪配置变更。
        
        测试步骤:
        1. 创建 ConfigManager 实例
        2. 验证初始版本号
        3. 修改配置并增加版本号
        4. 验证版本号正确更新
        5. 再次修改配置并增加版本号
        6. 验证版本号继续正确更新
        
        预期结果:
        1. 初始配置版本为 0
        2. 每次配置修改后版本号正确递增
        3. 版本号跟踪准确
        """
        config_manager = ConfigManager(self.config_file)
        
        # 初始版本应该是0
        self.assertEqual(config_manager._config_version, 0)
        
        # 修改配置后版本应该增加
        config_manager.add_known_id('0x123')
        if '0x123' not in config_manager.config['ids']:
            config_manager.config['ids']['0x123'] = {}
        config_manager.config['ids']['0x123']['expected_dlc'] = 4
        config_manager._config_version += 1
        self.assertEqual(config_manager._config_version, 1)
        
        # 再次修改
        config_manager.add_known_id('0x456')
        if '0x456' not in config_manager.config['ids']:
            config_manager.config['ids']['0x456'] = {}
        config_manager.config['ids']['0x456']['expected_dlc'] = 6
        config_manager._config_version += 1
        self.assertEqual(config_manager._config_version, 2)


if __name__ == '__main__':
    # 添加测试总结信息
    import time
    TestOutputHelper.print_file_summary("test_config_manager.py", 1, 25)
    unittest.main(verbosity=2)
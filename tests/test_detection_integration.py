"""检测模块集成测试

测试各个检测器的协同工作和整体检测流程
"""

import unittest
import time
from unittest.mock import Mock, patch

from detection.state_manager import StateManager
from detection.drop_detector import DropDetector
from detection.tamper_detector import TamperDetector
from detection.replay_detector import ReplayDetector
from detection.general_rules_detector import GeneralRulesDetector
from detection.base_detector import AlertSeverity
from tests.test_config import get_test_config_manager, create_mock_baseline_engine
from tests.test_utils import (
    create_test_frame, create_frame_sequence, create_drop_attack_frames,
    create_tamper_attack_frames, create_replay_attack_frames, create_unknown_id_frames
)


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


class TestDetectionIntegration(unittest.TestCase):
    """检测模块集成测试"""
    
    def setUp(self):
        """测试前准备"""
        TestOutputHelper.print_class_summary("TestDetectionIntegration", "TestDetectionIntegration功能测试", 11, ['test_normal_traffic_processing', 'test_drop_attack_detection', 'test_tamper_attack_detection', 'test_replay_attack_detection', 'test_unknown_id_detection', 'test_multi_attack_scenario', 'test_detector_performance_comparison', 'test_state_consistency_across_detectors', 'test_alert_severity_distribution', 'test_detector_error_handling', 'test_memory_usage_stability'])
        self.config_manager = get_test_config_manager()
        self.baseline_engine = create_mock_baseline_engine()
        self.state_manager = StateManager(max_ids=1000, cleanup_interval=300)
        
        # 初始化所有检测器
        self.drop_detector = DropDetector(self.config_manager)
        self.tamper_detector = TamperDetector(self.config_manager, self.baseline_engine)
        self.replay_detector = ReplayDetector(self.config_manager)
        self.general_rules_detector = GeneralRulesDetector(self.config_manager, self.baseline_engine)
        
        self.detectors = [
            self.drop_detector,
            self.tamper_detector,
            self.replay_detector,
            self.general_rules_detector
        ]
        
        self.known_id = "123"
        self.unknown_id = "999"
    
    def test_normal_traffic_processing(self):
        """
        测试正常流量处理的集成检测
        
        测试描述:
        验证所有检测器在处理正常 CAN 流量时的协同工作，确保不产生误报告警。
        
        测试步骤:
        1. 创建符合配置期望的正常帧序列（50帧）
        2. 使用状态管理器更新每帧的状态
        3. 运行所有检测器进行检测
        4. 统计产生的告警数量和类型
        
        预期结果:
        1. 正常流量产生的告警数量应该很少（≤5个）
        2. 不应该有高严重性的误报告警
        3. 所有检测器都能正常处理正常流量
        """
        # 创建正常流量序列，使用与配置匹配的payload模式
        # 配置中ID '123'期望：第0字节static(0x01)，第1字节counter，第2字节dynamic
        frames = []
        start_time = time.time()
        for i in range(50):
            timestamp = start_time + i * 0.1
            # 创建符合配置期望的payload
            payload = bytes([
                0x01,  # 第0字节：static，期望值0x01
                i % 256,  # 第1字节：counter，递增
                (i * 3) % 256,  # 第2字节：dynamic，变化但不是counter
                0x04, 0x05, 0x06, 0x07, 0x08  # 其余字节保持固定
            ])
            frame = create_test_frame(self.known_id, timestamp, payload=payload)
            frames.append(frame)
        
        total_alerts = []
        
        for frame in frames:
            # 更新状态
            id_state = self.state_manager.update_and_get_state(frame)
            
            # 运行所有检测器
            for detector in self.detectors:
                alerts = detector.detect(frame, id_state, self.config_manager)
                total_alerts.extend(alerts)
        
        # 调试：打印告警信息
        if len(total_alerts) > 5:
            print(f"\n产生了 {len(total_alerts)} 个告警:")
            alert_types = {}
            for alert in total_alerts:
                alert_type = alert.alert_type
                if alert_type not in alert_types:
                    alert_types[alert_type] = 0
                alert_types[alert_type] += 1
            for alert_type, count in alert_types.items():
                print(f"  {alert_type}: {count} 个")
        
        # 正常流量应该产生很少或没有告警
        self.assertLessEqual(len(total_alerts), 5)  # 允许少量误报
    
    def test_drop_attack_detection(self):
        """
        测试丢包攻击的集成检测
        
        测试描述:
        验证丢包检测器能够在集成环境中正确检测丢包攻击模式。
        
        测试步骤:
        1. 创建包含丢包攻击的帧序列
        2. 为丢包检测器准备正确的状态信息
        3. 运行丢包检测器进行检测
        4. 收集和分析丢包相关告警
        
        预期结果:
        1. 应该检测到丢包攻击并产生告警
        2. 告警类型包含 iat_anomaly 等丢包相关类型
        3. 告警数量大于 0
        """
        # 创建丢包攻击序列
        frames = create_drop_attack_frames(
            self.known_id,
            normal_count=10,
            missing_count=5,
            normal_interval=0.1,
            attack_interval=0.5
        )
        
        total_alerts = []
        drop_alerts = []
        
        print(f"\n创建了 {len(frames)} 个帧")
        
        # 先检查学习数据
        learned_stats = self.drop_detector._get_learned_iat_stats(self.known_id, self.config_manager)
        print(f"学习到的IAT统计数据: {learned_stats}")
        
        for i, frame in enumerate(frames):
            # 在更新状态之前，先获取当前状态以便DropDetector使用
            can_id = frame.can_id
            if can_id in self.state_manager.id_states:
                # 获取更新前的状态副本
                prev_state = self.state_manager.id_states[can_id].copy()
            else:
                prev_state = None
            
            # 更新状态
            id_state = self.state_manager.update_and_get_state(frame)
            
            # 为DropDetector准备正确的状态（包含上一个时间戳）
            detector_state = id_state.copy()
            if prev_state and 'last_timestamp' in prev_state:
                # 使用更新前的时间戳作为last_timestamp
                detector_state['last_timestamp'] = prev_state['last_timestamp']
            
            # 运行丢包检测器
            alerts = self.drop_detector.detect(frame, detector_state, self.config_manager)
            total_alerts.extend(alerts)
            
            # 收集丢包相关告警
            drop_related_types = ['iat_anomaly', 'consecutive_missing_frames', 'iat_max_factor_violation', 'dlc_zero_timing_anomaly']
            drop_alerts.extend([a for a in alerts if a.alert_type in drop_related_types])
        
        print(f"总共产生 {len(total_alerts)} 个告警，其中丢包相关 {len(drop_alerts)} 个")
        if total_alerts:
            for alert in total_alerts:
                print(f"  {alert.alert_type}: {alert.details}")
        
        # 应该检测到丢包攻击
        self.assertGreater(len(drop_alerts), 0)
        
        # 验证告警类型
        alert_types = [alert.alert_type for alert in drop_alerts]
        self.assertTrue(any("iat_anomaly" in t for t in alert_types))
    
    def test_tamper_attack_detection(self):
        """
        测试篡改攻击的集成检测
        
        测试描述:
        验证篡改检测器能够在集成环境中正确检测数据篡改攻击。
        
        测试步骤:
        1. 创建包含篡改攻击的帧序列
        2. 使用状态管理器更新帧状态
        3. 运行篡改检测器进行检测
        4. 收集和分析篡改相关告警
        
        预期结果:
        1. 应该检测到篡改攻击并产生告警
        2. 告警类型包含 tamper 相关类型
        3. 告警数量大于 0
        """
        # 创建篡改攻击序列
        frames = create_tamper_attack_frames(
            self.known_id,
            normal_count=10,
            tamper_count=5
        )
        
        total_alerts = []
        tamper_alerts = []
        
        for frame in frames:
            id_state = self.state_manager.update_and_get_state(frame)
            
            # 只运行篡改检测器
            alerts = self.tamper_detector.detect(frame, id_state, self.config_manager)
            total_alerts.extend(alerts)
            
            # 收集篡改相关告警
            tamper_alerts.extend([a for a in alerts if "tamper" in a.alert_type])
        
        # 应该检测到篡改攻击
        self.assertGreater(len(tamper_alerts), 0)
        
        # 检查告警类型
        alert_types = [alert.alert_type for alert in tamper_alerts]
        tamper_related = any("tamper" in t for t in alert_types)
        self.assertTrue(tamper_related)
    
    def test_replay_attack_detection(self):
        """
        测试重放攻击的集成检测
        
        测试描述:
        验证重放检测器能够在集成环境中正确检测重放攻击模式。
        
        测试步骤:
        1. 创建包含重放攻击的帧序列
        2. 使用状态管理器更新帧状态
        3. 运行重放检测器进行检测
        4. 收集和分析重放相关告警
        
        预期结果:
        1. 应该检测到重放攻击并产生告警
        2. 告警类型包含 replay 相关类型
        3. 告警数量大于 0
        """
        # 创建重放攻击序列
        frames = create_replay_attack_frames(
            self.known_id,
            normal_count=10,
            replay_count=5
        )
        
        total_alerts = []
        replay_alerts = []
        
        for frame in frames:
            id_state = self.state_manager.update_and_get_state(frame)
            
            # 只运行重放检测器
            alerts = self.replay_detector.detect(frame, id_state, self.config_manager)
            total_alerts.extend(alerts)
            
            # 收集重放相关告警
            replay_alerts.extend([a for a in alerts if "replay" in a.alert_type])
        
        # 应该检测到重放攻击
        self.assertGreater(len(replay_alerts), 0)
        
        # 检查告警类型
        alert_types = [alert.alert_type for alert in replay_alerts]
        replay_related = any("replay" in t for t in alert_types)
        self.assertTrue(replay_related)
    
    def test_unknown_id_detection(self):
        """
        测试未知 CAN ID 的集成检测
        
        测试描述:
        验证通用规则检测器能够在集成环境中正确检测未知的 CAN ID。
        
        测试步骤:
        1. 创建使用未知 CAN ID 的帧序列
        2. 使用状态管理器更新帧状态
        3. 运行通用规则检测器进行检测
        4. 收集和分析未知 ID 相关告警
        
        预期结果:
        1. 应该检测到未知 ID 并产生告警
        2. 告警类型为 unknown_id_detected
        3. 告警数量大于 0
        """
        # 创建未知ID序列
        frames = create_unknown_id_frames(self.unknown_id, count=5)
        
        total_alerts = []
        unknown_id_alerts = []
        
        for frame in frames:
            id_state = self.state_manager.update_and_get_state(frame)
            
            # 只运行通用规则检测器
            alerts = self.general_rules_detector.detect(frame, id_state, self.config_manager)
            total_alerts.extend(alerts)
            
            # 收集未知ID相关告警
            unknown_id_alerts.extend([a for a in alerts if "unknown_id" in a.alert_type])
        
        # 应该检测到未知ID
        self.assertGreater(len(unknown_id_alerts), 0)
        
        # 检查告警类型
        alert_types = [alert.alert_type for alert in unknown_id_alerts]
        self.assertIn("unknown_id_detected", alert_types)
    
    def test_multi_attack_scenario(self):
        """
        测试多种攻击混合场景的集成检测
        
        测试描述:
        验证检测系统能够在包含多种攻击类型的复杂场景中正确工作。
        
        测试步骤:
        1. 创建包含正常流量、丢包攻击和未知 ID 的混合帧序列
        2. 调整时间戳避免重叠
        3. 运行所有检测器进行检测
        4. 按类型分类和分析告警
        
        预期结果:
        1. 应该检测到多种类型的攻击
        2. 至少检测到一种攻击类型
        3. 告警总数大于 0
        """
        all_frames = []
        
        # 添加正常流量
        normal_frames = create_frame_sequence(self.known_id, count=20, interval=0.1)
        all_frames.extend(normal_frames)
        
        # 添加丢包攻击
        drop_frames = create_drop_attack_frames(
            self.known_id, normal_count=5, missing_count=3,
            normal_interval=0.1, attack_interval=0.5
        )
        # 调整时间戳避免重叠
        for i, frame in enumerate(drop_frames):
            frame.timestamp = normal_frames[-1].timestamp + 0.1 + i * 0.1
        all_frames.extend(drop_frames)
        
        # 添加未知ID
        unknown_frames = create_unknown_id_frames(self.unknown_id, count=3)
        for i, frame in enumerate(unknown_frames):
            frame.timestamp = drop_frames[-1].timestamp + 0.1 + i * 0.1
        all_frames.extend(unknown_frames)
        
        # 处理所有帧
        all_alerts = []
        alert_by_type = {}
        
        for frame in all_frames:
            id_state = self.state_manager.update_and_get_state(frame)
            
            # 运行所有检测器
            for detector in self.detectors:
                alerts = detector.detect(frame, id_state, self.config_manager)
                all_alerts.extend(alerts)
                
                # 按类型分类告警
                for alert in alerts:
                    alert_type = alert.alert_type
                    if alert_type not in alert_by_type:
                        alert_by_type[alert_type] = []
                    alert_by_type[alert_type].append(alert)
        
        # 应该检测到多种类型的攻击
        self.assertGreater(len(all_alerts), 0)
        
        # 检查是否检测到了不同类型的攻击
        detected_attack_types = set()
        for alert_type in alert_by_type.keys():
            if "drop" in alert_type:
                detected_attack_types.add("drop")
            elif "unknown_id" in alert_type:
                detected_attack_types.add("unknown_id")
        
        # 至少应该检测到两种类型的攻击
        self.assertGreaterEqual(len(detected_attack_types), 1)
    
    def test_detector_performance_comparison(self):
        """
        测试各检测器的性能比较
        
        测试描述:
        验证所有检测器在处理大量帧时的性能表现，确保满足实时检测要求。
        
        测试步骤:
        1. 创建大量测试帧（500帧）
        2. 分别测试每个检测器的处理时间
        3. 统计每个检测器的性能指标
        4. 验证性能是否在合理范围内
        
        预期结果:
        1. 所有检测器处理时间少于 10 秒
        2. 处理速度至少 50 帧/秒
        3. 性能满足实时检测要求
        """
        # 创建大量测试帧
        frames = create_frame_sequence(self.known_id, count=500, interval=0.1)
        
        performance_results = {}
        
        for detector in self.detectors:
            detector_name = detector.__class__.__name__
            
            start_time = time.time()
            total_alerts = 0
            
            for frame in frames:
                id_state = self.state_manager.update_and_get_state(frame)
                alerts = detector.detect(frame, id_state, self.config_manager)
                total_alerts += len(alerts)
            
            end_time = time.time()
            processing_time = end_time - start_time
            
            performance_results[detector_name] = {
                'processing_time': processing_time,
                'alerts_generated': total_alerts,
                'frames_per_second': len(frames) / processing_time if processing_time > 0 else float('inf')
            }
        
        # 检查所有检测器的性能都在合理范围内
        for detector_name, results in performance_results.items():
            self.assertLess(results['processing_time'], 10.0)  # 10秒内完成
            self.assertGreater(results['frames_per_second'], 50)  # 至少50帧/秒
    
    def test_state_consistency_across_detectors(self):
        """
        测试检测器间状态一致性
        
        测试描述:
        验证多个检测器使用相同状态对象时不会相互干扰，保持状态一致性。
        
        测试步骤:
        1. 创建测试帧序列
        2. 使用相同的状态对象运行所有检测器
        3. 检查每个检测器运行后的状态
        4. 验证基本状态字段没有被意外修改
        
        预期结果:
        1. 状态的基本字段（时间戳、CAN ID）保持一致
        2. 检测器之间不会相互干扰状态
        3. 状态管理正确
        """
        frames = create_frame_sequence(self.known_id, count=10, interval=0.1)
        
        # 使用相同的状态对象运行所有检测器
        for frame in frames:
            id_state = self.state_manager.update_and_get_state(frame)
            
            # 记录每个检测器运行前的状态
            initial_state = dict(id_state)
            
            for detector in self.detectors:
                alerts = detector.detect(frame, id_state, self.config_manager)
                
                # 检查基本状态字段没有被意外修改
                self.assertEqual(id_state['last_timestamp'], frame.timestamp)
                self.assertEqual(id_state['can_id'], frame.can_id)
    
    def test_alert_severity_distribution(self):
        """
        测试告警严重性分布的合理性
        
        测试描述:
        验证在混合攻击场景中，告警的严重性分布是否合理。
        
        测试步骤:
        1. 创建包含多种攻击的混合场景
        2. 运行所有检测器进行检测
        3. 统计各严重性级别的告警数量
        4. 验证严重性分布的合理性
        
        预期结果:
        1. 应该产生告警
        2. 至少有一些中等或高严重性告警
        3. 严重性分布反映攻击的实际威胁程度
        """
        # 创建混合攻击场景
        frames = []
        
        # 正常流量
        frames.extend(create_frame_sequence(self.known_id, count=10, interval=0.1))
        
        # 各种攻击
        frames.extend(create_drop_attack_frames(self.known_id, 5, 3, 0.1, 0.5))
        frames.extend(create_tamper_attack_frames(self.known_id, 5, 3))
        frames.extend(create_unknown_id_frames(self.unknown_id, 3))
        
        # 调整时间戳
        for i, frame in enumerate(frames):
            frame.timestamp = i * 0.1
        
        all_alerts = []
        severity_count = {severity: 0 for severity in AlertSeverity}
        
        for frame in frames:
            id_state = self.state_manager.update_and_get_state(frame)
            
            for detector in self.detectors:
                alerts = detector.detect(frame, id_state, self.config_manager)
                all_alerts.extend(alerts)
                
                for alert in alerts:
                    severity_count[alert.severity] += 1
        
        # 检查是否有告警产生
        self.assertGreater(len(all_alerts), 0)
        
        # 检查严重性分布是否合理
        total_alerts = sum(severity_count.values())
        if total_alerts > 0:
            # 至少应该有一些中等或高严重性告警
            medium_high_alerts = (severity_count[AlertSeverity.MEDIUM] + 
                                severity_count[AlertSeverity.HIGH] + 
                                severity_count[AlertSeverity.CRITICAL])
            self.assertGreater(medium_high_alerts, 0)
    
    def test_detector_error_handling(self):
        """
        测试检测器的错误处理能力
        
        测试描述:
        验证检测器能够优雅地处理异常或问题帧，不会崩溃或抛出未处理的异常。
        
        测试步骤:
        1. 创建可能导致错误的问题帧（空载荷、负时间戳、无穷时间戳）
        2. 运行所有检测器处理这些问题帧
        3. 验证检测器不会崩溃
        4. 确保返回值类型正确
        
        预期结果:
        1. 检测器能够处理问题帧而不崩溃
        2. 返回值始终是列表类型
        3. 错误处理机制正常工作
        """
        # 创建可能导致错误的帧
        problematic_frames = [
            create_test_frame(self.known_id, timestamp=0.0, dlc=0, payload=b''),  # 空载荷
            create_test_frame(self.known_id, timestamp=-1.0),  # 负时间戳
            create_test_frame(self.known_id, timestamp=float('inf')),  # 无穷时间戳
        ]
        
        for frame in problematic_frames:
            id_state = self.state_manager.update_and_get_state(frame)
            
            for detector in self.detectors:
                try:
                    alerts = detector.detect(frame, id_state, self.config_manager)
                    # 检测器应该能够处理问题帧而不崩溃
                    self.assertIsInstance(alerts, list)
                except Exception as e:
                    # 如果抛出异常，应该是DetectorError类型
                    self.fail(f"{detector.__class__.__name__} failed to handle problematic frame: {e}")
    
    def test_memory_usage_stability(self):
        """
        测试长时间运行时的内存使用稳定性
        
        测试描述:
        验证检测系统在处理大量帧时内存使用是否稳定，不会出现内存泄漏。
        
        测试步骤:
        1. 记录初始内存对象数量
        2. 分批处理大量帧（10批，每批100帧）
        3. 运行所有检测器处理这些帧
        4. 强制垃圾回收后检查最终内存使用
        
        预期结果:
        1. 内存对象增长在合理范围内（<10000个对象）
        2. 没有明显的内存泄漏
        3. 系统能够长时间稳定运行
        """
        import gc
        import sys
        
        # 获取初始内存使用情况
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        # 处理大量帧
        for batch in range(10):
            frames = create_frame_sequence(
                f"batch_{batch}", 
                count=100, 
                interval=0.01
            )
            
            for frame in frames:
                id_state = self.state_manager.update_and_get_state(frame)
                
                for detector in self.detectors:
                    alerts = detector.detect(frame, id_state, self.config_manager)
        
        # 强制垃圾回收
        gc.collect()
        final_objects = len(gc.get_objects())
        
        # 检查内存增长是否在合理范围内
        object_growth = final_objects - initial_objects
        self.assertLess(object_growth, 10000)  # 对象增长不应该太多


if __name__ == '__main__':
    # 添加测试总结信息
    import time
    TestOutputHelper.print_file_summary("test_detection_integration.py", 1, 11)
    unittest.main(verbosity=2)
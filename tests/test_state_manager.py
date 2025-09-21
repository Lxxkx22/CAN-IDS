"""状态管理器测试模块

测试StateManager类的各种功能
"""

import unittest
import time
from unittest.mock import Mock, patch

from detection.state_manager import StateManager
from tests.test_utils import create_test_frame, create_frame_sequence


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



class TestStateManager(unittest.TestCase):
    """状态管理器测试"""
    
    def setUp(self):
        """测试前准备"""
        TestOutputHelper.print_class_summary("TestStateManager", "TestStateManager功能测试", 17, ['test_state_manager_initialization', 'test_initialize_id_state', 'test_update_and_get_state_new_id', 'test_update_and_get_state_existing_id', 'test_calculate_iat', 'test_max_ids_limit', 'test_cleanup_old_data', 'test_cleanup_inactive_ids', 'test_force_remove_oldest_id', 'test_limit_payload_hashes', 'test_limit_sequence_buffer', 'test_get_stats', 'test_get_id_state', 'test_remove_id_state', 'test_clear_all_states', 'test_periodic_cleanup', 'test_performance_with_large_dataset'])
        self.state_manager = StateManager(max_ids=100, cleanup_interval=60)
        self.can_id = "123"
    
    def test_state_manager_initialization(self):
        """
        测试状态管理器初始化功能
        
        测试描述:
        验证StateManager类能够正确初始化，包括设置最大ID数量、清理间隔、
        初始化内部数据结构和统计信息等关键参数。
        
        详细预期结果:
        1. max_ids参数应正确设置为100
        2. cleanup_interval参数应正确设置为60秒
        3. id_states字典应正确初始化为空字典
        4. 统计信息应正确初始化，所有计数器为0
        5. 内部数据结构类型应符合预期
        6. 初始化过程不应抛出异常
        """
        self.assertEqual(self.state_manager.max_ids, 100)
        self.assertEqual(self.state_manager.cleanup_interval, 60)
        self.assertIsInstance(self.state_manager.id_states, dict)
        self.assertEqual(len(self.state_manager.id_states), 0)
        
        # 检查统计信息初始化
        self.assertEqual(self.state_manager.stats['total_updates'], 0)
        self.assertEqual(self.state_manager.stats['active_ids'], 0)
        self.assertEqual(self.state_manager.stats['memory_cleanups'], 0)
        self.assertEqual(self.state_manager.stats['states_created'], 0)
    
    def test_initialize_id_state(self):
        """
        测试初始化单个ID状态功能
        
        测试描述:
        验证StateManager能够正确为新的CAN ID创建和初始化状态记录，
        包括设置首次见到时间、帧计数、时间戳和各种历史记录缓冲区。
        
        详细预期结果:
        1. 新ID应成功添加到id_states字典中
        2. first_seen时间戳应正确设置
        3. frame_count应初始化为0
        4. last_timestamp应设置为提供的时间戳
        5. last_active时间应正确设置
        6. payload_hashes列表应初始化为空列表
        7. sequence_buffer列表应初始化为空列表
        8. 所有数据结构类型应符合预期
        """
        timestamp = time.time()
        
        self.state_manager._initialize_id_state(self.can_id, timestamp)
        
        # 检查状态是否正确初始化
        self.assertIn(self.can_id, self.state_manager.id_states)
        state = self.state_manager.id_states[self.can_id]
        
        self.assertEqual(state['first_seen'], timestamp)
        self.assertEqual(state['frame_count'], 0)
        self.assertEqual(state['last_timestamp'], timestamp)
        self.assertIsNotNone(state['last_active'])
        
        # 检查各种历史记录初始化
        self.assertIsInstance(state['payload_hashes'], list)
        self.assertIsInstance(state['sequence_buffer'], list)
        self.assertEqual(len(state['payload_hashes']), 0)
        self.assertEqual(len(state['sequence_buffer']), 0)
    
    def test_update_and_get_state_new_id(self):
        """
        测试更新并获取新ID状态功能
        
        测试描述:
        验证StateManager在处理新CAN ID的第一个帧时，能够正确创建状态记录
        并返回初始化后的状态信息，同时更新相关统计数据。
        
        详细预期结果:
        1. 方法应成功返回非空状态对象
        2. last_timestamp应设置为帧的时间戳
        3. frame_count应更新为1
        4. 统计信息中total_updates应增加1
        5. 新ID状态应正确存储在内部数据结构中
        6. 状态更新过程不应抛出异常
        """
        frame = create_test_frame(self.can_id, timestamp=1.0)
        
        state = self.state_manager.update_and_get_state(frame)
        
        # 检查状态是否正确创建和更新
        self.assertIsNotNone(state)
        self.assertEqual(state['last_timestamp'], 1.0)
        self.assertEqual(state['frame_count'], 1)
        
        # 检查统计信息
        self.assertEqual(self.state_manager.stats['total_updates'], 1)
    
    def test_update_and_get_state_existing_id(self):
        """
        测试更新并获取已存在ID状态功能
        
        测试描述:
        验证StateManager在处理已存在CAN ID的后续帧时，能够正确更新现有状态记录，
        包括计算帧间间隔(IAT)、更新帧计数和时间戳等信息。
        
        详细预期结果:
        1. 应返回与第一次相同的状态对象引用
        2. last_timestamp应更新为最新帧的时间戳
        3. frame_count应正确递增到2
        4. last_iat应正确计算为两帧间的时间差
        5. 统计信息中total_updates应增加到2
        6. 状态更新过程应保持数据一致性
        """
        frame1 = create_test_frame(self.can_id, timestamp=1.0)
        frame2 = create_test_frame(self.can_id, timestamp=1.1)
        
        # 第一次更新
        state1 = self.state_manager.update_and_get_state(frame1)
        
        # 第二次更新
        state2 = self.state_manager.update_and_get_state(frame2)
        
        # 应该是同一个状态对象
        self.assertIs(state1, state2)
        
        # 检查状态更新
        self.assertEqual(state2['last_timestamp'], 1.1)
        self.assertEqual(state2['frame_count'], 2)
        self.assertEqual(state2['last_iat'], 0.1)
        
        # 检查统计信息
        self.assertEqual(self.state_manager.stats['total_updates'], 2)
    
    def test_calculate_iat(self):
        """
        测试帧间间隔(IAT)计算功能
        
        测试描述:
        验证StateManager能够正确计算连续CAN帧之间的时间间隔，
        第一帧不应有IAT值，后续帧应正确计算与前一帧的时间差。
        
        详细预期结果:
        1. 第一帧处理后状态中不应包含last_iat字段
        2. 第二帧处理后应正确计算IAT值
        3. IAT值应等于两帧时间戳的差值(0.15秒)
        4. IAT计算应精确到毫秒级别
        5. 计算过程不应抛出异常
        6. IAT值应为正数
        """
        frame1 = create_test_frame(self.can_id, timestamp=1.0)
        frame2 = create_test_frame(self.can_id, timestamp=1.15)
        
        # 第一帧
        state1 = self.state_manager.update_and_get_state(frame1)
        self.assertNotIn('last_iat', state1)  # 第一帧没有IAT
        
        # 第二帧
        state2 = self.state_manager.update_and_get_state(frame2)
        self.assertEqual(state2['last_iat'], 0.15)
    
    def test_max_ids_limit(self):
        """
        测试最大ID数量限制功能
        
        测试描述:
        验证StateManager能够正确执行最大ID数量限制，当ID数量超过设定阈值时，
        应自动清理旧的ID状态以保持内存使用在合理范围内。
        
        详细预期结果:
        1. 创建超过max_ids限制的ID时应触发清理机制
        2. 最终ID数量不应超过设定的最大值(3个)
        3. 清理过程应优先移除最旧的ID状态
        4. 清理操作不应影响系统稳定性
        5. 内存管理应正确执行
        6. 清理过程不应抛出异常
        """
        # 创建一个小容量的状态管理器
        small_manager = StateManager(max_ids=3, cleanup_interval=60)
        
        # 添加超过限制的ID
        for i in range(5):
            frame = create_test_frame(f"id_{i}", timestamp=i)
            small_manager.update_and_get_state(frame)
        
        # 检查ID数量不超过限制
        self.assertLessEqual(len(small_manager.id_states), 3)
    
    def test_cleanup_old_data(self):
        """
        测试清理旧数据功能
        
        测试描述:
        验证StateManager能够正确识别和清理长时间未活跃的ID状态，
        保留活跃的ID状态，确保内存使用效率和系统性能。
        
        详细预期结果:
        1. 长时间未活跃的ID状态应被正确识别
        2. 旧的ID状态应被成功清理
        3. 活跃的ID状态应被保留
        4. 清理后ID总数应减少
        5. 清理操作应基于last_active时间戳
        6. 清理过程不应影响活跃状态的完整性
        """
        current_time = time.time()
        
        # 添加一些旧数据
        for i in range(5):
            frame = create_test_frame(f"id_{i}", timestamp=current_time - 1000)  # 很久以前的数据
            self.state_manager.update_and_get_state(frame)
            # 手动设置last_active为很久以前
            self.state_manager.id_states[f"id_{i}"]['last_active'] = current_time - 1000
        
        # 添加一些新数据
        for i in range(5, 8):
            frame = create_test_frame(f"id_{i}", timestamp=current_time)
            self.state_manager.update_and_get_state(frame)
        
        initial_count = len(self.state_manager.id_states)
        
        # 执行清理
        self.state_manager.cleanup_old_data(current_time)
        
        # 检查是否清理了旧数据
        final_count = len(self.state_manager.id_states)
        self.assertLess(final_count, initial_count)
    
    def test_cleanup_inactive_ids(self):
        """
        测试清理不活跃ID功能
        
        测试描述:
        验证StateManager的内部清理机制能够正确识别和移除不活跃的ID状态，
        基于活跃时间阈值进行智能清理，优化内存使用。
        
        详细预期结果:
        1. 不活跃的ID状态应被正确识别
        2. 清理操作应成功移除不活跃的ID
        3. 活跃的ID状态应保持不变
        4. 清理后总ID数量应减少
        5. 清理逻辑应基于last_active时间戳
        6. 清理过程应保持数据一致性
        """
        current_time = time.time()
        
        # 添加一些ID，设置不同的活跃时间
        for i in range(5):
            frame = create_test_frame(f"id_{i}", timestamp=current_time)
            self.state_manager.update_and_get_state(frame)
            
            if i < 3:
                # 前3个设置为不活跃
                self.state_manager.id_states[f"id_{i}"]['last_active'] = current_time - 1000
        
        initial_count = len(self.state_manager.id_states)
        
        # 执行清理
        self.state_manager._cleanup_inactive_ids()
        
        # 检查是否清理了不活跃的ID
        final_count = len(self.state_manager.id_states)
        self.assertLess(final_count, initial_count)
    
    def test_force_remove_oldest_id(self):
        """
        测试强制移除最旧ID功能
        
        测试描述:
        验证StateManager在内存压力下能够强制移除最旧的ID状态，
        基于first_seen时间戳确定最旧的ID并安全移除。
        
        详细预期结果:
        1. 应成功移除一个ID状态
        2. 移除的应该是first_seen时间最早的ID
        3. 总ID数量应减少1
        4. 最旧的ID(id_0)应从状态管理器中移除
        5. 其他ID状态应保持完整
        6. 强制移除操作不应抛出异常
        """
        current_time = time.time()
        
        # 添加一些ID，设置不同的首次见到时间
        for i in range(3):
            frame = create_test_frame(f"id_{i}", timestamp=current_time)
            self.state_manager.update_and_get_state(frame)
            # 手动设置first_seen时间
            self.state_manager.id_states[f"id_{i}"]['first_seen'] = current_time - (10 - i)
        
        initial_count = len(self.state_manager.id_states)
        
        # 强制移除最旧的ID
        self.state_manager._force_remove_oldest_id()
        
        # 检查是否移除了一个ID
        final_count = len(self.state_manager.id_states)
        self.assertEqual(final_count, initial_count - 1)
        
        # 检查是否移除了最旧的ID（id_0）
        self.assertNotIn('id_0', self.state_manager.id_states)
    
    def test_limit_payload_hashes(self):
        """
        测试限制载荷哈希数量功能
        
        测试描述:
        验证StateManager能够正确限制每个ID状态中存储的载荷哈希数量，
        防止内存无限增长，保持系统性能稳定。
        
        详细预期结果:
        1. 载荷哈希列表长度应被限制在最大值以内
        2. 超出限制的哈希应被移除
        3. 限制操作应保留最新的哈希值
        4. 限制过程不应影响其他状态数据
        5. 内存使用应得到有效控制
        6. 限制操作不应抛出异常
        """
        frame = create_test_frame(self.can_id)
        state = self.state_manager.update_and_get_state(frame)
        
        # 添加大量载荷哈希
        for i in range(1200):  # 超过限制
            state['payload_hashes'].append(f"hash_{i}")
        
        # 执行限制
        self.state_manager._limit_payload_hashes(state)
        
        # 检查数量是否被限制
        self.assertLessEqual(len(state['payload_hashes']), 
                           self.state_manager.max_payload_hashes_per_id)
    
    def test_limit_sequence_buffer(self):
        """
        测试限制序列缓冲区功能
        
        测试描述:
        验证StateManager能够正确限制每个ID状态中序列缓冲区的大小，
        防止缓冲区无限增长，确保内存使用效率。
        
        详细预期结果:
        1. 序列缓冲区长度应被限制在最大值以内
        2. 超出限制的序列数据应被移除
        3. 限制操作应保留最新的序列数据
        4. 限制过程不应影响其他状态信息
        5. 缓冲区管理应高效执行
        6. 限制操作不应抛出异常
        """
        frame = create_test_frame(self.can_id)
        state = self.state_manager.update_and_get_state(frame)
        
        # 添加大量序列数据
        for i in range(15):  # 超过限制
            state['sequence_buffer'].append(f"seq_{i}")
        
        # 执行限制
        self.state_manager._limit_sequence_buffer(state)
        
        # 检查数量是否被限制
        self.assertLessEqual(len(state['sequence_buffer']), 
                           self.state_manager.max_sequence_length)
    
    def test_get_stats(self):
        """
        测试获取统计信息功能
        
        测试描述:
        验证StateManager能够正确收集和返回系统运行统计信息，
        包括更新次数、活跃ID数量、清理次数等关键指标。
        
        详细预期结果:
        1. 统计信息应正确反映实际操作次数
        2. total_updates应等于实际更新次数(5)
        3. active_ids应等于当前活跃ID数量(5)
        4. 统计信息应包含所有必要字段
        5. 返回的统计数据应为字典格式
        6. 统计信息获取不应抛出异常
        """
        # 添加一些数据
        for i in range(5):
            frame = create_test_frame(f"id_{i}")
            self.state_manager.update_and_get_state(frame)
        
        stats = self.state_manager.get_stats()
        
        # 检查统计信息
        self.assertEqual(stats['total_updates'], 5)
        self.assertEqual(stats['active_ids'], 5)
        self.assertIn('memory_cleanups', stats)
        self.assertIn('states_created', stats)
    
    def test_get_id_state(self):
        """
        测试获取ID状态功能
        
        测试描述:
        验证StateManager能够正确获取指定ID的状态信息，
        对存在的ID返回完整状态，对不存在的ID返回None。
        
        详细预期结果:
        1. 存在的ID应返回非空状态对象
        2. 返回的状态应包含正确的frame_count值
        3. 不存在的ID应返回None
        4. 获取操作不应修改状态数据
        5. 方法应正确处理各种ID格式
        6. 获取过程不应抛出异常
        """
        frame = create_test_frame(self.can_id)
        self.state_manager.update_and_get_state(frame)
        
        # 获取存在的ID状态
        state = self.state_manager.get_id_state(self.can_id)
        self.assertIsNotNone(state)
        self.assertEqual(state['frame_count'], 1)
        
        # 获取不存在的ID状态
        nonexistent_state = self.state_manager.get_id_state("nonexistent")
        self.assertIsNone(nonexistent_state)
    
    def test_remove_id_state(self):
        """
        测试移除ID状态功能
        
        测试描述:
        验证StateManager能够正确移除指定ID的状态信息，
        成功移除存在的ID并正确处理不存在的ID移除请求。
        
        详细预期结果:
        1. 存在的ID应成功移除并返回True
        2. 移除后ID不应存在于状态管理器中
        3. 不存在的ID移除请求应返回False
        4. 移除操作不应影响其他ID状态
        5. 移除过程应完全清理相关数据
        6. 移除操作不应抛出异常
        """
        frame = create_test_frame(self.can_id)
        self.state_manager.update_and_get_state(frame)
        
        # 确认ID存在
        self.assertIn(self.can_id, self.state_manager.id_states)
        
        # 移除ID状态
        removed = self.state_manager.remove_id_state(self.can_id)
        
        # 检查是否成功移除
        self.assertTrue(removed)
        self.assertNotIn(self.can_id, self.state_manager.id_states)
        
        # 尝试移除不存在的ID
        not_removed = self.state_manager.remove_id_state("nonexistent")
        self.assertFalse(not_removed)
    
    def test_clear_all_states(self):
        """
        测试清空所有状态功能
        
        测试描述:
        验证StateManager能够正确清空所有ID状态信息，
        将系统重置到初始状态，释放所有占用的内存。
        
        详细预期结果:
        1. 清空前应确认存在多个ID状态
        2. 清空操作应成功执行
        3. 清空后id_states字典应为空
        4. 所有ID状态数据应被完全清除
        5. 系统应恢复到初始状态
        6. 清空操作不应抛出异常
        """
        # 添加一些数据
        for i in range(5):
            frame = create_test_frame(f"id_{i}")
            self.state_manager.update_and_get_state(frame)
        
        # 确认有数据
        self.assertGreater(len(self.state_manager.id_states), 0)
        
        # 清空所有状态
        self.state_manager.clear_all_states()
        
        # 检查是否清空
        self.assertEqual(len(self.state_manager.id_states), 0)
    
    def test_periodic_cleanup(self):
        """
        测试定期清理功能
        
        测试描述:
        验证StateManager的定期清理机制能够按照设定的时间间隔自动触发，
        在系统运行过程中自动维护内存使用效率。
        
        详细预期结果:
        1. 清理间隔应正确设置为1秒
        2. 超过清理间隔后的更新操作应触发清理
        3. last_cleanup_time应正确更新
        4. 清理机制应自动运行
        5. 定期清理不应影响正常操作
        6. 清理过程应保持系统稳定性
        """
        # 设置较短的清理间隔
        short_interval_manager = StateManager(max_ids=100, cleanup_interval=1)
        
        # 添加数据
        frame = create_test_frame(self.can_id, timestamp=1.0)
        short_interval_manager.update_and_get_state(frame)
        
        # 等待超过清理间隔
        time.sleep(1.1)
        
        # 再次更新，应该触发清理
        frame2 = create_test_frame("id_2", timestamp=time.time())
        short_interval_manager.update_and_get_state(frame2)
        
        # 检查last_cleanup_time是否更新
        self.assertGreater(short_interval_manager.last_cleanup_time, 1.0)
    
    def test_performance_with_large_dataset(self):
        """
        测试大数据集性能功能
        
        测试描述:
        验证StateManager在处理大量CAN帧数据时的性能表现，
        确保系统能够在合理时间内处理大规模数据集。
        
        详细预期结果:
        1. 1000帧数据应在5秒内完成处理
        2. 最终应正确管理50个不同的ID状态
        3. 统计信息应正确反映1000次更新
        4. 处理过程应保持高效率
        5. 大数据集处理不应导致内存泄漏
        6. 性能测试不应抛出异常
        """
        # 创建大量帧
        frames = []
        for i in range(1000):
            frame = create_test_frame(f"id_{i % 50}", timestamp=i * 0.001)  # 50个不同ID，每个20帧
            frames.append(frame)
        
        start_time = time.time()
        
        # 处理所有帧
        for frame in frames:
            self.state_manager.update_and_get_state(frame)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # 检查性能（应该在合理时间内完成）
        self.assertLess(processing_time, 5.0)  # 5秒内完成1000帧处理
        
        # 检查状态数量
        self.assertEqual(len(self.state_manager.id_states), 50)
        
        # 检查统计信息
        self.assertEqual(self.state_manager.stats['total_updates'], 1000)


if __name__ == '__main__':
    # 添加测试总结信息
    import time
    TestOutputHelper.print_file_summary("test_state_manager.py", 1, 17)
    unittest.main(verbosity=2)
"""测试工具模块

提供测试用的辅助函数和数据生成器
"""

import time
from typing import List, Optional
from can_frame import CANFrame


def create_test_frame(can_id: str = "123", 
                     timestamp: Optional[float] = None,
                     dlc: int = 8,
                     payload: Optional[bytes] = None,
                     is_extended_id: bool = False,
                     is_error_frame: bool = False) -> CANFrame:
    """创建测试用CAN帧
    
    Args:
        can_id: CAN ID
        timestamp: 时间戳，如果为None则使用当前时间
        dlc: 数据长度
        payload: 载荷数据，如果为None则生成默认数据
        is_extended_id: 是否为扩展ID
        is_error_frame: 是否为错误帧
        
    Returns:
        CANFrame对象
    """
    if timestamp is None:
        timestamp = time.time()
    
    if payload is None:
        # 生成默认载荷数据
        payload = bytes([i % 256 for i in range(dlc)])
    
    return CANFrame(
        timestamp=timestamp,
        can_id=can_id,
        dlc=dlc,
        payload=payload,
        is_extended_id=is_extended_id,
        is_error_frame=is_error_frame
    )


def create_frame_sequence(can_id: str = "123",
                         count: int = 10,
                         start_time: Optional[float] = None,
                         interval: float = 0.1,
                         dlc: int = 8,
                         payload_pattern: str = "sequential") -> List[CANFrame]:
    """创建CAN帧序列
    
    Args:
        can_id: CAN ID
        count: 帧数量
        start_time: 起始时间戳
        interval: 帧间隔
        dlc: 数据长度
        payload_pattern: 载荷模式 ('sequential', 'random', 'static', 'counter')
        
    Returns:
        CANFrame列表
    """
    if start_time is None:
        start_time = time.time()
    
    frames = []
    for i in range(count):
        timestamp = start_time + i * interval
        
        # 根据模式生成载荷
        if payload_pattern == "sequential":
            payload = bytes([(i + j) % 256 for j in range(dlc)])
        elif payload_pattern == "static":
            payload = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08][:dlc])
        elif payload_pattern == "counter":
            payload = bytes([i % 256] + [0x00] * (dlc - 1))
        elif payload_pattern == "random":
            import random
            payload = bytes([random.randint(0, 255) for _ in range(dlc)])
        else:
            payload = bytes([0x00] * dlc)
        
        frame = CANFrame(
            timestamp=timestamp,
            can_id=can_id,
            dlc=dlc,
            payload=payload
        )
        frames.append(frame)
    
    return frames


def create_drop_attack_frames(can_id: str = "123",
                             normal_count: int = 10,
                             missing_count: int = 3,
                             normal_interval: float = 0.1,
                             attack_interval: float = 0.5) -> List[CANFrame]:
    """创建丢包攻击测试帧序列
    
    Args:
        can_id: CAN ID
        normal_count: 正常帧数量
        missing_count: 丢失帧数量（通过增大间隔模拟）
        normal_interval: 正常间隔
        attack_interval: 攻击时的间隔
        
    Returns:
        包含丢包攻击的帧序列
    """
    frames = []
    start_time = time.time()
    
    # 正常帧
    for i in range(normal_count):
        timestamp = start_time + i * normal_interval
        frame = create_test_frame(can_id, timestamp, payload=bytes([i % 256] * 8))
        frames.append(frame)
    
    # 攻击帧（间隔异常大）
    for i in range(missing_count):
        timestamp = start_time + normal_count * normal_interval + i * attack_interval
        frame = create_test_frame(can_id, timestamp, payload=bytes([(normal_count + i) % 256] * 8))
        frames.append(frame)
    
    return frames


def create_tamper_attack_frames(can_id: str = "123",
                               normal_count: int = 10,
                               tamper_count: int = 5) -> List[CANFrame]:
    """创建篡改攻击测试帧序列
    
    Args:
        can_id: CAN ID
        normal_count: 正常帧数量
        tamper_count: 篡改帧数量
        
    Returns:
        包含篡改攻击的帧序列
    """
    frames = []
    start_time = time.time()
    interval = 0.1
    
    # 正常帧（固定模式）
    normal_payload = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    for i in range(normal_count):
        timestamp = start_time + i * interval
        frame = create_test_frame(can_id, timestamp, payload=normal_payload)
        frames.append(frame)
    
    # 篡改帧（异常DLC和载荷）
    for i in range(tamper_count):
        timestamp = start_time + (normal_count + i) * interval
        
        if i % 2 == 0:
            # DLC异常
            frame = create_test_frame(can_id, timestamp, dlc=4, payload=bytes([0xFF] * 4))
        else:
            # 载荷异常（高熵）
            import random
            random_payload = bytes([random.randint(0, 255) for _ in range(8)])
            frame = create_test_frame(can_id, timestamp, payload=random_payload)
        
        frames.append(frame)
    
    return frames


def create_replay_attack_frames(can_id: str = "123",
                               normal_count: int = 10,
                               replay_count: int = 5) -> List[CANFrame]:
    """创建重放攻击测试帧序列
    
    Args:
        can_id: CAN ID
        normal_count: 正常帧数量
        replay_count: 重放帧数量
        
    Returns:
        包含重放攻击的帧序列
    """
    frames = []
    start_time = time.time()
    interval = 0.1
    
    # 正常帧
    normal_frames = create_frame_sequence(can_id, normal_count, start_time, interval)
    frames.extend(normal_frames)
    
    # 重放攻击（快速重复之前的帧）
    replay_start_time = start_time + normal_count * interval
    for i in range(replay_count):
        # 重放第一帧，但时间间隔很短
        timestamp = replay_start_time + i * 0.001  # 1ms间隔，非常快
        replay_frame = CANFrame(
            timestamp=timestamp,
            can_id=can_id,
            dlc=normal_frames[0].dlc,
            payload=normal_frames[0].payload  # 重复相同载荷
        )
        frames.append(replay_frame)
    
    return frames


def create_unknown_id_frames(unknown_id: str = "999",
                            count: int = 5) -> List[CANFrame]:
    """创建未知ID测试帧
    
    Args:
        unknown_id: 未知的CAN ID
        count: 帧数量
        
    Returns:
        未知ID的帧序列
    """
    return create_frame_sequence(unknown_id, count)
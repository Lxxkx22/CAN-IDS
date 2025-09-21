import re
import logging
import time
from typing import Optional, Iterator
from can_frame import CANFrame

# 配置日志
logger = logging.getLogger(__name__)


class ParseError(Exception):
    """CAN帧解析异常"""
    pass


def parse_line(line: str) -> Optional[CANFrame]:
    """
    解析单行CAN数据

    输入格式示例：
    Timestamp:          0.000271        ID: 0080    000    DLC: 8    00 17 dc 09 16 11 16 bb

    Args:
        line: 包含CAN帧数据的字符串行

    Returns:
        CANFrame对象或None（解析失败时）
    """
    if not line or not line.strip():
        return None
    try:
        # 修改后的正则表达式：支持ATK标识，使数据部分可选，并允许ID后的数字有变化
        pattern = r'Timestamp:\s+([\d.]+)\s+ID:\s+([0-9A-Fa-f]+(?:ATK)?)\s+(\d+)\s+DLC:\s+(\d+)\s*([0-9A-Fa-f\s]*)?$'
        match = re.match(pattern, line.strip())

        if not match:
            logger.warning(f"Failed to parse line format: {line.strip()}")
            return None
        # 提取各字段（group(5)现在是可选的数据部分）
        timestamp_str = match.group(1)
        can_id_str = match.group(2)
        flags = match.group(3)  # 新增：捕获ID后的标志位
        dlc_str = match.group(4)
        payload_str = match.group(5).strip() if match.group(5) else ''
        # 转换数据类型（保持原有逻辑）
        try:
            timestamp = float(timestamp_str)
            dlc = int(dlc_str)
            # 处理ATK标识：分离攻击标识和纯净CAN ID
            is_attack = can_id_str.endswith('ATK')
            clean_can_id = can_id_str.replace('ATK', '') if is_attack else can_id_str
            # 将CAN ID格式化为0x前缀的十六进制格式
            can_id = f"0x{clean_can_id.upper()}"
        except ValueError as e:
            logger.error(f"Invalid format in timestamp/DLC: {e}")
            return None
        payload_bytes = b''
        if payload_str:
            # 移除所有空格后检查长度
            hex_string = re.sub(r'\s+', '', payload_str)
            expected_len = 2 * dlc

            if len(hex_string) != expected_len:
                logger.warning(
                    f"Payload hex length mismatch: expected {expected_len} chars, "
                    f"got {len(hex_string)} in '{payload_str}'"
                )
                return None

            try:
                payload_bytes = bytes.fromhex(hex_string)
            except ValueError as e:
                logger.error(f"Invalid payload hex: {payload_str}, error: {e}")
                return None
        else:
            # 无payload时DLC必须为0
            if dlc != 0:
                logger.warning(f"DLC={dlc} but no payload provided")
                return None
        # 创建CANFrame对象
        return CANFrame(
            timestamp=timestamp,
            can_id=can_id,
            dlc=dlc,
            payload=payload_bytes,
            raw_text=line.strip(),
            is_attack=is_attack
        )
    except Exception as e:
        logger.error(f"Unexpected error parsing line: {e}")
        return None


class DataSource:
    """数据源抽象类"""

    def __init__(self, source_path: str, input_format: str = 'file', real_time: bool = False):
        """
        初始化数据源

        Args:
            source_path: 数据源路径
            input_format: 输入格式 ('file', 'socketcan', 'candump')
            real_time: 是否实时处理
        """
        self.source_path = source_path
        self.input_format = input_format
        self.real_time = real_time
        self.line_count = 0
        self.parsed_count = 0
        self.error_count = 0

    def __iter__(self) -> Iterator[CANFrame]:
        """迭代器接口"""
        if self.input_format == 'file':
            return self._read_from_file()
        elif self.input_format == 'socketcan':
            return self._read_from_socketcan()
        elif self.input_format == 'candump':
            return self._read_from_candump()
        else:
            raise ValueError(f"Unsupported input format: {self.input_format}")

    def _read_from_file(self) -> Iterator[CANFrame]:
        """从文件读取数据"""
        try:
            with open(self.source_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    self.line_count = line_num

                    # 跳过空行和注释行
                    if not line.strip() or line.strip().startswith('#'):
                        continue

                    frame = parse_line(line)
                    if frame:
                        self.parsed_count += 1
                        yield frame
                    else:
                        self.error_count += 1
                        if line.strip():  # 非空行解析失败才记录
                            logger.debug(f"Skipped line {line_num}: {line.strip()}")

        except FileNotFoundError:
            logger.error(f"File not found: {self.source_path}")
            raise
        except IOError as e:
            logger.error(f"Error reading file {self.source_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error reading from file: {e}")
            raise

    def _read_from_socketcan(self) -> Iterator[CANFrame]:
        """从SocketCAN读取数据"""
        try:
            import can
        except ImportError:
            logger.error("python-can library not installed. Please install with: pip install python-can")
            raise ImportError("python-can library is required for SocketCAN support")
        
        logger.info(f"Connecting to SocketCAN interface: {self.source_path}")
        
        try:
            # 创建CAN总线连接
            # 在Windows上，可能需要使用其他接口如'vector', 'pcan'等
            # 这里提供多种接口的尝试
            bus = None
            interfaces_to_try = ['socketcan', 'vector', 'pcan', 'ixxat', 'kvaser']
            
            for interface in interfaces_to_try:
                try:
                    if interface == 'socketcan':
                        # Linux SocketCAN
                        bus = can.interface.Bus(channel=self.source_path, bustype='socketcan')
                    elif interface == 'vector':
                        # Vector CANoe/CANalyzer
                        bus = can.interface.Bus(channel=self.source_path, bustype='vector')
                    elif interface == 'pcan':
                        # PEAK CAN
                        bus = can.interface.Bus(channel=self.source_path, bustype='pcan')
                    elif interface == 'ixxat':
                        # IXXAT CAN
                        bus = can.interface.Bus(channel=self.source_path, bustype='ixxat')
                    elif interface == 'kvaser':
                        # Kvaser CAN
                        bus = can.interface.Bus(channel=self.source_path, bustype='kvaser')
                    
                    if bus:
                        logger.info(f"Successfully connected using {interface} interface")
                        break
                        
                except Exception as e:
                    logger.debug(f"Failed to connect with {interface}: {e}")
                    continue
            
            if not bus:
                raise RuntimeError(f"Failed to connect to CAN interface {self.source_path} with any available driver")
            
            logger.info("Starting real-time CAN data reception...")
            
            while True:
                try:
                    # 接收CAN消息，设置超时避免阻塞
                    message = bus.recv(timeout=1.0)
                    if message is None:
                        continue
                    
                    # 转换为CANFrame格式
                    frame = CANFrame(
                        timestamp=message.timestamp if message.timestamp else time.time(),
                        can_id=f"{message.arbitration_id:X}".upper(),
                        dlc=message.dlc if hasattr(message, 'dlc') else len(message.data),
                        payload=bytes(message.data) if message.data else b'',
                        is_extended_id=message.is_extended_id,
                        is_error_frame=message.is_error_frame if hasattr(message, 'is_error_frame') else False
                    )
                    
                    # 设置raw_text用于兼容现有格式
                    payload_hex = ' '.join(f'{b:02x}' for b in frame.payload)
                    frame.raw_text = f"Timestamp: {frame.timestamp:12.6f}        ID: {frame.can_id}    000    DLC: {frame.dlc}    {payload_hex}"
                    
                    self.parsed_count += 1
                    yield frame
                    
                    # 实时模式下添加小延迟，避免CPU占用过高
                    if self.real_time:
                        time.sleep(0.001)  # 1ms延迟
                        
                except can.CanError as e:
                    logger.warning(f"CAN error: {e}")
                    self.error_count += 1
                    continue
                except KeyboardInterrupt:
                    logger.info("SocketCAN reception interrupted by user")
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in SocketCAN reception: {e}")
                    self.error_count += 1
                    continue
                    
        except Exception as e:
            logger.error(f"SocketCAN connection error: {e}")
            raise
        finally:
            if 'bus' in locals() and bus:
                try:
                    bus.shutdown()
                    logger.info("SocketCAN connection closed")
                except:
                    pass

    def _read_from_candump(self) -> Iterator[CANFrame]:
        """从candump格式读取数据"""
        # 占位实现 - candump格式可能不同于当前格式
        logger.warning("candump format input not implemented yet")
        raise NotImplementedError("candump input format not implemented")

    def get_statistics(self) -> dict:
        """获取解析统计信息"""
        return {
            'total_lines': self.line_count,
            'parsed_frames': self.parsed_count,
            'parse_errors': self.error_count,
            'success_rate': self.parsed_count / max(self.line_count, 1) * 100
        }


def validate_frame(frame: CANFrame) -> bool:
    """
    验证CAN帧的有效性

    Args:
        frame: 要验证的CAN帧

    Returns:
        True如果帧有效，False否则
    """
    try:
        # 检查基本字段
        if frame.timestamp < 0:
            logger.warning(f"Invalid timestamp: {frame.timestamp}")
            return False

        if not frame.can_id:
            logger.warning("Empty CAN ID")
            return False

        if frame.dlc < 0 or frame.dlc > 8:
            logger.warning(f"Invalid DLC: {frame.dlc}")
            return False

        if len(frame.payload) != frame.dlc:
            logger.warning(f"Payload length {len(frame.payload)} does not match DLC {frame.dlc}")
            return False

        # 检查CAN ID格式（假设为十六进制）
        try:
            int(frame.can_id, 16)
        except ValueError:
            logger.warning(f"Invalid CAN ID format: {frame.can_id}")
            return False

        return True

    except Exception as e:
        logger.error(f"Error validating frame: {e}")
        return False


# 测试用的辅助函数
def test_parser_with_sample_data():
    """使用示例数据测试解析器"""
    sample_lines = [
        "Timestamp:          0.000271        ID: 0080    000    DLC: 8    00 17 dc 09 16 11 16 bb",
        "Timestamp:          0.000495        ID: 0000    000    DLC: 8    00 00 00 00 00 00 00 00",
        "Timestamp:          0.000736        ID: 0081    000    DLC: 8    40 84 87 00 00 00 00 6b",
        "Timestamp:          0.000983        ID: 0000    000    DLC: 8    00 00 00 00 00 00 00 00",
        "Timestamp:          0.001239        ID: 0165    000    DLC: 8    00 08 80 00 00 00 08 80"
    ]

    parsed_frames = []
    for line in sample_lines:
        frame = parse_line(line)
        if frame:
            parsed_frames.append(frame)
            print(f"Parsed: {frame}")
        else:
            print(f"Failed to parse: {line}")

    return parsed_frames


if __name__ == "__main__":
    # 简单测试
    logging.basicConfig(level=logging.DEBUG)
    test_parser_with_sample_data()
import math
import statistics
import hashlib
import xxhash
from collections import Counter
from typing import List, Dict, Any, Union


def calculate_entropy(data: bytes) -> float:
    """
    计算Shannon熵

    Args:
        data: 字节数据

    Returns:
        熵值 (0-8 bits)，8表示完全随机
    """
    if not data:
        return 0.0

    # 统计字节频率
    byte_counts = Counter(data)
    data_len = len(data)

    # 计算熵
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def hash_payload(data: bytes) -> str:
    """
    计算载荷哈希值

    Args:
        data: 字节数据

    Returns:
        哈希字符串
    """
    if not data:
        return hashlib.md5(b'').hexdigest()

    # 使用xxhash提供更好的性能
    try:
        return xxhash.xxh64(data).hexdigest()
    except ImportError:
        # 如果xxhash不可用，回退到MD5
        return hashlib.md5(data).hexdigest()


def fast_hash_payload(data: bytes) -> int:
    """
    快速载荷哈希（返回整数）

    Args:
        data: 字节数据

    Returns:
        哈希整数值
    """
    if not data:
        return 0

    try:
        return xxhash.xxh64_intdigest(data)
    except ImportError:
        # 回退到简单的哈希算法
        hash_val = 0
        for byte in data:
            hash_val = ((hash_val << 5) + hash_val) + byte
            hash_val &= 0xFFFFFFFFFFFFFFFF  # 保持64位
        return hash_val


def calculate_stats(data_list: List[float]) -> Dict[str, float]:
    """
    安全地计算统计数据

    Args:
        data_list: 数值列表

    Returns:
        统计数据字典
    """
    if not data_list:
        return {
            'mean': 0.0,
            'std': 0.0,
            'median': 0.0,
            'min': 0.0,
            'max': 0.0,
            'count': 0
        }

    if len(data_list) == 1:
        value = float(data_list[0])
        return {
            'mean': value,
            'std': 0.0,
            'median': value,
            'min': value,
            'max': value,
            'count': 1
        }

    try:
        mean_val = statistics.mean(data_list)
        std_val = statistics.stdev(data_list) if len(data_list) > 1 else 0.0
        median_val = statistics.median(data_list)
        min_val = min(data_list)
        max_val = max(data_list)

        return {
            'mean': float(mean_val),
            'std': float(std_val),
            'median': float(median_val),
            'min': float(min_val),
            'max': float(max_val),
            'count': len(data_list)
        }

    except (statistics.StatisticsError, ValueError) as e:
        # 处理统计计算错误
        return {
            'mean': 0.0,
            'std': 0.0,
            'median': 0.0,
            'min': 0.0,
            'max': 0.0,
            'count': len(data_list),
            'error': str(e)
        }


def is_entropy_anomaly(current_entropy: float, learned_mean: float,
                       learned_stddev: float, sigma_threshold: float) -> bool:
    """
    检测熵异常

    Args:
        current_entropy: 当前熵值
        learned_mean: 学习的平均熵
        learned_stddev: 学习的熵标准差
        sigma_threshold: Sigma阈值

    Returns:
        True如果检测到异常
    """
    if learned_stddev == 0:
        return current_entropy != learned_mean

    deviation = abs(current_entropy - learned_mean)
    threshold = sigma_threshold * learned_stddev

    return deviation > threshold


def calculate_byte_difference_ratio(payload1: bytes, payload2: bytes) -> float:
    """
    计算两个载荷的字节差异比例

    Args:
        payload1: 载荷1
        payload2: 载荷2

    Returns:
        差异比例 (0.0-1.0)
    """
    if not payload1 and not payload2:
        return 0.0

    if len(payload1) != len(payload2):
        return 1.0  # 长度不同视为完全不同

    if not payload1:  # 两个都为空
        return 0.0

    different_bytes = sum(1 for b1, b2 in zip(payload1, payload2) if b1 != b2)
    return different_bytes / len(payload1)


def normalize_can_id(can_id: Union[str, int]) -> str:
    """
    标准化CAN ID格式

    Args:
        can_id: CAN ID（字符串或整数）

    Returns:
        标准化的CAN ID字符串（大写十六进制）
    """
    if isinstance(can_id, int):
        return f"{can_id:X}"
    elif isinstance(can_id, str):
        # 移除可能的前缀和空格
        clean_id = can_id.strip().upper()
        if clean_id.startswith('0X'):
            clean_id = clean_id[2:]

        # 验证是否为有效的十六进制
        try:
            int(clean_id, 16)
            return clean_id
        except ValueError:
            raise ValueError(f"Invalid CAN ID format: {can_id}")
    else:
        raise TypeError(f"CAN ID must be string or int, got {type(can_id)}")


def format_payload_hex(payload: bytes, separator: str = ' ', uppercase: bool = True) -> str:
    """
    格式化载荷为十六进制字符串

    Args:
        payload: 载荷字节
        separator: 字节间分隔符
        uppercase: 是否使用大写

    Returns:
        格式化的十六进制字符串
    """
    if not payload:
        return ''

    hex_str = payload.hex()
    if uppercase:
        hex_str = hex_str.upper()

    if separator:
        # 每两个字符（一个字节）插入分隔符
        formatted = separator.join(hex_str[i:i + 2] for i in range(0, len(hex_str), 2))
        return formatted

    return hex_str


def parse_hex_string(hex_str: str) -> bytes:
    """
    解析十六进制字符串为字节

    Args:
        hex_str: 十六进制字符串

    Returns:
        字节数据
    """
    if not hex_str:
        return b''

    # 清理字符串
    clean_str = hex_str.replace(' ', '').replace(':', '').replace('-', '')
    clean_str = clean_str.strip()

    if not clean_str:
        return b''

    # 确保长度为偶数
    if len(clean_str) % 2 != 0:
        clean_str = '0' + clean_str

    try:
        return bytes.fromhex(clean_str)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {hex_str}, error: {e}")


def rolling_average(values: List[float], window_size: int) -> List[float]:
    """
    计算滚动平均值

    Args:
        values: 数值列表
        window_size: 窗口大小

    Returns:
        滚动平均值列表
    """
    if not values or window_size <= 0:
        return []

    if window_size >= len(values):
        return [statistics.mean(values)] * len(values)

    rolling_avg = []
    for i in range(len(values)):
        start_idx = max(0, i - window_size + 1)
        window = values[start_idx:i + 1]
        rolling_avg.append(statistics.mean(window))

    return rolling_avg


def detect_outliers_iqr(data: List[float], factor: float = 1.5) -> List[bool]:
    """
    使用IQR方法检测异常值

    Args:
        data: 数据列表
        factor: IQR倍数因子

    Returns:
        布尔列表，True表示异常值
    """
    if len(data) < 4:
        return [False] * len(data)

    try:
        q1 = statistics.quantiles(data, n=4)[0]  # 25th percentile
        q3 = statistics.quantiles(data, n=4)[2]  # 75th percentile
        iqr = q3 - q1

        lower_bound = q1 - factor * iqr
        upper_bound = q3 + factor * iqr

        return [x < lower_bound or x > upper_bound for x in data]

    except statistics.StatisticsError:
        return [False] * len(data)


def memory_efficient_counter(items: List[Any], max_items: int = 1000) -> Counter:
    """
    内存效率的计数器，限制最大项目数

    Args:
        items: 要计数的项目列表
        max_items: 最大项目数

    Returns:
        Counter对象
    """
    counter = Counter(items)

    if len(counter) <= max_items:
        return counter

    # 保留最常见的项目
    most_common = counter.most_common(max_items)
    return Counter(dict(most_common))


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """
    安全除法，避免除零错误

    Args:
        numerator: 分子
        denominator: 分母
        default: 默认值（当分母为0时）

    Returns:
        除法结果或默认值
    """
    if denominator == 0:
        return default
    return numerator / denominator


def clamp(value: float, min_val: float, max_val: float) -> float:
    """
    将值限制在指定范围内

    Args:
        value: 输入值
        min_val: 最小值
        max_val: 最大值

    Returns:
        限制后的值
    """
    return max(min_val, min(value, max_val))


def format_duration(seconds: float) -> str:
    """
    格式化持续时间为可读字符串

    Args:
        seconds: 秒数

    Returns:
        格式化的持续时间字符串
    """
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}min"
    else:
        return f"{seconds / 3600:.1f}h"


def format_byte_size(bytes_count: int) -> str:
    """
    格式化字节大小为可读字符串

    Args:
        bytes_count: 字节数

    Returns:
        格式化的大小字符串
    """
    units = ['B', 'KB', 'MB', 'GB']
    size = float(bytes_count)
    unit_index = 0

    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1

    return f"{size:.2f}{units[unit_index]}"


# 异常处理装饰器
def safe_execute(default_return=None, log_errors=True):
    """
    安全执行装饰器，捕获异常并返回默认值

    Args:
        default_return: 发生异常时的默认返回值
        log_errors: 是否记录错误日志
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if log_errors:
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.error(f"Error in {func.__name__}: {e}")
                return default_return

        return wrapper

    return decorator
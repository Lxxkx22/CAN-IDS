from dataclasses import dataclass
from typing import Optional
import hashlib


@dataclass
class CANFrame:
    """CAN帧数据结构"""
    timestamp: float
    can_id: str
    dlc: int
    payload: bytes
    raw_text: Optional[str] = None
    is_extended_id: Optional[bool] = False
    is_error_frame: Optional[bool] = False
    is_attack: Optional[bool] = False

    def get_payload_hash(self) -> str:
        """获取载荷哈希值"""
        if not self.payload:
            return hashlib.md5(b'').hexdigest()
        return hashlib.md5(self.payload).hexdigest()

    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            'timestamp': self.timestamp,
            'can_id': self.can_id,
            'dlc': self.dlc,
            'payload': self.payload.hex().upper() if self.payload else '',
            'payload_hash': self.get_payload_hash(),
            'raw_text': self.raw_text,
            'is_extended_id': self.is_extended_id,
            'is_error_frame': self.is_error_frame,
            'is_attack': self.is_attack
        }

    def __str__(self) -> str:
        """字符串表示 - 符合指定的CAN数据帧格式"""
        # 格式化载荷数据为空格分隔的十六进制字节
        if self.payload:
            payload_hex = ' '.join(f'{b:02x}' for b in self.payload)
        else:
            payload_hex = ''
        
        # 格式化CAN ID为4位十六进制（不带0x前缀）
        formatted_id = f"{int(self.can_id, 16):04x}" if self.can_id.isdigit() or all(c in '0123456789abcdefABCDEF' for c in self.can_id) else self.can_id
        
        # 返回指定格式：Timestamp: 时间戳 ID: CAN_ID 000 DLC: 数据长度 载荷数据
        return f"Timestamp: {self.timestamp:15.6f}        ID: {formatted_id}    000    DLC: {self.dlc}    {payload_hex}"
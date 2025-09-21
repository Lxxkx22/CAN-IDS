def parse_line(line: str) -> Optional[CANFrame]:
        """
        解析单行CAN数据
        """
        if not line or not line.strip():
            return None
        try:
            # 兼容ATK标识、可选载荷的正则表达式
            pattern = r'Timestamp:\s+([\d.]+)\s+ID:\s+([0-9A-Fa-f]+(?:ATK)?)\s+(\d+)\s+DLC:\s+(\d+)\s*([0-9A-Fa-f\s]*)?$'
            match = re.match(pattern, line.strip())

            if not match:
                logger.warning(f"Failed to parse line format: {line.strip()}")
                return None
            
            # 提取各字段
            timestamp_str, can_id_str, _, dlc_str, payload_str = match.groups()
            payload_str = payload_str.strip() if payload_str else ''

            # 类型转换与攻击标识处理
            timestamp = float(timestamp_str)
            dlc = int(dlc_str)
            is_attack = can_id_str.endswith('ATK')
            clean_can_id = can_id_str.replace('ATK', '') if is_attack else can_id_str
            can_id = f"0x{clean_can_id.upper()}"
            
            # 载荷处理
            payload_bytes = bytes.fromhex(re.sub(r'\s+', '', payload_str)) if payload_str else b''

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

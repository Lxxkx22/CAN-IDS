#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAN数据分析器 - 高性能版本
用于分析CAN数据帧并生成IDS配置文件
支持处理超过200万条数据记录
"""

import re
import json
import time
import math
import hashlib
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import statistics
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import gc

class CANDataAnalyzer:
    def __init__(self, input_file: str, config_file: str):
        self.input_file = input_file
        self.config_file = config_file
        self.frame_data = defaultdict(list)  # {can_id: [frames]}
        self.timing_data = defaultdict(list)  # {can_id: [timestamps]}
        self.payload_data = defaultdict(list)  # {can_id: [payloads]}
        self.dlc_data = defaultdict(list)  # {can_id: [dlcs]}
        self.total_frames = 0
        self.unique_ids = set()
        self.analysis_start_time = None
        self.first_timestamp = None
        self.last_timestamp = None
        
        # 性能优化参数
        self.batch_size = 50000  # 批处理大小
        self.gc_interval = 100000  # 垃圾回收间隔
        
    def parse_can_frame(self, line: str) -> Optional[Tuple[float, str, int, List[int]]]:
        """解析CAN帧数据"""
        # 正则表达式匹配CAN帧格式
        pattern = r'Timestamp:\s+(\d+\.\d+)\s+ID:\s+([0-9A-Fa-f]+)\s+\d+\s+DLC:\s+(\d+)(?:\s+([0-9A-Fa-f\s]+))?'
        match = re.match(pattern, line.strip())
        
        if not match:
            return None
            
        timestamp = float(match.group(1))
        can_id = match.group(2).upper()
        dlc = int(match.group(3))
        
        payload = []
        if match.group(4) and dlc > 0:
            payload_str = match.group(4).strip()
            if payload_str:
                payload = [int(x, 16) for x in payload_str.split()]
                
        return timestamp, can_id, dlc, payload
    
    def calculate_entropy(self, payload: List[int]) -> float:
        """计算载荷熵值"""
        if not payload:
            return 0.0
            
        # 计算字节频率
        byte_counts = Counter(payload)
        total_bytes = len(payload)
        
        # 计算熵
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / total_bytes
            if probability > 0:
                entropy -= probability * math.log2(probability)
                
        return entropy
    
    def analyze_byte_behavior(self, payloads: List[List[int]], max_dlc: int) -> List[Dict]:
        """分析字节行为模式"""
        if not payloads or max_dlc == 0:
            return []
            
        byte_profiles = []
        
        for pos in range(max_dlc):
            byte_values = []
            for payload in payloads:
                if len(payload) > pos:
                    byte_values.append(payload[pos])
                    
            if not byte_values:
                continue
                
            value_counts = Counter(byte_values)
            unique_values = len(value_counts)
            most_common_value = value_counts.most_common(1)[0][0]
            
            # 判断字节类型
            byte_type = "static"
            if unique_values > 1:
                if unique_values <= 10:
                    byte_type = "limited_values"
                elif self._is_counter_pattern(byte_values):
                    byte_type = "counter"
                else:
                    byte_type = "variable"
                    
            # 只保留前10个最常见的值以节省空间
            top_values = dict(value_counts.most_common(10))
            
            profile = {
                "position": pos,
                "type": byte_type,
                "unique_values": unique_values,
                "most_common_value": most_common_value,
                "value_distribution": top_values
            }
            
            byte_profiles.append(profile)
            
        return byte_profiles
    
    def _is_counter_pattern(self, values: List[int]) -> bool:
        """检测是否为计数器模式"""
        if len(values) < 10:
            return False
            
        # 检查连续递增模式
        consecutive_increases = 0
        for i in range(1, min(100, len(values))):
            if values[i] == (values[i-1] + 1) % 256:
                consecutive_increases += 1
            elif consecutive_increases > 0:
                break
                
        return consecutive_increases >= 5
    
    def calculate_iat_statistics(self, timestamps: List[float]) -> Tuple[float, float]:
        """计算帧间间隔统计"""
        if len(timestamps) < 2:
            return 0.0, 0.0
            
        # 计算帧间间隔（毫秒）
        iats = []
        for i in range(1, len(timestamps)):
            iat = (timestamps[i] - timestamps[i-1]) * 1000  # 转换为毫秒
            iats.append(iat)
            
        if not iats:
            return 0.0, 0.0
            
        mean_iat = statistics.mean(iats)
        std_iat = statistics.stdev(iats) if len(iats) > 1 else 0.0
        
        return mean_iat, std_iat
    
    def analyze_periodicity(self, timestamps: List[float]) -> Dict[str, Any]:
        """分析真实的周期性模式"""
        if len(timestamps) < 10:
            return {
                "dominant_periods": [10.0, 20.0],
                "periodicity_score": 0.0,
                "is_periodic": False,
                "expected_iat_variance": 0.5
            }
            
        # 计算帧间间隔（秒）
        iats = []
        for i in range(1, len(timestamps)):
            iat = timestamps[i] - timestamps[i-1]
            if iat > 0:  # 过滤掉重复时间戳
                iats.append(iat)
                
        if len(iats) < 5:
            return {
                "dominant_periods": [10.0, 20.0],
                "periodicity_score": 0.0,
                "is_periodic": False,
                "expected_iat_variance": 0.5
            }
            
        # 统计IAT分布
        iat_counts = Counter([round(iat, 6) for iat in iats])
        total_iats = len(iats)
        
        # 找出最常见的IAT值作为主要周期
        most_common_iats = iat_counts.most_common(3)
        dominant_periods = []
        
        for iat_value, count in most_common_iats:
            if count >= 3:  # 至少出现3次才认为是有效周期
                dominant_periods.append(iat_value)
                
        # 如果没有找到明显的周期，使用统计值
        if not dominant_periods:
            mean_iat = statistics.mean(iats)
            dominant_periods = [mean_iat, mean_iat * 2]
            
        # 计算周期性得分
        if dominant_periods:
            main_period = dominant_periods[0]
            main_period_count = iat_counts.get(round(main_period, 6), 0)
            periodicity_score = min(main_period_count / total_iats, 0.95)
        else:
            periodicity_score = 0.0
            
        # 判断是否为周期性
        is_periodic = periodicity_score > 0.3
        
        # 计算期望的IAT方差
        if len(iats) > 1:
            iat_std = statistics.stdev(iats)
            iat_mean = statistics.mean(iats)
            expected_iat_variance = round(iat_std / iat_mean, 3) if iat_mean > 0 else 0.5
        else:
            expected_iat_variance = 0.5
            
        return {
            "dominant_periods": dominant_periods[:2],  # 最多保留2个主要周期
            "periodicity_score": round(periodicity_score, 3),
            "is_periodic": is_periodic,
            "expected_iat_variance": expected_iat_variance
        }
    
    def analyze_payload_patterns(self, payloads: List[List[int]]) -> List[str]:
        """分析载荷模式"""
        if len(payloads) < 10:
            return []
            
        # 将载荷转换为十六进制字符串
        hex_payloads = []
        for payload in payloads[:1000]:  # 限制分析数量以提高性能
            if payload:
                hex_str = ''.join(f'{b:02X}' for b in payload)
                hex_payloads.append(hex_str)
                
        # 找出最常见的模式
        pattern_counts = Counter(hex_payloads)
        common_patterns = [pattern for pattern, count in pattern_counts.most_common(5) if count >= 3]
        
        return common_patterns
    
    def process_file_in_batches(self):
        """批量处理文件以优化内存使用"""
        print(f"开始分析文件: {self.input_file}")
        self.analysis_start_time = time.time()
        
        batch_count = 0
        current_batch = []
        
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if line.strip():
                        current_batch.append(line)
                        
                    # 批处理
                    if len(current_batch) >= self.batch_size:
                        self._process_batch(current_batch)
                        current_batch = []
                        batch_count += 1
                        
                        # 定期垃圾回收
                        if line_num % self.gc_interval == 0:
                            gc.collect()
                            print(f"已处理 {line_num} 行数据...")
                            
                # 处理最后一批
                if current_batch:
                    self._process_batch(current_batch)
                    
        except FileNotFoundError:
            print(f"错误: 找不到文件 {self.input_file}")
            return False
        except Exception as e:
            print(f"处理文件时出错: {e}")
            return False
            
        print(f"文件处理完成，共处理 {self.total_frames} 帧数据")
        return True
    
    def _process_batch(self, batch: List[str]):
        """处理一批数据"""
        for line in batch:
            frame_data = self.parse_can_frame(line)
            if frame_data:
                timestamp, can_id, dlc, payload = frame_data
                
                # 记录第一个和最后一个时间戳
                if self.first_timestamp is None:
                    self.first_timestamp = timestamp
                self.last_timestamp = timestamp
                
                # 存储数据
                self.frame_data[can_id].append((timestamp, dlc, payload))
                self.timing_data[can_id].append(timestamp)
                self.payload_data[can_id].append(payload)
                self.dlc_data[can_id].append(dlc)
                
                self.unique_ids.add(can_id)
                self.total_frames += 1
    
    def generate_id_config(self, can_id: str) -> Dict[str, Any]:
        """为特定CAN ID生成配置"""
        frames = self.frame_data[can_id]
        timestamps = self.timing_data[can_id]
        payloads = self.payload_data[can_id]
        dlcs = self.dlc_data[can_id]
        
        if not frames:
            return {}
            
        frame_count = len(frames)
        
        # 计算IAT统计
        mean_iat, std_iat = self.calculate_iat_statistics(timestamps)
        
        # 分析真实的周期性模式
        periodicity_analysis = self.analyze_periodicity(timestamps)
        
        # 分析DLC
        unique_dlcs = list(set(dlcs))
        max_dlc = max(dlcs) if dlcs else 0
        
        # 分析字节行为
        byte_profiles = self.analyze_byte_behavior(payloads, max_dlc)
        
        # 计算熵基线
        entropies = [self.calculate_entropy(payload) for payload in payloads if payload]
        entropy_baseline = None
        if entropies:
            entropy_baseline = {
                "mean": statistics.mean(entropies),
                "std": statistics.stdev(entropies) if len(entropies) > 1 else 0.0,
                "samples": len(entropies)
            }
        
        # 分析载荷模式
        payload_patterns = self.analyze_payload_patterns(payloads)
        
        # 计算频率
        if len(timestamps) > 1:
            duration = timestamps[-1] - timestamps[0]
            frequency_hz = (frame_count - 1) / duration if duration > 0 else 0
        else:
            frequency_hz = 0
            
        # 生成配置
        config = {
            "description": f"CAN ID {can_id} - Auto-generated from data analysis",
            "enabled": True,
            "priority": "normal",
            "drop": {
                "learned_mean_iat": round(mean_iat, 3) if mean_iat > 0 else None,
                "learned_std_iat": round(std_iat, 3) if std_iat > 0 else None,
                "frame_count": frame_count,
                "custom_threshold_sigma": None,
                "min_iat_ms": round(min(mean_iat - 3*std_iat, 1.0), 3) if mean_iat > 0 else None,
                "max_iat_ms": round(mean_iat + 3*std_iat, 3) if mean_iat > 0 else None
            },
            "tamper": {
                "learned_dlcs": unique_dlcs,
                "byte_behavior_profiles": byte_profiles,
                "entropy_baseline": entropy_baseline,
                "payload_patterns": payload_patterns,
                "custom_rules": []
            },
            "replay": {
                "sequence_history": [],
                "timing_patterns": [],
                "custom_detection_rules": [],
                "identical_payload_params": {
                    "enabled": True,
                    "time_window_sec": 1.0,
                    "min_repetitions": 3,
                    "max_allowed_iat_variance": 0.1
                },
                "sequence_replay_params": {
                    "enabled": True,
                    "sequence_length": 3,
                    "time_window_sec": 2.0,
                    "min_confidence": 0.8
                },
                "periodicity_baseline": {
                    "dominant_periods": periodicity_analysis["dominant_periods"],
                    "periodicity_score": periodicity_analysis["periodicity_score"],
                    "expected_iat_variance": periodicity_analysis["expected_iat_variance"],
                    "payload_patterns": {
                        "common_sequences": payload_patterns[:3],
                        "pattern_frequencies": {pattern: 0.3 for pattern in payload_patterns[:3]}
                    },
                    "is_periodic": periodicity_analysis["is_periodic"],
                    "period_tolerance": 0.05
                }
            },
            "metadata": {
                "description": f"Auto-analyzed CAN ID {can_id}",
                "ecu_name": "",
                "signal_names": [],
                "expected_frequency_hz": round(frequency_hz, 3) if frequency_hz > 0 else None,
                "critical_system": False
            }
        }
        
        return config
    
    def update_config_file(self):
        """更新配置文件"""
        print("正在生成配置文件...")
        
        try:
            # 读取现有配置
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except FileNotFoundError:
            print(f"错误: 找不到配置文件 {self.config_file}")
            return False
        except json.JSONDecodeError as e:
            print(f"错误: 配置文件JSON格式错误 - {e}")
            return False
            
        # 更新元数据
        analysis_duration = time.time() - self.analysis_start_time
        total_duration = self.last_timestamp - self.first_timestamp if self.first_timestamp and self.last_timestamp else 0
        
        config["meta"]["analysis_info"] = {
            "total_frames": self.total_frames,
            "unique_ids": len(self.unique_ids),
            "analysis_duration_sec": round(analysis_duration, 3),
            "data_duration_sec": round(total_duration, 3),
            "data_source": self.input_file,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        # 清空现有的ID配置（保留模板）
        template = config["ids"].get("_template", {})
        config["ids"] = {"_template": template}
        
        # 为每个CAN ID生成配置
        print(f"正在为 {len(self.unique_ids)} 个CAN ID生成配置...")
        
        for can_id in sorted(self.unique_ids):
            hex_id = f"0x{can_id}"
            id_config = self.generate_id_config(can_id)
            if id_config:
                config["ids"][hex_id] = id_config
                
        # 保存配置文件
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            print(f"配置文件已更新: {self.config_file}")
            return True
        except Exception as e:
            print(f"保存配置文件时出错: {e}")
            return False
    
    def analyze(self):
        """执行完整分析"""
        print("=== CAN数据分析器 ===")
        print(f"输入文件: {self.input_file}")
        print(f"配置文件: {self.config_file}")
        
        # 处理数据文件
        if not self.process_file_in_batches():
            return False
            
        # 更新配置文件
        if not self.update_config_file():
            return False
            
        # 输出统计信息
        analysis_duration = time.time() - self.analysis_start_time
        print(f"\n=== 分析完成 ===")
        print(f"总帧数: {self.total_frames:,}")
        print(f"唯一CAN ID数: {len(self.unique_ids)}")
        print(f"分析耗时: {analysis_duration:.2f} 秒")
        print(f"处理速度: {self.total_frames/analysis_duration:,.0f} 帧/秒")
        
        return True

def main():
    """主函数"""
    input_file = r"/data/Attack_free_dataset.txt"
    config_file = r"../config/config.json"
    
    analyzer = CANDataAnalyzer(input_file, config_file)
    success = analyzer.analyze()
    
    if success:
        print("\n数据分析和配置生成成功完成！")
    else:
        print("\n数据分析过程中出现错误！")
        
if __name__ == "__main__":
    main()
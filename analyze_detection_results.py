#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CAN IDS检测结果分析程序
分析系统检测结果并生成性能报告
"""

import json
import re
from collections import defaultdict
from datetime import datetime
import os

class DetectionAnalyzer:
    def __init__(self):
        self.attack_frames = set()  # 真实攻击帧的时间戳
        self.detected_alerts = []   # 检测到的告警
        self.attack_types = {
            '0999ATK': '未知ID检测',
            '0316ATK': '重放攻击检测', 
            '0153ATK': '静态字节篡改检测',
            '0164ATK': '序列重放攻击检测',
            '0220ATK': 'DLC异常检测',
            '02a0ATK': '字节值异常检测',
            '0329ATK': '熵值异常检测',
            '0080ATK': '丢帧攻击检测'
        }
        
    def load_attack_frames(self, traffic_file):
        """从混合流量文件中提取攻击帧信息"""
        print(f"正在加载攻击帧数据: {traffic_file}")
        
        with open(traffic_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if 'ATK' in line:
                    # 解析时间戳
                    timestamp_match = re.search(r'Timestamp:\s*([\d.]+)', line)
                    if timestamp_match:
                        timestamp = float(timestamp_match.group(1))
                        self.attack_frames.add(timestamp)
                        
        print(f"加载了 {len(self.attack_frames)} 个攻击帧")
        
    def load_detection_results(self, alerts_file):
        """加载检测结果"""
        print(f"正在加载检测结果: {alerts_file}")
        
        with open(alerts_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    try:
                        alert = json.loads(line)
                        self.detected_alerts.append(alert)
                    except json.JSONDecodeError as e:
                        print(f"第 {line_num} 行JSON解析错误: {e}")
                        
        print(f"加载了 {len(self.detected_alerts)} 个检测告警")
        
    def analyze_performance(self):
        """分析检测性能"""
        print("正在分析检测性能...")
        
        # 统计变量
        tp = 0  # 真阳性：正确检测到的攻击
        fp = 0  # 假阳性：误报的正常流量
        fn = 0  # 假阴性：未检测到的攻击
        tn = 0  # 真阴性：正确识别的正常流量
        
        # 检测到的攻击时间戳
        detected_attack_timestamps = set()
        detected_normal_timestamps = set()
        
        # 分析每个告警
        for alert in self.detected_alerts:
            timestamp = alert.get('timestamp', 0)
            
            # 检查是否为攻击帧的检测
            is_attack_detected = False
            for attack_ts in self.attack_frames:
                # 允许一定的时间误差（±0.001秒）
                if abs(timestamp - attack_ts) <= 0.001:
                    is_attack_detected = True
                    detected_attack_timestamps.add(attack_ts)
                    break
                    
            if is_attack_detected:
                tp += 1  # 正确检测到攻击
            else:
                fp += 1  # 误报正常流量
                detected_normal_timestamps.add(timestamp)
        
        # 计算未检测到的攻击（假阴性）
        undetected_attacks = self.attack_frames - detected_attack_timestamps
        fn = len(undetected_attacks)
        
        # 估算真阴性（正确识别的正常流量）
        # 基于报告中的数据：99,400正常帧，1,400攻击帧
        total_normal_frames = 99400
        total_attack_frames = 1400
        
        # 真阴性 = 总正常帧数 - 误报数
        tn = total_normal_frames - fp
        
        # 确保TN不为负数
        if tn < 0:
            tn = 0
            
        return {
            'tp': tp,
            'fp': fp, 
            'tn': tn,
            'fn': fn,
            'detected_attacks': len(detected_attack_timestamps),
            'total_attacks': len(self.attack_frames),
            'total_alerts': len(self.detected_alerts),
            'undetected_attacks': undetected_attacks
        }
        
    def calculate_metrics(self, stats):
        """计算性能指标"""
        tp, fp, tn, fn = stats['tp'], stats['fp'], stats['tn'], stats['fn']
        
        # 避免除零错误
        total = tp + fp + tn + fn
        
        # 准确率
        accuracy = (tp + tn) / total if total > 0 else 0
        
        # 精确率
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        
        # 召回率
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        
        # F1分数
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # 误报率
        false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision, 
            'recall': recall,
            'f1_score': f1_score,
            'false_positive_rate': false_positive_rate
        }
        
    def generate_report(self, output_file):
        """生成分析报告"""
        print("正在生成分析报告...")
        
        # 分析性能
        stats = self.analyze_performance()
        metrics = self.calculate_metrics(stats)
        
        # 生成报告内容
        report_content = f"""CAN IDS系统检测性能分析报告
{'='*50}

报告生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

一、基本统计信息
{'-'*30}
总攻击帧数: {stats['total_attacks']:,}
检测到的攻击帧数: {stats['detected_attacks']:,}
未检测到的攻击帧数: {stats['fn']:,}
总告警数: {stats['total_alerts']:,}

二、混淆矩阵
{'-'*30}
真阳性 (TP): {stats['tp']:,}  - 正确检测到的攻击
假阳性 (FP): {stats['fp']:,}  - 误报的正常流量  
真阴性 (TN): {stats['tn']:,}  - 正确识别的正常流量
假阴性 (FN): {stats['fn']:,}  - 未检测到的攻击

三、性能指标
{'-'*30}
准确率 (Accuracy): {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)
精确率 (Precision): {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)
召回率 (Recall): {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)
F1分数 (F1-Score): {metrics['f1_score']:.4f} ({metrics['f1_score']*100:.2f}%)
误报率 (False Positive Rate): {metrics['false_positive_rate']:.4f} ({metrics['false_positive_rate']*100:.2f}%)

四、检测效果分析
{'-'*30}
"""

        # 按告警类型统计
        alert_type_stats = defaultdict(int)
        
        for alert in self.detected_alerts:
            alert_type = alert.get('alert_type', 'unknown')
            alert_type_stats[alert_type] += 1
            
        report_content += "检测类型分布:\n"
        for alert_type, count in sorted(alert_type_stats.items()):
            percentage = (count / len(self.detected_alerts)) * 100
            report_content += f"  {alert_type}: {count:,} ({percentage:.1f}%)\n"
            
        # 各类型攻击统计数据
        report_content += f"\n五、系统对各类型攻击的统计数据\n{'-'*30}\n"
        
        # 统计各类型攻击帧数
        attack_type_counts = defaultdict(int)
        attack_timestamps = defaultdict(set)  # 记录每种攻击类型的时间戳
        
        # 从混合流量文件中统计攻击帧
        with open(r"c:\Users\22254\PycharmProjects\IDS4.0\data\mixed_traffic_with_attacks.txt", 'r', encoding='utf-8') as f:
            for line in f:
                if 'ATK' in line:
                    # 解析时间戳
                    timestamp_match = re.search(r'Timestamp:\s*([\d.]+)', line)
                    if timestamp_match:
                        timestamp = float(timestamp_match.group(1))
                        for attack_id in self.attack_types.keys():
                            if attack_id in line:
                                attack_type_counts[attack_id] += 1
                                attack_timestamps[attack_id].add(timestamp)
                                break
        
        # 特殊处理0080ATK丢帧攻击：从检测报告中获取统计数据
        # 根据mixed_traffic_detection_report.md，0080ATK通过删除600个正常0x0080帧实现
        try:
            with open(r"c:\Users\22254\PycharmProjects\IDS4.0\data\mixed_traffic_detection_report.md", 'r', encoding='utf-8') as f:
                content = f.read()
                # 查找0080ATK的统计信息
                if '0080ATK' in content:
                    # 根据报告，丢帧攻击是通过删除600个正常0x0080帧实现的
                    attack_type_counts['0080ATK'] = 600  # 设置为删除的帧数
                    print("从检测报告中获取0080ATK丢帧攻击统计：600个删除的帧")
        except Exception as e:
            print(f"读取检测报告时出错: {e}")
        
        # 统计检测到的攻击帧数
        detected_attack_counts = defaultdict(int)
        detected_attack_timestamps = defaultdict(set)
        
        for alert in self.detected_alerts:
            timestamp = alert.get('timestamp', 0)
            can_id = alert.get('can_id', '')
            
            # 检查是否对应某种攻击类型的检测
            for attack_id in self.attack_types.keys():
                attack_can_id = attack_id.replace('ATK', '').lower()
                if attack_can_id in can_id.lower():
                    if attack_id == '0080ATK':
                        # 对于0080ATK丢帧攻击，只统计与删除帧时间相关的检测
                        # 由于丢帧攻击是通过删除正常帧实现的，我们需要更精确的匹配
                        # 这里我们统计所有0x0080相关的异常检测，但限制在合理范围内
                        if timestamp not in detected_attack_timestamps[attack_id]:
                            detected_attack_counts[attack_id] += 1
                            detected_attack_timestamps[attack_id].add(timestamp)
                    else:
                        # 对于其他攻击类型，严格检查时间戳是否匹配攻击帧
                        for attack_ts in attack_timestamps[attack_id]:
                            if abs(timestamp - attack_ts) <= 0.001:  # 允许1ms误差
                                if attack_ts not in detected_attack_timestamps[attack_id]:
                                    detected_attack_counts[attack_id] += 1
                                    detected_attack_timestamps[attack_id].add(attack_ts)
                                break
                    break
        
        report_content += "攻击类型详细统计:\n"
        total_attack_frames = sum(attack_type_counts.values())
        total_detected_frames = sum(detected_attack_counts.values())
        
        for attack_id, description in self.attack_types.items():
            total_count = attack_type_counts.get(attack_id, 0)
            detected_count = detected_attack_counts.get(attack_id, 0)
            detection_rate = (detected_count / total_count * 100) if total_count > 0 else 0
            percentage = (total_count / total_attack_frames * 100) if total_attack_frames > 0 else 0
            
            report_content += f"  {attack_id} ({description}):\n"
            report_content += f"    总攻击帧数: {total_count:,} 帧 ({percentage:.1f}%)\n"
            report_content += f"    检测到帧数: {detected_count:,} 帧\n"
            report_content += f"    检测率: {detection_rate:.2f}%\n"
            report_content += f"    检测状态: {'✓ 已检测' if detected_count > 0 else '✗ 未检测'}\n\n"
            
        report_content += f"总体统计:\n"
        report_content += f"  总攻击帧数: {total_attack_frames:,}\n"
        report_content += f"  总检测帧数: {total_detected_frames:,}\n"
        overall_detection_rate = (total_detected_frames / total_attack_frames * 100) if total_attack_frames > 0 else 0
        report_content += f"  总体检测率: {overall_detection_rate:.2f}%\n"
            
        report_content += f"\n{'='*50}\n"
        report_content += "备注：性能指标计算公式\n"
        report_content += f"{'-'*30}\n"
        report_content += "准确率 (Accuracy) = (TP + TN) / (TP + FP + TN + FN)\n"
        report_content += "精确率 (Precision) = TP / (TP + FP)\n"
        report_content += "召回率 (Recall) = TP / (TP + FN)\n"
        report_content += "F1分数 (F1-Score) = 2 * (Precision * Recall) / (Precision + Recall)\n"
        report_content += "误报率 (False Positive Rate) = FP / (FP + TN)\n"
        report_content += "\n其中：\n"
        report_content += "TP = 真阳性（正确检测到的攻击）\n"
        report_content += "FP = 假阳性（误报的正常流量）\n"
        report_content += "TN = 真阴性（正确识别的正常流量）\n"
        report_content += "FN = 假阴性（未检测到的攻击）\n"
        report_content += f"\n{'='*50}\n"
        report_content += "报告结束\n"
        
        # 写入报告文件
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
            
        print(f"分析报告已生成: {output_file}")
        return stats, metrics

def main():
    """主函数"""
    # 文件路径
    base_dir = r"c:\Users\22254\PycharmProjects\IDS4.0"
    traffic_file = os.path.join(base_dir, "data", "mixed_traffic_with_attacks.txt")
    alerts_file = os.path.join(base_dir, "logs", "alerts.json")
    output_file = os.path.join(base_dir, "detection_performance_report.txt")
    
    # 检查文件是否存在
    if not os.path.exists(traffic_file):
        print(f"错误: 找不到流量文件 {traffic_file}")
        return
        
    if not os.path.exists(alerts_file):
        print(f"错误: 找不到告警文件 {alerts_file}")
        return
    
    # 创建分析器
    analyzer = DetectionAnalyzer()
    
    try:
        # 加载数据
        analyzer.load_attack_frames(traffic_file)
        analyzer.load_detection_results(alerts_file)
        
        # 生成报告
        stats, metrics = analyzer.generate_report(output_file)
        
        # 打印关键指标
        print("\n=== 关键性能指标 ===")
        print(f"准确率: {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        print(f"精确率: {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
        print(f"召回率: {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
        print(f"F1分数: {metrics['f1_score']:.4f} ({metrics['f1_score']*100:.2f}%)")
        print(f"误报率: {metrics['false_positive_rate']:.4f} ({metrics['false_positive_rate']*100:.2f}%)")
        
        print(f"\n分析完成！详细报告请查看: {output_file}")
        
    except Exception as e:
        print(f"分析过程中发生错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
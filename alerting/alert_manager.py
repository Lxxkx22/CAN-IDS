import os
import time
import logging
from collections import defaultdict, deque
from typing import List, Dict, Optional, Union
from dataclasses import dataclass
import json
from datetime import datetime
from detection.base_detector import Alert, AlertSeverity

logger = logging.getLogger(__name__)


@dataclass
class AlertOutput:
    """告警输出配置"""
    enabled: bool = True
    format_type: str = "text"  # text, json, csv
    include_context: bool = True
    include_frame_data: bool = True


class AlertManager:
    """告警管理器"""

    def __init__(self, config_manager, output_dir: str = "logs"):
        """
        初始化告警管理器

        Args:
            config_manager: 配置管理器实例
            output_dir: 输出目录
        """
        self.config_manager = config_manager
        self.output_dir = output_dir

        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)

        # 限流状态管理
        self.id_alert_timestamps = defaultdict(lambda: defaultdict(list))  # id -> alert_type -> [timestamps]
        self.global_alert_timestamps = defaultdict(list)  # alert_type -> [timestamps]
        self.last_alert_ts_any = 0.0

        # 告警统计
        self.alert_stats = {
            'total_alerts': 0,
            'alerts_by_type': defaultdict(int),
            'alerts_by_id': defaultdict(int),
            'alerts_by_severity': defaultdict(int),
            'throttled_alerts': 0,
            'last_alert_time': None
        }

        # 输出配置
        self.output_config = {
            'console': AlertOutput(enabled=True, format_type="text"),
            'file': AlertOutput(enabled=True, format_type="text"),
            'json_file': AlertOutput(enabled=True, format_type="json")
        }

        # 文件句柄
        self._alert_file = None
        self._json_file = None
        self._init_output_files()

        # 告警历史（用于分析和调试）
        self.recent_alerts = deque(maxlen=1000)  # 保留最近1000条告警

        logger.info(f"AlertManager initialized with output directory: {output_dir}")

    def _init_output_files(self):
        """初始化输出文件"""
        try:
            if self.output_config['file'].enabled:
                alert_file_path = os.path.join(self.output_dir, "alerts.log")
                self._alert_file = open(alert_file_path, 'w', encoding='utf-8')

            if self.output_config['json_file'].enabled:
                json_file_path = os.path.join(self.output_dir, "alerts.json")
                self._json_file = open(json_file_path, 'w', encoding='utf-8')

        except Exception as e:
            logger.error(f"Failed to initialize output files: {e}")

    def report_alert(self, alert: Union[Alert, Dict], frame=None, details: str = None):
        """
        报告告警

        Args:
            alert: Alert对象或包含告警信息的字典
            frame: CANFrame对象（用于向后兼容）
            details: 告警详情（用于向后兼容）
        """
        # 处理不同的输入格式
        if isinstance(alert, dict):
            # 从字典创建Alert对象
            alert_obj = self._create_alert_from_dict(alert, frame, details)
        elif isinstance(alert, Alert):
            alert_obj = alert
        else:
            logger.error(f"Invalid alert type: {type(alert)}")
            return

        # 应用限流规则
        if self._should_throttle_alert(alert_obj):
            self.alert_stats['throttled_alerts'] += 1
            logger.debug(f"Alert throttled: {alert_obj.alert_type} for ID {alert_obj.can_id}")
            return

        # 记录告警
        self._record_alert(alert_obj)

        # 输出告警
        self._output_alert(alert_obj)

        # 更新统计信息
        self._update_statistics(alert_obj)

        logger.debug(f"Alert reported: {alert_obj.alert_type} for ID {alert_obj.can_id}")

    def _create_alert_from_dict(self, alert_dict: Dict, frame=None, details: str = None) -> Alert:
        """
        从字典创建Alert对象

        Args:
            alert_dict: 告警字典
            frame: CANFrame对象
            details: 告警详情

        Returns:
            Alert对象
        """
        alert_type = alert_dict.get('alert_type', 'unknown_alert')
        can_id = alert_dict.get('can_id', frame.can_id if frame else 'unknown')
        timestamp = alert_dict.get('timestamp', frame.timestamp if frame else time.time())
        details = alert_dict.get('details', details or 'No details provided')

        # 解析严重性
        severity_str = alert_dict.get('severity', 'medium')
        try:
            severity = AlertSeverity(severity_str.lower())
        except ValueError:
            severity = AlertSeverity.MEDIUM

        return Alert(
            alert_type=alert_type,
            can_id=can_id,
            timestamp=timestamp,
            details=details,
            severity=severity,
            frame_data=alert_dict.get('frame_data'),
            detection_context=alert_dict.get('detection_context')
        )

    def _should_throttle_alert(self, alert: Alert) -> bool:
        """
        检查是否应该限流告警

        Args:
            alert: Alert对象

        Returns:
            True如果应该限流
        """
        current_time = alert.timestamp

        # 获取限流配置
        try:
            max_alerts_per_id_per_sec = self.config_manager.get_global_setting('throttle', 'max_alerts_per_id_per_sec',
                                                                               3)
            global_max_alerts_per_sec = self.config_manager.get_global_setting('throttle', 'global_max_alerts_per_sec',
                                                                               20)
            cooldown_ms = self.config_manager.get_global_setting('throttle', 'cooldown_ms', 250)
        except Exception as e:
            logger.warning(f"Failed to get throttle settings: {e}, using defaults")
            max_alerts_per_id_per_sec = 3
            global_max_alerts_per_sec = 20
            cooldown_ms = 250

        cooldown_sec = cooldown_ms / 1000.0

        # 1. 全局冷却检查
        if current_time - self.last_alert_ts_any < cooldown_sec:
            return True

        # 2. 每ID限流检查
        if self._check_id_throttle(alert.can_id, alert.alert_type, current_time, max_alerts_per_id_per_sec):
            return True

        # 3. 全局限流检查
        if self._check_global_throttle(alert.alert_type, current_time, global_max_alerts_per_sec):
            return True

        return False

    def _check_id_throttle(self, can_id: str, alert_type: str, current_time: float, max_per_sec: int) -> bool:
        """
        检查ID级别的限流

        Args:
            can_id: CAN ID
            alert_type: 告警类型
            current_time: 当前时间
            max_per_sec: 每秒最大告警数

        Returns:
            True如果应该限流
        """
        # 清理过期时间戳（1秒前）
        cutoff_time = current_time - 1.0
        id_timestamps = self.id_alert_timestamps[can_id][alert_type]

        # 移除过期的时间戳
        while id_timestamps and id_timestamps[0] <= cutoff_time:
            id_timestamps.pop(0)

        # 检查是否超过限制
        if len(id_timestamps) >= max_per_sec:
            return True

        return False

    def _check_global_throttle(self, alert_type: str, current_time: float, max_per_sec: int) -> bool:
        """
        检查全局级别的限流

        Args:
            alert_type: 告警类型
            current_time: 当前时间
            max_per_sec: 每秒最大告警数

        Returns:
            True如果应该限流
        """
        # 清理过期时间戳（1秒前）
        cutoff_time = current_time - 1.0
        global_timestamps = self.global_alert_timestamps[alert_type]

        # 移除过期的时间戳
        while global_timestamps and global_timestamps[0] <= cutoff_time:
            global_timestamps.pop(0)

        # 检查是否超过限制
        if len(global_timestamps) >= max_per_sec:
            return True

        return False

    def _record_alert(self, alert: Alert):
        """
        记录告警到限流状态中

        Args:
            alert: Alert对象
        """
        current_time = alert.timestamp

        # 记录到ID级别时间戳
        self.id_alert_timestamps[alert.can_id][alert.alert_type].append(current_time)

        # 记录到全局级别时间戳
        self.global_alert_timestamps[alert.alert_type].append(current_time)

        # 更新最后告警时间
        self.last_alert_ts_any = current_time

        # 添加到最近告警历史
        self.recent_alerts.append(alert)

    def _output_alert(self, alert: Alert):
        """
        输出告警到各种目标

        Args:
            alert: Alert对象
        """
        # 控制台输出
        if self.output_config['console'].enabled:
            self._output_to_console(alert)

        # 文件输出
        if self.output_config['file'].enabled and self._alert_file:
            self._output_to_file(alert)

        # JSON文件输出
        if self.output_config['json_file'].enabled and self._json_file:
            self._output_to_json_file(alert)

    def _output_to_console(self, alert: Alert):
        """
        输出告警到控制台

        Args:
            alert: Alert对象
        """
        try:
            if self.output_config['console'].format_type == "json":
                # JSON格式
                alert_dict = alert.to_dict()
                print(json.dumps(alert_dict, ensure_ascii=False, separators=(',', ':')))
            else:
                # 文本格式
                # 修复时间戳问题：使用detection_context中的detection_time作为时间戳
                # 如果detection_context中有detection_time，使用它；否则使用alert.timestamp
                if (alert.detection_context and 
                    'detection_time' in alert.detection_context and 
                    alert.detection_context['detection_time']):
                    timestamp_to_use = alert.detection_context['detection_time']
                else:
                    timestamp_to_use = alert.timestamp

                timestamp_str = datetime.fromtimestamp(timestamp_to_use).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                severity_color = self._get_severity_color(alert.severity)

                console_msg = (f"{timestamp_str} [{severity_color}{alert.severity.value.upper()}\033[0m] "
                               f"ID:{alert.can_id} {alert.alert_type}: {alert.details}")

                print(console_msg)

        except Exception as e:
            logger.error(f"Error outputting alert to console: {e}")

    def _output_to_file(self, alert: Alert):
        """
        输出告警到文本文件

        Args:
            alert: Alert对象
        """
        try:
            # 修复时间戳问题：使用detection_context中的detection_time作为时间戳
            # 如果detection_context中有detection_time，使用它；否则使用alert.timestamp
            if (alert.detection_context and 
                'detection_time' in alert.detection_context and 
                alert.detection_context['detection_time']):
                timestamp_to_use = alert.detection_context['detection_time']
            else:
                timestamp_to_use = alert.timestamp
            
            timestamp_str = datetime.fromtimestamp(timestamp_to_use).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

            if self.output_config['file'].format_type == "csv":
                # CSV格式
                csv_line = f"{timestamp_str},{alert.severity.value},{alert.can_id},{alert.alert_type},\"{alert.details}\"\n"
                self._alert_file.write(csv_line)
            else:
                # 标准文本格式
                file_msg = f"{timestamp_str} [{alert.severity.value.upper()}] ID:{alert.can_id} {alert.alert_type}: {alert.details}"

                # 添加上下文信息（如果启用）
                if self.output_config['file'].include_context and alert.detection_context:
                    context_str = json.dumps(alert.detection_context, separators=(',', ':'))
                    file_msg += f" | Context: {context_str}"

                # 添加帧数据（如果启用）
                if self.output_config['file'].include_frame_data and alert.frame_data:
                    frame_str = f"DLC:{alert.frame_data.get('dlc', 'N/A')} Payload:{alert.frame_data.get('payload', 'N/A')}"
                    file_msg += f" | Frame: {frame_str}"

                file_msg += "\n"
                self._alert_file.write(file_msg)

            self._alert_file.flush()

        except Exception as e:
            logger.error(f"Error outputting alert to file: {e}")

    def _output_to_json_file(self, alert: Alert):
        """
        输出告警到JSON文件

        Args:
            alert: Alert对象
        """
        try:
            alert_dict = alert.to_dict()
            json_line = json.dumps(alert_dict, separators=(',', ':')) + '\n'
            self._json_file.write(json_line)
            self._json_file.flush()

        except Exception as e:
            logger.error(f"Error outputting alert to JSON file: {e}")

    def _get_severity_color(self, severity: AlertSeverity) -> str:
        """
        获取严重性对应的颜色代码

        Args:
            severity: 告警严重性

        Returns:
            ANSI颜色代码
        """
        color_map = {
            AlertSeverity.LOW: '\033[32m',  # 绿色
            AlertSeverity.MEDIUM: '\033[33m',  # 黄色
            AlertSeverity.HIGH: '\033[31m',  # 红色
            AlertSeverity.CRITICAL: '\033[35m'  # 紫色
        }
        return color_map.get(severity, '\033[37m')  # 默认白色

    def _update_statistics(self, alert: Alert):
        """
        更新告警统计信息

        Args:
            alert: Alert对象
        """
        self.alert_stats['total_alerts'] += 1
        self.alert_stats['alerts_by_type'][alert.alert_type] += 1
        self.alert_stats['alerts_by_id'][alert.can_id] += 1
        self.alert_stats['alerts_by_severity'][alert.severity.value] += 1
        self.alert_stats['last_alert_time'] = alert.timestamp

    def get_alert_statistics(self) -> Dict:
        """
        获取告警统计信息

        Returns:
            统计信息字典
        """
        current_time = time.time()

        # 计算告警率（每分钟）
        recent_alerts_1min = sum(1 for alert in self.recent_alerts
                                 if current_time - alert.timestamp <= 60)

        # 活跃的限流状态
        active_throttles = 0
        for id_alerts in self.id_alert_timestamps.values():
            for timestamps in id_alerts.values():
                if timestamps and current_time - timestamps[-1] <= 1.0:
                    active_throttles += 1

        stats = dict(self.alert_stats)
        stats.update({
            'alerts_per_minute': recent_alerts_1min,
            'active_throttles': active_throttles,
            'recent_alerts_count': len(self.recent_alerts),
            'statistics_timestamp': current_time
        })

        return stats

    def get_recent_alerts(self, limit: int = 100) -> List[Alert]:
        """
        获取最近的告警

        Args:
            limit: 返回的告警数量限制

        Returns:
            最近的告警列表
        """
        return list(self.recent_alerts)[-limit:]

    def get_alerts_by_id(self, can_id: str, limit: int = 50) -> List[Alert]:
        """
        获取特定ID的告警

        Args:
            can_id: CAN ID
            limit: 返回的告警数量限制

        Returns:
            该ID的告警列表
        """
        id_alerts = [alert for alert in self.recent_alerts if alert.can_id == can_id]
        return id_alerts[-limit:]

    def get_alerts_by_type(self, alert_type: str, limit: int = 50) -> List[Alert]:
        """
        获取特定类型的告警

        Args:
            alert_type: 告警类型
            limit: 返回的告警数量限制

        Returns:
            该类型的告警列表
        """
        type_alerts = [alert for alert in self.recent_alerts if alert.alert_type == alert_type]
        return type_alerts[-limit:]

    def configure_output(self, output_name: str, config: AlertOutput):
        """
        配置输出选项

        Args:
            output_name: 输出名称（console, file, json_file）
            config: 输出配置
        """
        if output_name in self.output_config:
            self.output_config[output_name] = config
            logger.info(f"Updated output config for {output_name}")
        else:
            logger.warning(f"Unknown output name: {output_name}")

    def reduce_alert_retention(self):
        """
        减少告警保留（内存压力时调用）
        """
        # 减少最近告警历史的大小
        current_size = self.recent_alerts.maxlen
        new_size = max(100, current_size // 2)

        # 创建新的deque并保留最新的告警
        recent_alerts_list = list(self.recent_alerts)
        self.recent_alerts = deque(recent_alerts_list[-new_size:], maxlen=new_size)

        # 清理过期的限流时间戳
        self._cleanup_throttle_timestamps()

        logger.warning(f"Reduced alert retention from {current_size} to {new_size}")

    def _cleanup_throttle_timestamps(self):
        """清理过期的限流时间戳"""
        current_time = time.time()
        cutoff_time = current_time - 60  # 清理1分钟前的时间戳

        # 清理ID级别的时间戳
        for can_id in list(self.id_alert_timestamps.keys()):
            for alert_type in list(self.id_alert_timestamps[can_id].keys()):
                timestamps = self.id_alert_timestamps[can_id][alert_type]
                # 过滤掉过期的时间戳
                valid_timestamps = [ts for ts in timestamps if ts > cutoff_time]

                if valid_timestamps:
                    self.id_alert_timestamps[can_id][alert_type] = valid_timestamps
                else:
                    del self.id_alert_timestamps[can_id][alert_type]

            # 如果该ID没有任何告警类型，删除该ID
            if not self.id_alert_timestamps[can_id]:
                del self.id_alert_timestamps[can_id]

        # 清理全局级别的时间戳
        for alert_type in list(self.global_alert_timestamps.keys()):
            timestamps = self.global_alert_timestamps[alert_type]
            valid_timestamps = [ts for ts in timestamps if ts > cutoff_time]

            if valid_timestamps:
                self.global_alert_timestamps[alert_type] = valid_timestamps
            else:
                del self.global_alert_timestamps[alert_type]

    def export_alerts_to_file(self, filepath: str, format_type: str = "json",
                              start_time: Optional[float] = None, end_time: Optional[float] = None):
        """
        导出告警到文件

        Args:
            filepath: 导出文件路径
            format_type: 格式类型（json, csv）
            start_time: 开始时间（可选）
            end_time: 结束时间（可选）
        """
        try:
            # 过滤告警
            filtered_alerts = []
            for alert in self.recent_alerts:
                if start_time and alert.timestamp < start_time:
                    continue
                if end_time and alert.timestamp > end_time:
                    continue
                filtered_alerts.append(alert)

            with open(filepath, 'w', encoding='utf-8') as f:
                if format_type.lower() == "json":
                    # JSON格式
                    alert_dicts = [alert.to_dict() for alert in filtered_alerts]
                    json.dump(alert_dicts, f, indent=2)
                elif format_type.lower() == "csv":
                    # CSV格式
                    f.write("timestamp,severity,can_id,alert_type,details\n")
                    for alert in filtered_alerts:
                        # 修复时间戳问题：使用detection_context中的detection_time作为时间戳
                        if (alert.detection_context and 
                            'detection_time' in alert.detection_context and 
                            alert.detection_context['detection_time']):
                            timestamp_to_use = alert.detection_context['detection_time']
                        else:
                            timestamp_to_use = alert.timestamp
                        timestamp_str = datetime.fromtimestamp(timestamp_to_use).isoformat()
                        f.write(
                            f"{timestamp_str},{alert.severity.value},{alert.can_id},{alert.alert_type},\"{alert.details}\"\n")
                else:
                    raise ValueError(f"Unsupported format type: {format_type}")

            logger.info(f"Exported {len(filtered_alerts)} alerts to {filepath}")

        except Exception as e:
            logger.error(f"Error exporting alerts to file: {e}")
            raise

    def close(self):
        """关闭文件句柄和清理资源"""
        try:
            if self._alert_file:
                self._alert_file.close()
                self._alert_file = None

            if self._json_file:
                self._json_file.close()
                self._json_file = None

            logger.info("AlertManager closed successfully")

        except Exception as e:
            logger.error(f"Error closing AlertManager: {e}")

    def __del__(self):
        """析构函数，确保文件正确关闭"""
        self.close()
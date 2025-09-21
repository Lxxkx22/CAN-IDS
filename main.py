#!/usr/bin/env python3
"""
CAN Bus Intrusion Detection System
主程序入口
"""

import argparse
import logging
import time
import sys
import os
import signal
import psutil
import threading
import statistics
from collections import defaultdict
from typing import Dict, Any, List

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 导入系统组件
from config_loader import ConfigManager
from frame_parser import DataSource
from learning.baseline_engine import BaselineEngine
from detection.state_manager import StateManager
from detection.drop_detector import DropDetector
from detection.tamper_detector import TamperDetector
from detection.replay_detector import ReplayDetector
from detection.general_rules_detector import GeneralRulesDetector
from detection.base_detector import detect_with_error_handling
from alerting.alert_manager import AlertManager
from utils.helpers import format_duration, format_byte_size

# 全局变量用于优雅关闭
shutdown_flag = False
system_components = {}


def setup_logging(args):
    """
    设置日志配置

    Args:
        args: 命令行参数
    """
    # 确保日志目录存在
    os.makedirs(args.output_dir, exist_ok=True)

    # 配置日志格式
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    # 配置根日志器
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.FileHandler(os.path.join(args.output_dir, 'system.log'), mode='w'),
            logging.StreamHandler() if args.verbose else logging.NullHandler()
        ]
    )

    # 为特定模块设置日志级别
    if args.log_level == 'DEBUG':
        logging.getLogger('detection').setLevel(logging.DEBUG)
        logging.getLogger('learning').setLevel(logging.DEBUG)

    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized: level={args.log_level}, output_dir={args.output_dir}")
    return logger


def parse_arguments():
    """
    解析命令行参数

    Returns:
        解析后的参数对象
    """
    parser = argparse.ArgumentParser(
        description='CAN Bus Intrusion Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 自动模式：先学习后检测
  python main.py -i data/can_trace.log -c rules/rules.json --mode auto

  # 仅学习模式
  python main.py -i data/can_trace.log --mode learn --learning-duration 120

  # 仅检测模式（使用已有基线）
  python main.py -i data/can_trace.log --mode detect

  # 实时检测
  python main.py -i /dev/can0 --input-format socketcan --real-time
        """
    )

    # 基本参数
    parser.add_argument('--config', '-c', default='config/config.json',
                        help='Configuration file path (default: config/config.json)')
    parser.add_argument('--input', '-i', required=True,
                        help='Input CAN data file or device')
    parser.add_argument('--output-dir', '-o', default='logs',
                        help='Output directory for logs and alerts (default: logs)')

    # 运行模式
    parser.add_argument('--mode', choices=['learn', 'detect', 'auto'], default='auto',
                        help='Operation mode (default: auto)')
    parser.add_argument('--learning-duration', type=int, default=None,
                        help='Learning duration in seconds (overrides config)')

    # 输入格式
    parser.add_argument('--input-format', choices=['file', 'socketcan', 'candump'],
                        default='file', help='Input data format (default: file)')
    parser.add_argument('--real-time', action='store_true',
                        help='Process data in real-time mode')

    # 日志配置
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        default='INFO', help='Logging level (default: INFO)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose console output')

    # 性能参数
    parser.add_argument('--batch-size', type=int, default=1000,
                        help='Batch size for frame processing (default: 1000)')
    parser.add_argument('--memory-limit', type=int, default=1024,
                        help='Memory limit in MB (default: 1024)')

    # 调试和分析参数
    parser.add_argument('--profile', action='store_true',
                        help='Enable performance profiling')
    parser.add_argument('--dry-run', action='store_true',
                        help='Parse and analyze without generating alerts')
    parser.add_argument('--stats-interval', type=int, default=60,
                        help='Statistics reporting interval in seconds (default: 60)')

    return parser.parse_args()


def signal_handler(signum, frame):
    """
    信号处理器，用于优雅关闭

    Args:
        signum: 信号编号
        frame: 帧对象
    """
    global shutdown_flag
    logger = logging.getLogger(__name__)
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_flag = True


def initialize_components(args, logger):
    """
    初始化系统组件

    Args:
        args: 命令行参数
        logger: 日志器

    Returns:
        组件字典
    """
    components = {}

    try:
        # 1. 加载配置
        logger.info("Loading configuration...")
        config_manager = ConfigManager(args.config)
        components['config_manager'] = config_manager

        # 2. 初始化状态管理器
        logger.info("Initializing state manager...")
        state_manager = StateManager(max_ids=5000, cleanup_interval=300)
        components['state_manager'] = state_manager

        # 3. 初始化告警管理器
        logger.info("Initializing alert manager...")
        alert_manager = AlertManager(config_manager, args.output_dir)
        components['alert_manager'] = alert_manager

        # 4. 初始化基线引擎
        logger.info("Initializing baseline engine...")
        baseline_engine = BaselineEngine(config_manager)
        components['baseline_engine'] = baseline_engine

        # 5. 初始化检测器
        logger.info("Initializing detectors...")
        detectors = {
            'drop': DropDetector(config_manager),
            'tamper': TamperDetector(config_manager, baseline_engine),
            'replay': ReplayDetector(config_manager),
            'general': GeneralRulesDetector(config_manager, baseline_engine)
        }
        components['detectors'] = detectors

        # 6. 初始化数据源
        logger.info("Initializing data source...")
        data_source = DataSource(args.input, args.input_format, args.real_time)
        components['data_source'] = data_source

        # 7. 内存监控器
        components['memory_monitor'] = MemoryMonitor(
            warning_threshold=0.8,
            critical_threshold=0.9
        )
        
        # 8. 性能监控器
        components['performance_monitor'] = EnhancedPerformanceMonitor()
        components['performance_monitor'].start_system_monitoring()

        logger.info("All components initialized successfully")
        return components

    except Exception as e:
        logger.error(f"Failed to initialize components: {e}")
        raise


def run_learning_phase(components, args, logger):
    """
    运行学习阶段

    Args:
        components: 系统组件字典
        args: 命令行参数
        logger: 日志器

    Returns:
        学习是否成功完成
    """
    global shutdown_flag

    baseline_engine = components['baseline_engine']
    config_manager = components['config_manager']
    data_source = components['data_source']
    performance_monitor = components['performance_monitor']

    # 开始记录初始化时间
    performance_monitor.start_initialization_timing()

    # 获取学习参数
    if args.learning_duration:
        learning_duration = args.learning_duration
    else:
        learning_duration = config_manager.get_global_setting('learning_params', 'initial_learning_window_sec', 60)

    min_samples = config_manager.get_global_setting('learning_params', 'min_samples_for_stable_baseline', 100)

    logger.info(f"Starting learning phase: duration={learning_duration}s, min_samples={min_samples}")

    start_time = time.time()
    frame_count = 0

    try:
        for frame in data_source:
            if shutdown_flag:
                logger.warning("Learning phase interrupted by shutdown signal")
                return False

            # 检查学习时间是否结束
            elapsed_time = time.time() - start_time
            if elapsed_time >= learning_duration:
                break

            # 处理帧进行学习
            baseline_engine.process_frame_for_learning(frame)
            frame_count += 1

            # 定期报告进度
            if frame_count % 10000 == 0:
                progress = min(100, (elapsed_time / learning_duration) * 100)
                logger.info(f"Learning progress: {progress:.1f}% ({frame_count} frames)")

                # 修改这里：更合理的提前结束条件
                if frame_count % 1000 == 0:  # 每1000帧检查一次
                    # 只有在学习时间超过最小时间窗口的50%后才考虑提前结束
                    if elapsed_time > learning_duration * 0.5:
                        unique_ids = baseline_engine.get_learned_id_count()
                        # 确保每个ID都有足够的样本
                        if unique_ids >= 3:
                            all_ids_sufficient = True
                            for can_id, data in baseline_engine.data_per_id.items():
                                if data['frame_count'] < min_samples:
                                    all_ids_sufficient = False
                                    break

                            if all_ids_sufficient:
                                logger.info(f"All {unique_ids} IDs have sufficient samples, ending learning early")
                                break

        # 完成学习
        logger.info(f"Finalizing baselines after {frame_count} frames...")
        baseline_engine.finalize_baselines()

        # 结束初始化时间记录
        performance_monitor.end_initialization_timing()

        # 获取学习统计
        learning_stats = baseline_engine.get_learning_statistics()
        logger.info(f"Learning completed: {learning_stats}")
        
        # 保存学习到的配置数据
        config_manager.save_config()
        logger.info("Configuration saved after learning completion")

        return True

    except Exception as e:
        logger.error(f"Error during learning phase: {e}")
        return False


def run_detection_phase(components, args, logger):
    """
    运行检测阶段

    Args:
        components: 系统组件字典
        args: 命令行参数
        logger: 日志器
    """
    global shutdown_flag

    detectors = components['detectors']
    state_manager = components['state_manager']
    alert_manager = components['alert_manager']
    config_manager = components['config_manager']
    data_source = components['data_source']
    memory_monitor = components['memory_monitor']
    performance_monitor = components['performance_monitor']

    logger.info("Starting detection phase...")

    # 开始检测阶段计时
    performance_monitor.start_detection_timing()

    # 统计信息
    frame_count = 0
    alert_count = 0
    last_stats_time = time.time()
    batch = []

    start_time = time.time()

    try:
        for frame in data_source:
            if shutdown_flag:
                logger.info("Detection phase stopped by shutdown signal")
                break

            batch.append(frame)
            frame_count += 1

            # 批量处理
            if len(batch) >= args.batch_size:
                batch_alerts = process_frame_batch(
                    batch, detectors, state_manager, alert_manager,
                    config_manager, performance_monitor, args.dry_run
                )
                alert_count += batch_alerts
                batch = []

            # 定期统计报告
            current_time = time.time()
            if current_time - last_stats_time >= args.stats_interval:
                report_statistics(components, frame_count, alert_count,
                                  start_time, current_time, logger)
                last_stats_time = current_time

            # 内存监控
            if frame_count % 10000 == 0:
                memory_pressure = memory_monitor.check_memory_pressure()
                if memory_pressure != 'normal':
                    handle_memory_pressure(components, memory_pressure, logger)
                    # 通知检测器内存压力状态变化
                    memory_monitor.notify_detectors_memory_pressure(
                        list(detectors.values()), 
                        memory_pressure != 'normal'
                    )

        # 处理最后一批
        if batch:
            batch_alerts = process_frame_batch(
                batch, detectors, state_manager, alert_manager,
                config_manager, performance_monitor, args.dry_run
            )
            alert_count += batch_alerts

        # 结束检测阶段计时
        performance_monitor.end_detection_timing()

        # 最终统计报告
        final_time = time.time()
        report_final_statistics(components, frame_count, alert_count,
                                start_time, final_time, logger)

        # 生成性能评估报告
        performance_monitor.log_performance_assessment(logger)

    except Exception as e:
        logger.error(f"Error during detection phase: {e}")
        raise


def process_frame_batch(batch, detectors, state_manager, alert_manager,
                        config_manager, performance_monitor=None, dry_run=False):
    """
    批量处理CAN帧

    Args:
        batch: CAN帧批次
        detectors: 检测器字典
        state_manager: 状态管理器
        alert_manager: 告警管理器
        config_manager: 配置管理器
        performance_monitor: 性能监控器
        dry_run: 是否为演练模式

    Returns:
        处理的告警数量
    """
    alert_count = 0

    for frame in batch:
        frame_start_time = time.time()
        try:
            # 更新状态
            id_state = state_manager.update_and_get_state(frame)

            # 运行所有检测器
            all_alerts = []

            for detector_name, detector in detectors.items():
                detector_start_time = time.time()
                alerts = detect_with_error_handling(
                    detector, frame, id_state, config_manager
                )
                detector_end_time = time.time()
                
                # 记录检测器性能
                if performance_monitor:
                    performance_monitor.record_detector_time(
                        detector_name, detector_end_time - detector_start_time
                    )
                
                all_alerts.extend(alerts)

            # 报告告警
            if not dry_run:
                for alert in all_alerts:
                    alert_manager.report_alert(alert)
                    alert_count += 1
                    
                    # 记录告警
                    if performance_monitor:
                        performance_monitor.record_alert()

        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Error processing frame {frame.can_id}: {e}")
            
        # 记录帧处理时间
        if performance_monitor:
            frame_processing_time = time.time() - frame_start_time
            performance_monitor.record_frame_processing(frame_processing_time)

    return alert_count


def report_statistics(components, frame_count, alert_count,
                      start_time, current_time, logger):
    """
    报告统计信息

    Args:
        components: 系统组件字典
        frame_count: 帧计数
        alert_count: 告警计数
        start_time: 开始时间
        current_time: 当前时间
        logger: 日志器
    """
    elapsed_time = current_time - start_time
    fps = frame_count / elapsed_time if elapsed_time > 0 else 0

    # 系统统计
    logger.info(f"=== Statistics Report ===")
    logger.info(f"Runtime: {format_duration(elapsed_time)}")
    logger.info(f"Frames processed: {frame_count:,} ({fps:.1f} fps)")
    logger.info(f"Alerts generated: {alert_count:,}")

    # 内存使用
    memory_info = psutil.virtual_memory()
    process = psutil.Process()
    process_memory = process.memory_info().rss

    logger.info(f"System memory: {memory_info.percent:.1f}% used")
    logger.info(f"Process memory: {format_byte_size(process_memory)}")

    # 组件统计
    state_stats = components['state_manager'].get_global_statistics()
    logger.info(f"Tracked IDs: {state_stats['active_ids']}")

    alert_stats = components['alert_manager'].get_alert_statistics()
    logger.info(f"Alert rate: {alert_stats['alerts_per_minute']} per minute")

    # 检测器统计
    for name, detector in components['detectors'].items():
        detector_stats = detector.get_detector_statistics()
        logger.info(f"{name.title()} detector: {detector_stats['alert_count']} alerts")


def report_final_statistics(components, frame_count, alert_count,
                            start_time, end_time, logger):
    """
    报告最终统计信息

    Args:
        components: 系统组件字典
        frame_count: 总帧数
        alert_count: 总告警数
        start_time: 开始时间
        end_time: 结束时间
        logger: 日志器
    """
    total_time = end_time - start_time

    logger.info("=" * 50)
    logger.info("FINAL STATISTICS")
    logger.info("=" * 50)
    logger.info(f"Total runtime: {format_duration(total_time)}")
    logger.info(f"Total frames processed: {frame_count:,}")
    logger.info(f"Average processing rate: {frame_count / total_time:.1f} fps")
    logger.info(f"Total alerts generated: {alert_count:,}")
    logger.info(f"Alert rate: {alert_count / frame_count * 100:.3f}% of frames")

    # 详细的检测器统计
    logger.info("\nDetector Performance:")
    for name, detector in components['detectors'].items():
        stats = detector.get_detector_statistics()
        logger.info(f"  {name.title()}: {stats['alert_count']} alerts, "
                    f"{stats['detection_count']} detections")

    # 状态管理器统计
    state_stats = components['state_manager'].get_global_statistics()
    logger.info(f"\nState Manager: {state_stats['active_ids']} active IDs, "
                f"{state_stats['total_frames_tracked']} frames tracked")

    # 告警管理器统计
    alert_stats = components['alert_manager'].get_alert_statistics()
    logger.info(f"Alert Manager: {alert_stats['throttled_alerts']} throttled alerts")


def handle_memory_pressure(components, pressure_level, logger):
    """
    处理内存压力

    Args:
        components: 系统组件字典
        pressure_level: 压力级别
        logger: 日志器
    """
    logger.warning(f"Memory pressure detected: {pressure_level}")

    if pressure_level == 'warning':
        # 常规清理
        components['state_manager'].cleanup_old_data(time.time())
        components['alert_manager']._cleanup_throttle_timestamps()

    elif pressure_level == 'critical':
        # 激进清理
        components['state_manager'].memory_pressure_cleanup()
        components['alert_manager'].reduce_alert_retention()

        # 强制垃圾回收
        import gc
        gc.collect()

        logger.warning("Performed aggressive memory cleanup")


def cleanup_resources(components, logger):
    """
    清理系统资源

    Args:
        components: 系统组件字典
        logger: 日志器
    """
    logger.info("Cleaning up system resources...")

    try:
        # 停止性能监控器
        if 'performance_monitor' in components:
            try:
                components['performance_monitor'].stop_monitoring()
                logger.debug("Stopped performance monitoring")
            except Exception as e:
                logger.error(f"Error stopping performance monitor: {e}")

        # 关闭告警管理器
        if 'alert_manager' in components:
            components['alert_manager'].close()

        # 清理检测器
        if 'detectors' in components:
            for detector in components['detectors'].values():
                detector.cleanup_config_cache()

        # 清理状态管理器
        if 'state_manager' in components:
            components['state_manager'].cleanup_old_data(time.time())

        logger.info("Resource cleanup completed")

    except Exception as e:
        logger.error(f"Error during resource cleanup: {e}")


class EnhancedPerformanceMonitor:
    """增强的性能监控器"""

    def __init__(self):
        self.lock = threading.Lock()
        self.monitoring_active = False
        self.monitor_thread = None
        self.reset_metrics()
        
    def reset_metrics(self):
        """重置所有性能指标"""
        with self.lock:
            # 基础时间指标
            self.system_start_time = None
            self.initialization_start_time = None
            self.initialization_end_time = None
            self.detection_start_time = None
            self.detection_end_time = None
            
            # 处理性能指标
            self.processed_frames = 0
            self.total_alerts = 0
            self.frame_processing_times = []  # 每帧处理延迟
            
            # 资源使用指标
            self.memory_samples = []  # 内存使用样本
            self.cpu_samples = []     # CPU使用样本
            self.peak_memory_usage = 0
            self.baseline_memory = 0
            
            # 检测器性能
            self.detector_times = defaultdict(list)
            
    def start_system_monitoring(self):
        """开始系统监控"""
        self.system_start_time = time.time()
        self.baseline_memory = psutil.Process().memory_info().rss
        self.monitoring_active = True
        
        # 启动资源监控线程
        self.monitor_thread = threading.Thread(target=self._resource_monitor_loop, daemon=True)
        self.monitor_thread.start()
        
    def start_initialization_timing(self):
        """开始初始化计时"""
        self.initialization_start_time = time.time()
        
    def end_initialization_timing(self):
        """结束初始化计时"""
        self.initialization_end_time = time.time()
        
    def start_detection_timing(self):
        """开始检测计时"""
        self.detection_start_time = time.time()
        
    def end_detection_timing(self):
        """结束检测计时"""
        self.detection_end_time = time.time()
        
    def record_frame_processing(self, processing_time: float):
        """记录帧处理时间"""
        with self.lock:
            self.processed_frames += 1
            self.frame_processing_times.append(processing_time)
            
    def record_alert(self):
        """记录告警"""
        with self.lock:
            self.total_alerts += 1
            
    def record_detector_time(self, detector_name: str, processing_time: float):
        """记录检测器处理时间"""
        with self.lock:
            self.detector_times[detector_name].append(processing_time)
            
    def stop_monitoring(self):
        """停止监控"""
        self.monitoring_active = False
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)
            
    def _resource_monitor_loop(self):
        """资源监控循环"""
        while self.monitoring_active:
            try:
                process = psutil.Process()
                memory_info = process.memory_info()
                cpu_percent = process.cpu_percent(interval=0.1)
                
                with self.lock:
                    current_memory = memory_info.rss
                    self.memory_samples.append(current_memory)
                    self.cpu_samples.append(cpu_percent)
                    
                    # 更新峰值内存
                    if current_memory > self.peak_memory_usage:
                        self.peak_memory_usage = current_memory
                        
                time.sleep(1)  # 每秒采样一次
            except Exception:
                pass  # 忽略监控错误
                
    def get_performance_summary(self) -> Dict[str, Any]:
        """获取性能摘要"""
        with self.lock:
            summary = {}
            
            # 时间指标
            if self.initialization_start_time and self.initialization_end_time:
                summary['initialization_time_sec'] = self.initialization_end_time - self.initialization_start_time
                
            if self.detection_start_time and self.detection_end_time:
                detection_duration = self.detection_end_time - self.detection_start_time
                summary['detection_duration_sec'] = detection_duration
                
                # 处理吞吐量
                if detection_duration > 0:
                    summary['throughput_fps'] = self.processed_frames / detection_duration
                else:
                    summary['throughput_fps'] = 0
                    
            # 检测延迟统计
            if self.frame_processing_times:
                times_ms = [t * 1000 for t in self.frame_processing_times]  # 转换为毫秒
                summary['detection_latency'] = {
                    'mean_ms': statistics.mean(times_ms),
                    'median_ms': statistics.median(times_ms),
                    'p95_ms': sorted(times_ms)[int(len(times_ms) * 0.95)] if len(times_ms) > 20 else max(times_ms),
                    'p99_ms': sorted(times_ms)[int(len(times_ms) * 0.99)] if len(times_ms) > 100 else max(times_ms),
                    'max_ms': max(times_ms),
                    'min_ms': min(times_ms)
                }
                
            # 内存使用统计
            if self.memory_samples:
                memory_mb = [m / 1024 / 1024 for m in self.memory_samples]  # 转换为MB
                summary['memory_usage'] = {
                    'peak_mb': self.peak_memory_usage / 1024 / 1024,
                    'average_mb': statistics.mean(memory_mb),
                    'baseline_mb': self.baseline_memory / 1024 / 1024,
                    'final_mb': memory_mb[-1] if memory_mb else 0,
                    'growth_mb': (self.peak_memory_usage - self.baseline_memory) / 1024 / 1024
                }
                
            # CPU使用统计
            if self.cpu_samples:
                # 过滤掉异常值（超过100%的CPU使用率）
                valid_cpu_samples = [cpu for cpu in self.cpu_samples if cpu <= 100]
                if valid_cpu_samples:
                    summary['cpu_usage'] = {
                        'average_percent': statistics.mean(valid_cpu_samples),
                        'peak_percent': max(valid_cpu_samples),
                        'min_percent': min(valid_cpu_samples)
                    }
                    
            # 处理统计
            summary['processing_stats'] = {
                'total_frames': self.processed_frames,
                'total_alerts': self.total_alerts,
                'alert_rate_percent': (self.total_alerts / self.processed_frames * 100) if self.processed_frames > 0 else 0
            }
            
            return summary
            
    def log_performance_assessment(self, logger):
        """Log performance assessment to logger"""
        summary = self.get_performance_summary()
        
        logger.info("System Performance and Resource Consumption Assessment Report")
        
        if 'initialization_time_sec' in summary:
            logger.info(f"Initialization Time: {summary['initialization_time_sec']:.3f} seconds")
        if 'detection_duration_sec' in summary:
            logger.info(f"Detection Runtime: {summary['detection_duration_sec']:.3f} seconds")
        if 'throughput_fps' in summary:
            logger.info(f"Processing Throughput: {summary['throughput_fps']:.2f} frames/sec")
            
        # Detection Performance
        if 'detection_latency' in summary:
            latency = summary['detection_latency']
            logger.info(f"Average Latency: {latency['mean_ms']:.3f} ms")
            logger.info(f"Median Latency: {latency['median_ms']:.3f} ms")
            logger.info(f"95th Percentile: {latency['p95_ms']:.3f} ms")
            logger.info(f"99th Percentile: {latency['p99_ms']:.3f} ms")
            logger.info(f"Maximum Latency: {latency['max_ms']:.3f} ms")
            
        # Memory Usage
        if 'memory_usage' in summary:
            memory = summary['memory_usage']
            logger.info(f"Baseline Memory Usage: {memory['baseline_mb']:.2f} MB")
            logger.info(f"Average Memory Usage: {memory['average_mb']:.2f} MB")
            logger.info(f"Peak Memory Usage: {memory['peak_mb']:.2f} MB")
            logger.info(f"Memory Growth: {memory['growth_mb']:.2f} MB")
            
        # CPU Usage
        if 'cpu_usage' in summary:
            cpu = summary['cpu_usage']
            logger.info(f"Average CPU Usage: {cpu['average_percent']:.2f}%")
            logger.info(f"Peak CPU Usage: {cpu['peak_percent']:.2f}%")
            logger.info(f"Minimum CPU Usage: {cpu['min_percent']:.2f}%")
            
        # Processing Statistics
        if 'processing_stats' in summary:
            stats = summary['processing_stats']
            logger.info(f"Total Frames Processed: {stats['total_frames']:,}")
            logger.info(f"Total Alerts Generated: {stats['total_alerts']:,}")
            logger.info(f"Alert Rate: {stats['alert_rate_percent']:.3f}%")
            logger.info("")
            
        logger.info("="*80)
        logger.info("Performance Assessment Report End")
        logger.info("="*80)


class MemoryMonitor:
    """内存监控器"""

    def __init__(self, warning_threshold=0.8, critical_threshold=0.9):
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold

    def check_memory_pressure(self):
        """检查内存压力"""
        memory_percent = psutil.virtual_memory().percent / 100.0

        if memory_percent > self.critical_threshold:
            return 'critical'
        elif memory_percent > self.warning_threshold:
            return 'warning'
        else:
            return 'normal'
    
    def notify_detectors_memory_pressure(self, detectors: list, pressure_mode: bool):
        """
        通知所有检测器内存压力状态变化（解决问题4）
        
        Args:
            detectors: 检测器列表
            pressure_mode: 是否启用内存压力模式
        """
        for detector in detectors:
            if hasattr(detector, 'set_memory_pressure_mode'):
                try:
                    detector.set_memory_pressure_mode(pressure_mode)
                except Exception as e:
                    logger.warning(f"Failed to set memory pressure mode for {detector.__class__.__name__}: {e}")


def main():
    """主函数"""
    global system_components

    # 解析命令行参数
    args = parse_arguments()

    # 设置日志
    logger = setup_logging(args)

    # 注册信号处理器
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        logger.info("=" * 50)
        logger.info("CAN Bus Intrusion Detection System Starting")
        logger.info("=" * 50)
        logger.info(f"Mode: {args.mode}")
        logger.info(f"Input: {args.input} ({args.input_format})")
        logger.info(f"Config: {args.config}")
        logger.info(f"Output: {args.output_dir}")

        # 初始化组件
        system_components = initialize_components(args, logger)

        # 运行学习阶段
        if args.mode in ['learn', 'auto']:
            success = run_learning_phase(system_components, args, logger)
            if not success and args.mode == 'auto':
                logger.error("Learning phase failed, cannot proceed to detection")
                return 1

        # 运行检测阶段
        if args.mode in ['detect', 'auto'] and not shutdown_flag:
            run_detection_phase(system_components, args, logger)

        logger.info("System shutdown completed successfully")
        return 0

    except KeyboardInterrupt:
        logger.info("System interrupted by user")
        return 0
    except Exception as e:
        logger.error(f"System error: {e}", exc_info=True)
        return 1
    finally:
        # 清理资源
        if system_components:
            cleanup_resources(system_components, logger)


if __name__ == "__main__":
    sys.exit(main())
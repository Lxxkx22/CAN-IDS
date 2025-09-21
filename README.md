# CAN总线入侵检测系统 (IDS4.0)

一个先进的CAN总线入侵检测系统，支持实时监听和离线分析，能够检测多种类型的CAN总线攻击。

## 🚀 主要特性

- **多种输入模式**：支持文件分析和实时CAN总线监听
- **智能学习**：自动学习正常CAN流量模式
- **多重检测**：支持篡改、重放、丢包和通用规则检测
- **实时告警**：即时检测和报告异常行为
- **跨平台支持**：支持Linux SocketCAN和Windows CAN设备
- **高性能**：批量处理和内存优化

## 📋 系统要求

- Python 3.8+
- 支持的操作系统：Linux, Windows
- CAN硬件接口（用于实时监听）

## 🛠️ 安装

### 1. 克隆项目
```bash
git clone <repository-url>
cd IDS4.0
```

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. CAN硬件驱动（可选）
根据你的CAN硬件安装相应驱动：
- **Vector**: CANoe/CANalyzer驱动
- **PEAK**: PCAN驱动
- **Kvaser**: Kvaser驱动
- **IXXAT**: IXXAT驱动

## 🚀 快速开始

### 文件分析模式

```bash
# 自动模式：先学习后检测
python main.py -i data/can_trace.log -c config.json --mode auto

# 仅学习模式
python main.py -i data/can_trace.log --mode learn --learning-duration 120

# 仅检测模式
python main.py -i data/can_trace.log --mode detect
```

### 实时CAN总线监听 🆕

```bash
# Linux SocketCAN
python main.py -i can0 --input-format socketcan --real-time --mode auto

# Windows CAN设备
python main.py -i 0 --input-format socketcan --real-time --mode detect

# 带详细日志的实时监听
python main.py -i can0 --input-format socketcan --real-time --mode auto --verbose
```

## 📖 详细文档

- **[CAN总线设置指南](CAN_SETUP.md)** - 实时监听配置详解
- **[配置文件说明](CONFIG_README.md)** - 系统配置详细说明
- **[测试文档](tests/README.md)** - 测试框架和用例

## 🔧 配置

系统使用JSON配置文件控制行为。主要配置项：

```json
{
  "learning_params": {
    "initial_learning_window_sec": 300,
    "min_frames_for_learning": 100
  },
  "detection_params": {
    "entropy_threshold": 3.0,
    "replay_window_sec": 10.0
  },
  "alerting": {
    "enabled": true,
    "output_format": "json"
  }
}
```

## 🎯 检测能力

### 1. 篡改检测 (TamperDetector)
- 载荷熵异常检测
- 统计学习和sigma偏差分析
- 自适应阈值调整

### 2. 重放检测 (ReplayDetector)
- 时间窗口内的重复帧检测
- 载荷哈希比较
- 可配置检测窗口

### 3. 丢包检测 (DropDetector)
- 周期性帧丢失检测
- 自适应间隔学习
- 异常间隔告警

### 4. 通用规则检测 (GeneralRulesDetector)
- 自定义检测规则
- 模式匹配
- 阈值检测

## 📊 输出格式

### 告警输出
系统生成详细的JSON格式告警：

```json
{
  "alert_type": "entropy_anomaly",
  "can_id": "0x0316",
  "timestamp": 0.0,
  "severity": "medium",
  "details": "Entropy anomaly detected...",
  "detection_context": {
    "current_entropy": 2.75,
    "learned_mean_entropy": 2.99,
    "detector": "TamperDetector"
  }
}
```

### 日志文件
- `logs/system.log` - 系统运行日志
- `logs/alerts.log` - 告警日志
- `logs/alerts.json` - JSON格式告警

## 🔍 命令行选项

```bash
python main.py [选项]

必需参数:
  -i, --input           输入文件或CAN接口

可选参数:
  -c, --config          配置文件路径
  --mode               运行模式 (learn/detect/auto)
  --input-format       输入格式 (file/socketcan/candump)
  --real-time          启用实时处理
  --learning-duration  学习持续时间（秒）
  --batch-size         批处理大小
  --memory-limit       内存限制（MB）
  --log-level          日志级别
  --verbose            详细输出
  --dry-run            演练模式（不生成告警）
```

## 🧪 测试

运行完整测试套件：

```bash
# 运行所有测试
python -m pytest tests/

# 运行特定测试
python -m pytest tests/test_tamper_detector.py

# 生成覆盖率报告
python -m pytest tests/ --cov=. --cov-report=html
```

## 📈 性能优化

### 实时监听优化
- 批量处理：`--batch-size 1000`
- 内存限制：`--memory-limit 2048`
- 统计间隔：`--stats-interval 60`

### 内存管理
- 自动内存压力检测
- 定期数据清理
- 可配置保留策略

## 🔒 安全考虑

- 在生产环境使用前充分测试
- 定期备份学习数据
- 监控系统资源使用
- 设置合适的告警阈值

## 🤝 贡献

欢迎提交Issue和Pull Request！

1. Fork项目
2. 创建特性分支
3. 提交更改
4. 推送到分支
5. 创建Pull Request

## 📄 许可证

本项目采用MIT许可证 - 查看[LICENSE](LICENSE)文件了解详情。

## 🆘 支持

如遇问题，请：

1. 查看[CAN设置指南](CAN_SETUP.md)
2. 检查系统日志
3. 提交Issue并附上日志信息

## 📝 更新日志

### v4.0 🆕
- ✅ 新增实时CAN总线监听支持
- ✅ 支持多种CAN硬件接口
- ✅ 改进的内存管理
- ✅ 增强的错误处理
- ✅ 完善的文档和示例

### v3.x
- 基础检测功能
- 文件分析模式
- 配置系统
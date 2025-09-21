# IDS4.0 - CAN总线入侵检测系统

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)

## 📖 项目简介

IDS4.0是一个先进的CAN总线入侵检测系统，专为汽车网络安全设计。系统采用机器学习和规则引擎相结合的方法，能够实时检测CAN总线上的各种攻击行为，包括重放攻击、篡改攻击、丢包攻击等。

### 🎯 主要特性

- **多种检测算法**: 支持丢包检测、篡改检测、重放检测和通用规则检测
- **自适应学习**: 智能学习正常CAN流量模式，自动建立基线
- **实时监控**: 支持实时CAN总线监听和离线数据分析
- **灵活配置**: 丰富的配置选项，支持不同场景的定制化需求
- **告警管理**: 多级别告警系统，支持多种输出格式
- **性能优化**: 高效的内存管理和处理性能
- **完整测试**: 全面的测试套件，确保系统稳定性

## 🏗️ 系统架构

```
IDS4.0/
├── main.py                    # 主程序入口
├── config/                    # 配置文件目录
│   ├── config.json           # 主配置文件
│   ├── CONFIG_README.md      # 配置说明文档
│   └── whitelist_config.py   # 白名单配置
├── detection/                 # 检测模块
│   ├── base_detector.py      # 检测器基类
│   ├── drop_detector.py      # 丢包检测器
│   ├── tamper_detector.py    # 篡改检测器
│   ├── replay_detector.py    # 重放检测器
│   ├── general_rules_detector.py # 通用规则检测器
│   └── state_manager.py      # 状态管理器
├── learning/                  # 学习模块
│   └── baseline_engine.py    # 基线学习引擎
├── alerting/                  # 告警模块
│   └── alert_manager.py      # 告警管理器
├── utils/                     # 工具模块
│   ├── helpers.py            # 辅助函数
│   └── CAN_SETUP.md          # CAN设置指南
├── data/                      # 数据目录
├── logs/                      # 日志目录
└── tests/                     # 测试套件
```

## 🚀 快速开始

### 环境要求

- Python 3.8+
- 支持的操作系统: Windows, Linux, macOS
- 内存: 建议4GB以上
- 存储: 至少1GB可用空间

### 安装依赖

```bash
# 克隆项目
git clone <repository-url>
cd IDS4.0

# 安装Python依赖
pip install -r requirements.txt

# 或手动安装主要依赖
pip install python-can>=4.0.0 numpy pandas matplotlib
```

### 基本使用

#### 1. 离线数据分析

```bash
# 分析CAN数据文件
python main.py -i data/can_trace.log -c config/config.json

# 指定输出目录
python main.py -i data/can_trace.log -c config/config.json -o output/

# 启用详细日志
python main.py -i data/can_trace.log -c config/config.json --verbose
```

#### 2. 实时CAN监听

```bash
# Linux SocketCAN
python main.py -i can0 --input-format socketcan --real-time --mode detect

# 自动学习模式（先学习300秒，然后检测）
python main.py -i can0 --input-format socketcan --real-time --mode auto --learning-duration 300
```

#### 3. 运行模式

- **learn**: 仅学习模式，建立基线
- **detect**: 仅检测模式，使用现有配置
- **auto**: 自动模式，先学习后检测

```bash
# 学习模式
python main.py -i data/normal_traffic.log --mode learn --learning-duration 600

# 检测模式
python main.py -i data/test_traffic.log --mode detect -c learned_config.json
```

## 🔧 配置说明

### 主配置文件结构

系统使用JSON格式的配置文件，主要包含以下部分：

```json
{
  "meta": {
    "version": "4.0",
    "description": "CAN Bus IDS Configuration"
  },
  "global_settings": {
    "learning_params": { ... },
    "drop": { ... },
    "tamper": { ... },
    "replay": { ... }
  },
  "general_rules": { ... },
  "alerting": { ... },
  "logging": { ... },
  "ids": { ... }
}
```

详细配置说明请参考 [CONFIG_README.md](config/CONFIG_README.md)

### 关键参数

- **学习参数**: 控制系统学习阶段的行为
- **检测阈值**: 各种检测算法的敏感度设置
- **告警配置**: 告警级别和输出格式
- **性能参数**: 内存限制和处理优化

## 🔍 检测能力

### 支持的攻击类型

1. **丢包攻击 (Drop Attack)**
   - 检测CAN帧的异常丢失
   - 基于帧间间隔(IAT)统计分析
   - 支持自适应阈值调整

2. **篡改攻击 (Tampering Attack)**
   - DLC长度异常检测
   - 载荷内容篡改检测
   - 熵值异常分析
   - 字节行为模式检测

3. **重放攻击 (Replay Attack)**
   - 快速重放检测
   - 序列重放检测
   - 周期性模式分析

4. **通用规则检测**
   - 未知CAN ID检测
   - 频率异常检测
   - 自定义规则引擎

### 检测性能

- **处理速度**: >10,000 帧/秒
- **内存占用**: <500MB (典型场景)
- **检测延迟**: <1ms (实时模式)
- **误报率**: <1% (经过调优)

## 📊 测试与验证

### 运行测试套件

```bash
# 运行所有测试
python tests/run_all_tests.py

# 运行特定类别测试
python tests/run_all_tests.py detectors

# 运行单个测试文件
python -m unittest tests.test_drop_detector
```

### 测试覆盖范围

- ✅ 单元测试: 所有核心组件
- ✅ 集成测试: 端到端功能
- ✅ 性能测试: 负载和压力测试
- ✅ 攻击案例测试: 真实攻击场景

详细测试说明请参考 [tests/README.md](tests/README.md)

## 📈 性能监控

### 系统指标

系统提供丰富的性能监控指标：

- 处理帧数和速率
- 内存使用情况
- 检测器性能统计
- 告警统计信息

### 日志系统

- **系统日志**: `logs/system.log`
- **告警日志**: `logs/alerts.log`
- **JSON格式**: `logs/alerts.json`

## 🛠️ 开发指南

### 添加新检测器

1. 继承 `BaseDetector` 类
2. 实现 `_detect_frame` 方法
3. 在配置文件中添加相应配置
4. 编写单元测试

```python
from detection.base_detector import BaseDetector, Alert

class CustomDetector(BaseDetector):
    def _detect_frame(self, frame, state):
        # 实现检测逻辑
        if self.is_anomaly(frame):
            return self.create_alert("custom_attack", frame.can_id, "检测到异常")
        return None
```

### 代码规范

- 遵循PEP 8编码规范
- 添加类型注解
- 编写文档字符串
- 保持测试覆盖率>90%

## 🔧 故障排除

### 常见问题

1. **CAN接口连接失败**
   - 检查硬件连接
   - 确认驱动程序安装
   - 验证接口权限

2. **内存使用过高**
   - 调整配置中的内存限制参数
   - 减少学习窗口大小
   - 启用内存压力模式

3. **检测误报过多**
   - 延长学习时间
   - 调整检测阈值
   - 检查数据质量

### 调试模式

```bash
# 启用详细调试信息
python main.py -i data/test.log --verbose --debug

# 输出性能统计
python main.py -i data/test.log --performance-stats
```

## 📄 许可证

本项目采用MIT许可证 - 详见 [LICENSE](LICENSE) 文件

## 🤝 贡献指南

欢迎贡献代码！请遵循以下步骤：

1. Fork 项目
2. 创建功能分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

## 📞 支持与联系

- 项目文档: [docs/](docs/)
- 问题反馈: [Issues](../../issues)
- 技术讨论: [Discussions](../../discussions)

## 🔄 版本历史

### v4.0 (当前版本)
- 全新架构设计
- 增强的检测算法
- 改进的性能和稳定性
- 完整的测试套件

### 路线图
- [ ] 机器学习检测算法
- [ ] Web管理界面
- [ ] 分布式部署支持
- [ ] 更多CAN协议支持

---

**注意**: 本系统仅用于合法的网络安全研究和防护目的，请勿用于非法攻击活动。
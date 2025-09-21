# Detection模块测试套件

这是为IDS4.0项目的detection模块设计的完整测试套件，包含单元测试、集成测试和性能测试。

## 📁 测试文件结构

```
tests/
├── __init__.py                    # 测试模块初始化
├── README.md                      # 本文档
├── run_all_tests.py              # 测试运行主脚本
├── test_settings.py               # 测试配置和设置
├── test_config.py                 # 模拟配置管理器
├── test_utils.py                  # 测试工具函数
├── test_base_detector.py          # BaseDetector和Alert类测试
├── test_drop_detector.py          # DropDetector测试
├── test_tamper_detector.py        # TamperDetector测试
├── test_replay_detector.py        # ReplayDetector测试
├── test_general_rules_detector.py # GeneralRulesDetector测试
├── test_state_manager.py          # StateManager测试
└── test_detection_integration.py  # 集成测试
```

## 🚀 快速开始

### 运行所有测试

```bash
# 在项目根目录下运行
python tests/run_all_tests.py
```

### 运行特定类别的测试

```bash
# 只运行基础组件测试
python tests/run_all_tests.py basic

# 只运行检测器测试
python tests/run_all_tests.py detectors

# 只运行集成测试
python tests/run_all_tests.py integration
```

### 运行单个测试文件

```bash
# 运行特定检测器的测试
python -m unittest tests.test_drop_detector
python -m unittest tests.test_tamper_detector
python -m unittest tests.test_replay_detector

# 运行特定测试类
python -m unittest tests.test_base_detector.TestAlert

# 运行特定测试方法
python -m unittest tests.test_drop_detector.TestDropDetector.test_normal_iat_detection
```

## 📋 测试覆盖范围

### 基础组件测试

#### Alert类 (`test_base_detector.py`)
- ✅ 告警对象创建和属性设置
- ✅ 告警转换为字典格式
- ✅ 告警字符串表示
- ✅ 告警严重性级别

#### BaseDetector类 (`test_base_detector.py`)
- ✅ 检测器初始化
- ✅ 告警创建功能
- ✅ 检测启用/禁用状态
- ✅ 配置缓存机制
- ✅ 检测前后处理钩子
- ✅ 抽象检测方法
- ✅ 内存压力模式
- ✅ 配置版本变更处理

#### StateManager类 (`test_state_manager.py`)
- ✅ 状态管理器初始化
- ✅ CAN ID状态创建和更新
- ✅ IAT计算和统计
- ✅ 载荷哈希管理
- ✅ 序列缓冲区管理
- ✅ 内存限制和清理
- ✅ 性能测试

### 检测器测试

#### DropDetector (`test_drop_detector.py`)
- ✅ 丢包检测器初始化
- ✅ IAT异常检测
- ✅ 连续丢失帧检测
- ✅ 最大IAT因子检测
- ✅ 学习模式和检测模式
- ✅ 特殊情况处理（DLC=0等）
- ✅ 性能测试

#### TamperDetector (`test_tamper_detector.py`)
- ✅ 篡改检测器初始化
- ✅ DLC异常检测
- ✅ 载荷熵异常检测
- ✅ 字节行为分析
- ✅ 字节变化率检测
- ✅ 基线数据依赖处理
- ✅ 性能测试

#### ReplayDetector (`test_replay_detector.py`)
- ✅ 重放检测器初始化
- ✅ 快速重放检测
- ✅ 增强快速重放检测
- ✅ 上下文载荷重复检测
- ✅ 序列重放检测
- ✅ 周期性模式识别
- ✅ 性能测试

#### GeneralRulesDetector (`test_general_rules_detector.py`)
- ✅ 通用规则检测器初始化
- ✅ 未知ID检测
- ✅ Shadow学习模式
- ✅ 自动添加ID功能
- ✅ 基线引擎集成
- ✅ 性能测试

### 集成测试 (`test_detection_integration.py`)

- ✅ 正常流量处理
- ✅ 多种攻击检测
- ✅ 检测器协同工作
- ✅ 状态一致性
- ✅ 告警严重性分布
- ✅ 错误处理
- ✅ 内存使用稳定性
- ✅ 性能比较

## 🔧 测试配置

测试配置位于 `test_settings.py` 文件中，包含：

- **检测器配置**: 各个检测器的参数设置
- **性能测试配置**: 性能测试的阈值和限制
- **攻击模拟配置**: 模拟攻击的参数
- **测试数据配置**: 测试用的CAN ID和载荷模式
- **基线数据配置**: 模拟的基线引擎数据

## 🎯 测试工具

### 测试工具函数 (`test_utils.py`)

- `create_test_frame()`: 创建测试用CAN帧
- `create_frame_sequence()`: 创建CAN帧序列
- `create_drop_attack_frames()`: 生成丢包攻击序列
- `create_tamper_attack_frames()`: 生成篡改攻击序列
- `create_replay_attack_frames()`: 生成重放攻击序列
- `create_unknown_id_frames()`: 生成未知ID序列

### 模拟组件 (`test_config.py`)

- `MockConfigManager`: 模拟配置管理器
- `create_mock_baseline_engine()`: 创建模拟基线引擎

## 📊 测试报告

运行测试后会生成详细的测试报告，包括：

- ✅ 成功的测试数量和百分比
- ❌ 失败的测试详情
- ⚠️ 跳过的测试原因
- ⏱️ 测试执行时间
- 🎨 彩色输出便于查看结果

## 🔍 调试测试

### 增加详细输出

```bash
# 使用-v参数增加详细输出
python -m unittest -v tests.test_drop_detector
```

### 运行特定测试进行调试

```bash
# 只运行失败的测试
python -m unittest tests.test_drop_detector.TestDropDetector.test_abnormal_iat_detection
```

### 使用Python调试器

```python
# 在测试代码中添加断点
import pdb; pdb.set_trace()
```

## 📈 性能测试

性能测试包含在各个测试文件中，主要测试：

- **处理速度**: 每秒处理的帧数
- **内存使用**: 内存增长和清理
- **响应时间**: 检测延迟
- **扩展性**: 大数据集处理能力

### 性能基准

- 最小处理速度: 1000帧/秒
- 最大内存增长: 1MB
- 最大处理延迟: 1ms/帧

## 🚨 常见问题

### 导入错误

如果遇到模块导入错误，确保：

1. 在项目根目录下运行测试
2. Python路径包含项目根目录
3. 所有依赖模块已正确安装

### 测试失败

如果测试失败：

1. 检查错误信息和堆栈跟踪
2. 确认测试环境配置正确
3. 检查是否有代码变更影响了测试
4. 运行单个测试进行调试

### 性能测试失败

如果性能测试失败：

1. 检查系统负载
2. 调整性能阈值（在test_settings.py中）
3. 确认测试环境的硬件配置

## 🔄 持续集成

这个测试套件设计为可以轻松集成到CI/CD流水线中：

```bash
# CI脚本示例
#!/bin/bash
set -e

# 运行所有测试
python tests/run_all_tests.py

# 检查测试覆盖率（如果安装了coverage）
# coverage run -m unittest discover tests
# coverage report
```

## 📝 贡献指南

添加新测试时请遵循以下规范：

1. **命名规范**: 测试文件以`test_`开头，测试方法以`test_`开头
2. **文档字符串**: 每个测试方法都应有清晰的文档字符串
3. **断言消息**: 使用有意义的断言消息
4. **测试隔离**: 确保测试之间相互独立
5. **清理资源**: 在tearDown中清理测试资源

### 测试模板

```python
def test_new_feature(self):
    """测试新功能的描述"""
    # Arrange - 准备测试数据
    test_data = create_test_data()
    
    # Act - 执行被测试的操作
    result = function_under_test(test_data)
    
    # Assert - 验证结果
    self.assertEqual(result, expected_value, "详细的错误消息")
```

## 📞 支持

如果在使用测试套件时遇到问题，请：

1. 查看本README文档
2. 检查测试配置文件
3. 查看具体的测试代码实现
4. 提交issue描述问题

---

**注意**: 这个测试套件是为IDS4.0项目的detection模块专门设计的，确保在正确的项目环境中运行。
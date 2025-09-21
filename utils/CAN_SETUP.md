# CAN总线实时监听设置指南

本文档说明如何配置IDS4.0系统以支持实时CAN总线监听。

## 1. 安装依赖

首先安装必要的Python库：

```bash
pip install -r requirements.txt
```

或者单独安装CAN库：

```bash
pip install python-can>=4.0.0
```

## 2. 硬件支持

系统支持多种CAN接口硬件：

### Linux系统 (SocketCAN)
- 原生SocketCAN支持
- USB-CAN适配器
- 内置CAN控制器

### Windows系统
- **Vector CANoe/CANalyzer**: 专业CAN分析工具
- **PEAK CAN**: PCAN-USB等设备
- **Kvaser**: Kvaser Leaf等设备
- **IXXAT**: IXXAT USB-to-CAN等设备

## 3. 使用方法

### 基本语法

```bash
python main.py -i <CAN接口> --input-format socketcan --real-time [其他选项]
```

### 示例命令

#### Linux SocketCAN
```bash
# 监听can0接口并进行检测
python main.py -i can0 --input-format socketcan --real-time --mode detect

# 先学习后检测（自动模式）
python main.py -i can0 --input-format socketcan --real-time --mode auto --learning-duration 300

# 仅学习模式
python main.py -i can0 --input-format socketcan --real-time --mode learn --learning-duration 120
```

#### Windows CAN设备
```bash
# Vector CANoe (通道0)
python main.py -i 0 --input-format socketcan --real-time --mode detect

# PEAK CAN (PCAN_USBBUS1)
python main.py -i PCAN_USBBUS1 --input-format socketcan --real-time --mode detect

# Kvaser (通道0)
python main.py -i 0 --input-format socketcan --real-time --mode detect
```

## 4. 配置说明

### 重要参数

- `--input-format socketcan`: 指定使用CAN总线输入
- `--real-time`: 启用实时处理模式
- `--mode`: 运行模式
  - `learn`: 仅学习模式
  - `detect`: 仅检测模式
  - `auto`: 先学习后检测
- `--learning-duration`: 学习阶段持续时间（秒）

### 性能调优

```bash
# 调整批处理大小以优化性能
python main.py -i can0 --input-format socketcan --real-time --batch-size 500

# 设置内存限制
python main.py -i can0 --input-format socketcan --real-time --memory-limit 2048

# 启用详细日志
python main.py -i can0 --input-format socketcan --real-time --log-level DEBUG --verbose
```

## 5. 故障排除

### 常见问题

#### 1. 找不到CAN接口
```
RuntimeError: Failed to connect to CAN interface can0 with any available driver
```

**解决方案：**
- 检查CAN接口是否存在：`ip link show` (Linux)
- 确认硬件连接正常
- 检查驱动程序是否安装

#### 2. 权限问题 (Linux)
```
PermissionError: [Errno 1] Operation not permitted
```

**解决方案：**
```bash
# 添加用户到can组
sudo usermod -a -G dialout $USER

# 或使用sudo运行
sudo python main.py -i can0 --input-format socketcan --real-time
```

#### 3. python-can库未安装
```
ImportError: python-can library is required for SocketCAN support
```

**解决方案：**
```bash
pip install python-can
```

### 调试模式

启用详细日志以诊断问题：

```bash
python main.py -i can0 --input-format socketcan --real-time --log-level DEBUG --verbose
```

## 6. 性能考虑

### 实时性能

- 系统会自动尝试多种CAN接口驱动
- 实时模式下添加1ms延迟以避免CPU占用过高
- 支持批量处理以提高效率

### 内存管理

- 定期清理旧数据
- 支持内存压力检测和自动清理
- 可配置内存限制

## 7. 与文件模式的兼容性

系统完全向后兼容，仍支持文件输入模式：

```bash
# 传统文件模式
python main.py -i data/can_trace.log --input-format file --mode auto

# 混合使用：先从文件学习，再实时检测
python main.py -i data/baseline.log --mode learn
python main.py -i can0 --input-format socketcan --real-time --mode detect
```

## 8. 安全建议

- 在生产环境中使用前，先在测试环境验证
- 定期备份学习到的基线数据
- 监控系统资源使用情况
- 设置适当的告警阈值

## 9. 技术支持

如遇到问题，请检查：

1. 系统日志：`logs/system.log`
2. 告警日志：`logs/alerts.log`
3. 硬件连接状态
4. 驱动程序版本

更多技术细节请参考项目文档和源代码注释。
# IDS4.0 配置文件说明

本文档详细说明了CAN总线入侵检测系统(IDS4.0)的配置文件结构和使用方法。

## 配置文件概述

系统使用JSON格式的配置文件来控制各个组件的行为。配置文件包含以下主要部分：

- **meta**: 元数据信息
- **global_settings**: 全局设置
- **general_rules**: 通用检测规则
- **alerting**: 告警配置
- **logging**: 日志配置
- **data_sources**: 数据源配置
- **ids**: CAN ID特定配置
- **system**: 系统运行时配置

## 快速开始

1. 复制 `config_template.json` 为你的配置文件（如 `config.json`）
2. 根据你的需求修改配置参数
3. 使用 `-c` 参数指定配置文件：
   ```bash
   python main.py -i data/can_trace.log -c config.json
   ```

## 配置部分详解

### 1. 元数据 (meta)

```json
{
  "meta": {
    "version": "4.0",
    "description": "配置文件描述",
    "author": "作者信息",
    "created_date": "创建日期",
    "analysis_info": {
      "total_frames": 0,
      "unique_ids": 0
    }
  }
}
```

### 2. 学习参数 (learning_params)

控制系统的学习阶段行为：

- `initial_learning_window_sec`: 初始学习窗口时间（秒）
- `baseline_update_interval_sec`: 基线更新间隔（秒）
- `min_samples_for_stable_baseline`: 稳定基线所需的最小样本数
- `adaptive_learning_enabled`: 是否启用自适应学习

### 3. 丢包检测 (drop)

检测CAN帧丢失攻击：

- `missing_frame_sigma`: 丢帧检测的sigma阈值
- `consecutive_missing_allowed`: 允许的连续丢帧数
- `max_iat_factor`: 最大帧间间隔因子
- `treat_dlc_zero_as_special`: 是否将DLC为0的帧特殊处理

### 4. 篡改检测 (tamper)

检测CAN帧内容篡改：

#### DLC检测
- `dlc_learning_mode`: DLC学习模式（"strict_whitelist" 或 "adaptive"）
- `payload_analysis_min_dlc`: 载荷分析的最小DLC值

#### 熵分析
```json
"entropy_params": {
  "enabled": true,
  "learning_mode": "per_id_baseline",
  "sigma_threshold": 3.0,
  "min_entropy_samples": 100
}
```

#### 字节行为分析
```json
"byte_behavior_params": {
  "enabled": true,
  "learning_window_min_changes_for_variable": 5,
  "static_byte_mismatch_threshold": 1,
  "counter_byte_params": {
    "detect_simple_counters": true,
    "max_value_before_rollover_guess": 255,
    "allowed_counter_skips": 1
  }
}
```

### 5. 重放检测 (replay)

检测CAN帧重放攻击：

- `min_iat_factor_for_fast_replay`: 快速重放检测的最小IAT因子
- `absolute_min_iat_ms`: 绝对最小帧间间隔（毫秒）

#### 相同载荷检测
```json
"identical_payload_params": {
  "enabled": true,
  "time_window_ms": 1000,
  "repetition_threshold": 4
}
```

#### 序列重放检测
```json
"sequence_replay_params": {
  "enabled": true,
  "sequence_length": 5,
  "max_sequence_age_sec": 300,
  "min_interval_between_sequences_sec": 10
}
```

### 6. 告警限流 (throttle)

控制告警频率，防止告警风暴：

- `max_alerts_per_id_per_sec`: 每个ID每秒最大告警数
- `global_max_alerts_per_sec`: 全局每秒最大告警数
- `cooldown_ms`: 告警冷却时间（毫秒）

### 7. 通用规则 (general_rules)

#### 未知ID检测
```json
"detect_unknown_id": {
  "enabled": true,
  "learning_mode": "shadow",
  "shadow_duration_sec": 600,
  "auto_add_to_baseline": true
}
```

### 8. 告警配置 (alerting)

#### 输出格式
```json
"output_formats": {
  "console": {
    "enabled": true,
    "format_type": "text",
    "include_context": true
  },
  "file": {
    "enabled": true,
    "format_type": "text",
    "include_frame_data": true
  },
  "json_file": {
    "enabled": true,
    "format_type": "json"
  }
}
```

#### 严重级别配置
- `low`: 低级别告警
- `medium`: 中级别告警
- `high`: 高级别告警
- `critical`: 关键告警

### 9. CAN ID特定配置 (ids)

为特定的CAN ID配置个性化参数：

```json
"0x123": {
  "description": "引擎控制单元",
  "enabled": true,
  "priority": "high",
  "drop": {
    "custom_threshold_sigma": 2.5
  },
  "tamper": {
    "learned_dlcs": [8],
    "custom_rules": []
  },
  "metadata": {
    "ecu_name": "Engine ECU",
    "critical_system": true
  }
}
```

## 配置最佳实践

### 1. 学习阶段配置

- **初始部署**: 设置较长的学习窗口（120-300秒）
- **生产环境**: 可以缩短学习窗口（60-120秒）
- **高流量环境**: 增加 `min_samples_for_stable_baseline`

### 2. 检测敏感度调整

- **高敏感度**: 降低sigma阈值（2.0-2.5）
- **低误报**: 提高sigma阈值（3.5-4.0）
- **平衡模式**: 使用默认值（3.0-3.5）

### 3. 性能优化

- **高性能**: 增加 `batch_processing_size`
- **低内存**: 减少 `cache_size_limit`
- **实时处理**: 启用 `adaptive_learning_enabled`

### 4. 告警管理

- **生产环境**: 启用文件和JSON输出，关闭控制台输出
- **调试模式**: 启用所有输出格式
- **高流量**: 适当提高告警限流参数

## 配置验证

系统启动时会自动验证配置文件：

1. **JSON格式验证**: 检查语法正确性
2. **结构验证**: 检查必需的配置节
3. **数值范围验证**: 检查参数值的合理性
4. **逻辑一致性验证**: 检查配置间的逻辑关系

## 故障排除

### 常见配置错误

1. **JSON语法错误**: 检查括号、逗号、引号匹配
2. **数值超出范围**: 检查sigma值、时间间隔等参数
3. **缺少必需配置**: 确保包含所有必需的配置节
4. **类型不匹配**: 确保数值类型正确（整数vs浮点数）

### 调试技巧

1. 使用 `--log-level DEBUG` 查看详细日志
2. 检查 `logs/system.log` 中的配置验证信息
3. 使用 `--dry-run` 模式测试配置
4. 运行配置验证测试：`python -m pytest tests/test_config_validation.py`

## 配置文件示例

### 基础配置示例

适用于初次部署和测试：

```json
{
  "meta": {
    "version": "4.0",
    "description": "Basic IDS Configuration"
  },
  "global_settings": {
    "learning_params": {
      "initial_learning_window_sec": 120,
      "min_samples_for_stable_baseline": 50
    },
    "drop": {
      "missing_frame_sigma": 3.0
    },
    "tamper": {
      "entropy_params": {
        "enabled": true,
        "sigma_threshold": 3.0
      }
    }
  }
}
```

### 生产环境配置示例

适用于生产环境部署：

```json
{
  "global_settings": {
    "learning_params": {
      "initial_learning_window_sec": 60,
      "min_samples_for_stable_baseline": 200
    },
    "throttle": {
      "max_alerts_per_id_per_sec": 1,
      "global_max_alerts_per_sec": 10
    }
  },
  "alerting": {
    "output_formats": {
      "console": {"enabled": false},
      "file": {"enabled": true},
      "json_file": {"enabled": true}
    }
  }
}
```

## 版本兼容性

- **4.0**: 当前版本，支持所有功能
- **3.x**: 部分配置项可能不兼容
- **2.x**: 需要配置迁移

## 更多信息

- 查看 `tests/test_config_validation.py` 了解配置验证规则
- 查看 `config_loader.py` 了解配置加载逻辑
- 查看各检测器源码了解具体参数含义
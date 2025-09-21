# CAN总线入侵检测系统攻击案例文档

## 概述
本文档详细说明了在 `mixed_traffic_with_attacks.txt` 文件中设计的各种攻击案例，以及系统的检测机制。

## 攻击案例列表

### 1. 未知ID攻击 (Unknown ID Attack)
**攻击帧:** `0x0999ATK`  
**时间戳:** 0.063494s  
**载荷:** AA BB CC DD EE FF 00 11  
**检测器:** GeneralRulesDetector  
**检测类型:** unknown_id_detected  
**严重级别:** MEDIUM  
**原理:** 系统配置中不存在ID 0x0999，触发未知ID检测

### 2. 重放攻击 (Replay Attack)
**攻击帧:** `0x0316ATK`  
**时间戳:** 0.090462s, 0.148180s, 0.152809s, 0.162129s等  
**载荷:** 05 20 ea 0a 20 1a 00 7f (相同载荷)  
**检测器:** ReplayDetector  
**检测类型:** non_periodic_fast_replay  
**严重级别:** LOW  
**原理:** 在短时间内重复发送相同载荷，违反正常通信模式

### 3. DLC篡改攻击 (DLC Tampering)
**攻击帧:** `0x0316ATK`  
**时间戳:** 0.301665s  
**DLC:** 4 (学习值为8)  
**检测器:** TamperDetector  
**检测类型:** tamper_dlc_anomaly  
**严重级别:** HIGH  
**原理:** DLC从学习的8字节变为4字节，违反严格白名单模式

### 4. 熵值异常攻击 (Entropy Anomaly)
**攻击帧:** `0x0316ATK`  
**时间戳:** 0.301665s  
**载荷:** 05 20 ea 0a (熵值2.000)  
**检测器:** TamperDetector  
**检测类型:** entropy_anomaly  
**严重级别:** MEDIUM  
**原理:** 熵值2.000偏离学习均值2.793±0.178超过3σ阈值

### 5. 载荷篡改攻击 (Payload Tampering)
**攻击帧:** `0x0316ATK`  
**时间戳:** 0.351648s  
**载荷:** 99 20 ea 0a 20 1a 00 7f  
**检测器:** TamperDetector  
**检测类型:** 字节行为异常  
**严重级别:** MEDIUM  
**原理:** 第0字节从05变为99，违反字节行为模式

### 6. 静态字节篡改攻击 (Static Byte Tampering)
**攻击帧:** `0x0153ATK`  
**时间戳:** 0.441893s  
**载荷:** FF 80 10 ff 00 ff 40 ce  
**检测器:** TamperDetector  
**检测类型:** static_byte_mismatch  
**严重级别:** HIGH  
**原理:** 第0字节应为0x00(静态)，但攻击帧设为0xFF

### 7. 序列重放攻击 (Sequence Replay)
**攻击帧:** `0x0164ATK`  
**时间戳:** 0.541225s-0.815786s (连续5帧)  
**载荷:** 00 08 00 00 00 00 01 09 (相同载荷)  
**检测器:** ReplayDetector  
**检测类型:** sequence_replay  
**严重级别:** MEDIUM  
**原理:** 在短时间内重复发送相同载荷序列

### 8. DLC异常攻击 (DLC Anomaly)
**攻击帧:** `0x0220ATK`  
**时间戳:** 0.859559s  
**DLC:** 2 (学习值为8)  
**检测器:** TamperDetector  
**检测类型:** tamper_dlc_anomaly  
**严重级别:** HIGH  
**原理:** DLC从学习的8字节变为2字节

### 9. 字节值异常攻击 (Byte Value Anomaly)
**攻击帧:** `0x02a0ATK`  
**时间戳:** 0.883895s  
**载荷:** 62 00 60 9d db 0c ba FF  
**检测器:** TamperDetector  
**检测类型:** byte_behavior_anomaly  
**严重级别:** MEDIUM  
**原理:** 第7字节从正常值变为0xFF，违反字节行为模式

### 10. 全字节异常攻击 (All Bytes Anomaly)
**攻击帧:** `0x0329ATK`, `0x0220ATK`  
**时间戳:** 0.910761s, 0.938214s  
**载荷:** FF FF FF FF FF FF FF FF  
**检测器:** TamperDetector  
**检测类型:** byte_behavior_anomaly  
**严重级别:** HIGH  
**原理:** 所有字节都设为0xFF，严重违反正常载荷模式

## 系统配置要求

### 全局检测参数
- **DLC学习模式:** strict_whitelist
- **熵值检测:** 启用，3σ阈值
- **字节行为分析:** 启用
- **重放检测:** 启用，最小IAT因子0.3
- **丢帧检测:** 启用，最大IAT因子2.5

### 关键配置项
```json
"tamper": {
  "dlc_learning_mode": "strict_whitelist",
  "entropy_params": {
    "enabled": true,
    "sigma_threshold": 3.0
  },
  "byte_behavior_params": {
    "enabled": true,
    "static_byte_mismatch_threshold": 1
  }
},
"replay": {
  "min_iat_factor_for_fast_replay": 0.3,
  "identical_payload_params": {
    "enabled": true,
    "repetition_threshold": 4
  }
},
"drop": {
  "max_iat_factor": 2.5,
  "missing_frame_sigma": 3.5
}
```

## 预期检测结果

总计应检测到约12-15条告警，涵盖以下检测类型：
1. unknown_id_detected (1条)
2. non_periodic_fast_replay (3条)
3. tamper_dlc_anomaly (3条)
4. entropy_anomaly (2条)
5. iat_max_factor_violation (3条)
6. static_byte_mismatch (1条)
7. byte_behavior_anomaly (2条)

## 注意事项

1. **时间戳顺序:** 攻击帧的时间戳必须保持递增顺序
2. **配置依赖:** 某些检测需要对应ID的学习数据存在于配置文件中
3. **阈值调整:** 可根据需要调整检测阈值以平衡检测率和误报率
4. **载荷设计:** 攻击载荷应基于正常载荷进行有针对性的修改

## 更新日志

- **2025-06-12:** 初始版本，包含10种攻击类型
- **2025-06-12:** 添加丢帧攻击和字节篡改攻击案例
- **2025-06-12:** 优化重放攻击时间间隔，减少误报
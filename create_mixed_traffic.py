import random
import re

def extract_timestamp(line):
    """从CAN帧行中提取时间戳"""
    match = re.search(r'Timestamp:\s*([0-9.]+)', line)
    if match:
        return float(match.group(1))
    return None

def update_timestamp_in_line(line, new_timestamp):
    """更新CAN帧行中的时间戳"""
    return re.sub(r'Timestamp:\s*[0-9.]+', f'Timestamp: {new_timestamp:>15.6f}', line)

def extract_can_id(line):
    """从CAN帧行中提取CAN ID"""
    match = re.search(r'ID: (\w+)', line)
    if match:
        return match.group(1)
    return None

def create_mixed_traffic_file():
    """创建包含攻击数据的混合流量文件，攻击比例约2%，保持时间序列单调性
    对于丢弃攻击(0x0080)，通过删除正常帧实现；对于其他攻击，通过插入攻击帧实现"""
    
    # 读取正常流量文件
    print("读取正常流量文件...")
    with open('c:/Users/22254/PycharmProjects/IDS4.0/data/attack_free_simplified.txt', 'r') as f:
        normal_lines = f.readlines()
    
    # 读取攻击测试数据，提取攻击帧
    print("读取攻击测试数据...")
    with open('c:/Users/22254/PycharmProjects/IDS4.0/data/attack_test_data.txt', 'r') as f:
        attack_lines = f.readlines()
    
    # 提取攻击帧（包含ATK标识的行），排除0x0080ATK
    attack_frames = []
    drop_attack_frames = []
    for line in attack_lines:
        if 'ATK' in line:
            if '0080ATK' in line:
                drop_attack_frames.append(line.strip())
            else:
                attack_frames.append(line.strip())
    
    print(f"正常流量帧数: {len(normal_lines)}")
    print(f"非丢弃攻击帧数: {len(attack_frames)}")
    print(f"丢弃攻击帧数: {len(drop_attack_frames)}")
    
    # 找出所有0x0080的正常帧位置
    normal_0x0080_positions = []
    for i, line in enumerate(normal_lines):
        can_id = extract_can_id(line)
        if can_id and can_id.upper() == '0080':
            normal_0x0080_positions.append(i)
    
    print(f"正常0x0080帧数: {len(normal_0x0080_positions)}")
    
    # 计算攻击数量（2%比例）
    total_normal = len(normal_lines)
    target_attack_count = int(total_normal * 0.02)
    
    # 分配攻击类型：30%为丢弃攻击，70%为其他攻击
    drop_attack_count = int(target_attack_count * 0.3)
    other_attack_count = target_attack_count - drop_attack_count
    
    # 限制丢弃攻击数量不超过可用的0x0080帧数
    drop_attack_count = min(drop_attack_count, len(normal_0x0080_positions))
    other_attack_count = target_attack_count - drop_attack_count
    
    print(f"目标丢弃攻击数量: {drop_attack_count}")
    print(f"目标其他攻击数量: {other_attack_count}")
    
    # 生成随机位置
    random.seed(42)  # 固定种子确保可重现
    
    # 选择要删除的0x0080帧位置
    drop_positions = set()
    if drop_attack_count > 0 and normal_0x0080_positions:
        drop_positions = set(random.sample(normal_0x0080_positions, drop_attack_count))
    
    # 选择插入其他攻击帧的位置（排除要删除的位置）
    available_positions = [i for i in range(1, total_normal-1) if i not in drop_positions]
    insert_positions = set()
    if other_attack_count > 0 and available_positions:
        insert_positions = set(random.sample(available_positions, min(other_attack_count, len(available_positions))))
    
    print(f"删除位置示例: {sorted(list(drop_positions))[:10]}")
    print(f"插入位置示例: {sorted(list(insert_positions))[:10]}")
    
    # 创建其他攻击帧池
    other_attack_pool = []
    for i in range(other_attack_count):
        if attack_frames:
            other_attack_pool.append(attack_frames[i % len(attack_frames)])
    
    print("开始创建混合流量文件...")
    
    # 创建混合流量
    mixed_traffic = []
    insert_attack_index = 0
    dropped_frames_count = 0
    inserted_frames_count = 0
    
    for i, normal_line in enumerate(normal_lines):
        # 检查是否需要删除此帧（丢弃攻击）
        if i in drop_positions:
            dropped_frames_count += 1
            print(f"删除第{i}行的0x0080帧: {normal_line.strip()[:50]}...")
            continue  # 跳过此帧，实现丢弃攻击
        
        # 添加正常帧
        mixed_traffic.append(normal_line.rstrip())
        
        # 检查是否需要在此位置插入其他攻击帧
        if i in insert_positions and insert_attack_index < len(other_attack_pool):
            # 计算合适的攻击帧时间戳
            current_timestamp = extract_timestamp(normal_line)
            next_timestamp = None
            if i + 1 < len(normal_lines):
                next_timestamp = extract_timestamp(normal_lines[i + 1])
            
            if current_timestamp is not None and next_timestamp is not None:
                # 在当前帧和下一帧之间插入攻击帧
                attack_timestamp = current_timestamp + (next_timestamp - current_timestamp) * 0.5
            elif current_timestamp is not None:
                # 如果没有下一帧，在当前时间戳基础上增加小量
                attack_timestamp = current_timestamp + 0.001
            else:
                # 如果无法解析时间戳，使用默认值
                attack_timestamp = 0.001
            
            # 更新攻击帧的时间戳
            attack_frame = other_attack_pool[insert_attack_index]
            updated_attack_frame = update_timestamp_in_line(attack_frame, attack_timestamp)
            mixed_traffic.append(updated_attack_frame)
            insert_attack_index += 1
            inserted_frames_count += 1
    
    # 写入混合流量文件
    output_file = 'c:/Users/22254/PycharmProjects/IDS4.0/data/mixed_traffic_with_attacks.txt'
    print(f"写入混合流量文件: {output_file}")
    
    with open(output_file, 'w') as f:
        for line in mixed_traffic:
            f.write(line + '\n')
    
    print(f"混合流量文件创建完成！")
    print(f"总帧数: {len(mixed_traffic)}")
    print(f"原始正常帧数: {len(normal_lines)}")
    print(f"删除的帧数(丢弃攻击): {dropped_frames_count}")
    print(f"插入的攻击帧数: {inserted_frames_count}")
    print(f"总攻击数: {dropped_frames_count + inserted_frames_count}")
    print(f"攻击比例: {(dropped_frames_count + inserted_frames_count) / len(normal_lines) * 100:.2f}%")
    
    # 验证插入的攻击帧分布
    attack_count_by_type = {}
    for frame in other_attack_pool[:insert_attack_index]:
        if 'ID:' in frame:
            id_match = re.search(r'ID: (\w+)', frame)
            if id_match:
                attack_id = id_match.group(1)
                attack_count_by_type[attack_id] = attack_count_by_type.get(attack_id, 0) + 1
    
    print("\n攻击类型分布:")
    print(f"  丢弃攻击(删除0x0080帧): {dropped_frames_count} 次")
    print("  插入攻击帧分布:")
    for attack_id, count in attack_count_by_type.items():
        print(f"    {attack_id}: {count} 帧")
    
    return output_file

if __name__ == "__main__":
    create_mixed_traffic_file()
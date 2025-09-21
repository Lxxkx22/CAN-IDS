import re
import pandas as pd
from collections import defaultdict

def parse_test_log():
    # 读取测试日志文件
    with open(r'c:\Users\22254\PycharmProjects\IDS4.0\tests\comprehensive_test_log_20250608_111234_readable.txt', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 解析测试数据
    test_data = []
    current_file = ''
    
    # 按文件分割内容
    file_sections = re.split(r'文件: (.+?)\n-{60,}', content)
    
    for i in range(1, len(file_sections), 2):
        if i + 1 < len(file_sections):
            current_file = file_sections[i].strip()
            file_content = file_sections[i + 1]
            
            # 解析每个测试
            test_blocks = re.split(r'\s+测试 #\d+', file_content)
            
            for test_block in test_blocks[1:]:  # 跳过第一个空块
                lines = test_block.strip().split('\n')
                if len(lines) < 6:
                    continue
                
                test_info = {}
                test_info['文件名'] = current_file
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('类名:'):
                        test_info['类名'] = line.replace('类名:', '').strip()
                    elif line.startswith('方法:'):
                        test_info['方法名'] = line.replace('方法:', '').strip()
                    elif line.startswith('描述:'):
                        test_info['描述'] = line.replace('描述:', '').strip()
                    elif line.startswith('预期结果:'):
                        test_info['预期结果'] = line.replace('预期结果:', '').strip()
                    elif line.startswith('实际结果:'):
                        test_info['实际结果'] = line.replace('实际结果:', '').strip()
                    elif line.startswith('状态:'):
                        test_info['状态'] = line.replace('状态:', '').strip()
                    elif line.startswith('耗时:'):
                        test_info['耗时'] = line.replace('耗时:', '').strip()
                    elif line.startswith('时间:'):
                        test_info['时间'] = line.replace('时间:', '').strip()
                
                # 确保所有必要字段都存在
                if all(key in test_info for key in ['类名', '方法名', '描述', '预期结果', '实际结果']):
                    test_data.append(test_info)
    
    # 创建DataFrame
    df = pd.DataFrame(test_data)
    
    if df.empty:
        print("未能解析到测试数据")
        return
    
    # 按类名分组并保存到Excel
    excel_path = r'c:\Users\22254\PycharmProjects\IDS4.0\tests\测试结果汇总.xlsx'
    
    with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
        # 创建总览表
        df.to_excel(writer, sheet_name='总览', index=False)
        
        # 调整列宽
        worksheet = writer.sheets['总览']
        for column in worksheet.columns:
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)  # 最大宽度50
            worksheet.column_dimensions[column_letter].width = adjusted_width
        
        # 按类名创建分表
        for class_name in df['类名'].unique():
            class_df = df[df['类名'] == class_name]
            # 清理工作表名称
            safe_class_name = re.sub(r'[\\/*?:\[\]]', '_', str(class_name))[:31]
            class_df.to_excel(writer, sheet_name=safe_class_name, index=False)
            
            # 调整分表列宽
            if safe_class_name in writer.sheets:
                worksheet = writer.sheets[safe_class_name]
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column_letter].width = adjusted_width
    
    print(f'成功解析了 {len(test_data)} 个测试方法')
    print(f'涉及 {len(df["类名"].unique())} 个测试类')
    print(f'Excel文件已保存到: {excel_path}')
    
    # 显示统计信息
    print('\n各类测试方法数量统计:')
    class_counts = df['类名'].value_counts()
    for class_name, count in class_counts.items():
        print(f'  {class_name}: {count} 个方法')

if __name__ == '__main__':
    parse_test_log()
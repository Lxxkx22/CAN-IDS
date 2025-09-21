#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
全面测试运行器
详细记录每个测试方法的信息到日志文件
包括：用例名、测试方法、预期结果、实际结果
"""

import os
import sys
import subprocess
import time
import json
import re
import unittest
import importlib
import importlib.util
from pathlib import Path
from datetime import datetime
from io import StringIO


class TestResult:
    """测试结果记录"""
    def __init__(self):
        self.results = []
        
    def add_result(self, test_file, test_class, test_method, expected, actual, status, error=None, duration=0, description=None):
        """添加测试结果"""
        self.results.append({
            'timestamp': datetime.now().isoformat(),
            'test_file': test_file,
            'test_class': test_class,
            'test_method': test_method,
            'test_description': description or '',
            'expected_result': expected,
            'actual_result': actual,
            'status': status,
            'error_message': error,
            'duration_seconds': duration
        })


class DetailedTestResult(unittest.TestResult):
    """自定义测试结果收集器"""
    
    def __init__(self, test_recorder, test_file):
        super().__init__()
        self.test_recorder = test_recorder
        self.test_file = test_file
        self.start_times = {}
        
    def startTest(self, test):
        super().startTest(test)
        self.start_times[test] = time.time()
        
    def addSuccess(self, test):
        super().addSuccess(test)
        duration = time.time() - self.start_times.get(test, 0)
        test_method = getattr(test, test._testMethodName)
        description = self._extract_test_description(test_method)
        self.test_recorder.add_result(
            self.test_file,
            test.__class__.__name__,
            test._testMethodName,
            self._get_expected_result(test._testMethodName, test_method),
            "测试通过",
            "PASS",
            duration=duration,
            description=description
        )
        
    def addError(self, test, err):
        super().addError(test, err)
        duration = time.time() - self.start_times.get(test, 0)
        error_msg = self._format_error(err)
        test_method = getattr(test, test._testMethodName)
        description = self._extract_test_description(test_method)
        self.test_recorder.add_result(
            self.test_file,
            test.__class__.__name__,
            test._testMethodName,
            self._get_expected_result(test._testMethodName, test_method),
            f"测试错误: {error_msg}",
            "ERROR",
            error=error_msg,
            duration=duration,
            description=description
        )
        
    def addFailure(self, test, err):
        super().addFailure(test, err)
        duration = time.time() - self.start_times.get(test, 0)
        error_msg = self._format_error(err)
        test_method = getattr(test, test._testMethodName)
        description = self._extract_test_description(test_method)
        self.test_recorder.add_result(
            self.test_file,
            test.__class__.__name__,
            test._testMethodName,
            self._get_expected_result(test._testMethodName, test_method),
            f"测试失败: {error_msg}",
            "FAIL",
            error=error_msg,
            duration=duration,
            description=description
        )
        
    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        duration = time.time() - self.start_times.get(test, 0)
        test_method = getattr(test, test._testMethodName)
        description = self._extract_test_description(test_method)
        self.test_recorder.add_result(
            self.test_file,
            test.__class__.__name__,
            test._testMethodName,
            self._get_expected_result(test._testMethodName, test_method),
            f"测试跳过: {reason}",
            "SKIP",
            duration=duration,
            description=description
        )
        
    def _format_error(self, err):
        """格式化错误信息"""
        exc_type, exc_value, exc_traceback = err
        return f"{exc_type.__name__}: {str(exc_value)}"
        
    def _get_expected_result(self, method_name, test_method=None):
        """从测试方法的docstring中提取预期结果，如果没有则推断"""
        if test_method and hasattr(test_method, '__doc__') and test_method.__doc__:
            docstring = test_method.__doc__.strip()
            # 提取预期结果部分（支持多种格式）
            expected_keywords = ['预期结果:', '详细预期结果:', 'Expected Result:', 'Expected:']
            for keyword in expected_keywords:
                if keyword in docstring:
                    lines = docstring.split('\n')
                    in_expected_section = False
                    expected_lines = []
                    for line in lines:
                        line = line.strip()
                        if keyword in line:
                            in_expected_section = True
                            # 如果关键词后面还有内容，也包含进来
                            after_keyword = line.split(keyword, 1)[1].strip()
                            if after_keyword:
                                expected_lines.append(after_keyword)
                            continue
                        elif in_expected_section:
                            # 遇到新的section或docstring结束时停止
                            if (line.startswith('"""') or 
                                line.endswith(':') and any(section in line for section in ['测试步骤', '测试描述', '注意事项', '参数说明']) or
                                (line and not line.startswith(('1.', '2.', '3.', '4.', '5.', '6.', '7.', '8.', '9.', '-', '•', '  -', '  •')))):
                                break
                            if line:
                                expected_lines.append(line)
                    if expected_lines:
                        return '; '.join(expected_lines)
                    break
        
        # 如果没有docstring或没有详细预期结果，则使用推断逻辑
        expectations = {
            'initialization': '组件应正确初始化',
            'configuration': '配置应正确加载',
            'detection': '检测功能应正常工作',
            'performance': '性能应满足要求',
            'memory': '内存使用应在合理范围内',
            'cpu': 'CPU使用应在合理范围内',
            'baseline': '基线功能应正常工作',
            'alert': '告警功能应正常工作',
            'logging': '日志功能应正常工作',
            'validation': '验证功能应正常工作',
            'integration': '集成测试应通过',
            'e2e': '端到端测试应通过',
            'system': '系统测试应通过',
            'load': '负载测试应通过',
            'stress': '压力测试应通过',
            'security': '安全测试应通过',
            'data': '数据处理应正确',
            'file': '文件操作应正确',
            'network': '网络功能应正常',
            'database': '数据库操作应正确'
        }
        
        method_lower = method_name.lower()
        for key, expectation in expectations.items():
            if key in method_lower:
                return expectation
                
        return "测试应该通过"
        
    def _extract_test_description(self, test_method):
        """从测试方法的docstring中提取测试描述"""
        if hasattr(test_method, '__doc__') and test_method.__doc__:
            docstring = test_method.__doc__.strip()
            lines = docstring.split('\n')
            
            # 提取第一行作为简短描述
            first_line = lines[0].strip() if lines else ''
            
            # 提取测试描述部分（支持多种格式）
            description_keywords = ['测试描述:', 'Description:', '描述:']
            description_lines = []
            
            for keyword in description_keywords:
                if keyword in docstring:
                    in_description_section = False
                    for line in lines:
                        line = line.strip()
                        if keyword in line:
                            in_description_section = True
                            # 如果关键词后面还有内容，也包含进来
                            after_keyword = line.split(keyword, 1)[1].strip()
                            if after_keyword:
                                description_lines.append(after_keyword)
                            continue
                        elif in_description_section:
                            # 遇到新的section时停止
                            if (line.endswith(':') and any(section in line for section in ['测试步骤', '预期结果', '详细预期结果', '注意事项', '参数说明']) or
                                line.startswith('"""')):
                                break
                            if line:
                                description_lines.append(line)
                    break
            
            if description_lines:
                return ' '.join(description_lines)
            elif first_line:
                return first_line
                
        return ''


class ComprehensiveTestRunner:
    """全面测试运行器"""
    
    def __init__(self):
        self.test_recorder = TestResult()
        self.start_time = datetime.now()
        
    def run_test_file(self, test_file_path, project_root):
        """运行单个测试文件"""
        test_file_name = test_file_path.name
        print(f"\n{'='*80}")
        print(f"正在运行测试文件: {test_file_name}")
        print(f"{'='*80}")
        
        try:
            # 动态导入测试模块
            module_name = f"tests.{test_file_path.stem}"
            
            # 添加项目根目录到Python路径
            if str(project_root) not in sys.path:
                sys.path.insert(0, str(project_root))
                
            # 导入模块
            spec = importlib.util.spec_from_file_location(module_name, test_file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # 查找测试类
            test_classes = []
            for name in dir(module):
                obj = getattr(module, name)
                if (isinstance(obj, type) and 
                    issubclass(obj, unittest.TestCase) and 
                    obj != unittest.TestCase):
                    test_classes.append(obj)
            
            if not test_classes:
                print(f"警告: 在 {test_file_name} 中未找到测试类")
                self.test_recorder.add_result(
                    test_file_name, "Unknown", "no_tests",
                    "应该包含测试类", "未找到测试类", "ERROR",
                    error="未找到unittest.TestCase子类"
                )
                return False
            
            # 运行每个测试类
            all_success = True
            for test_class in test_classes:
                success = self._run_test_class(test_class, test_file_name)
                all_success = all_success and success
                
            return all_success
            
        except Exception as e:
            print(f"✗ 运行测试时出错: {e}")
            self.test_recorder.add_result(
                test_file_name, "Unknown", "import_error",
                "模块应正确导入", f"导入失败: {str(e)}", "ERROR",
                error=str(e)
            )
            return False
            
    def _run_test_class(self, test_class, test_file_name):
        """运行单个测试类"""
        print(f"\n运行测试类: {test_class.__name__}")
        
        # 创建测试套件
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(test_class)
        
        # 创建自定义结果收集器
        result = DetailedTestResult(self.test_recorder, test_file_name)
        
        # 运行测试
        suite.run(result)
        
        # 输出结果
        total_tests = result.testsRun
        errors = len(result.errors)
        failures = len(result.failures)
        skipped = len(result.skipped)
        
        print(f"  测试方法数: {total_tests}")
        print(f"  通过: {total_tests - errors - failures - skipped}")
        print(f"  失败: {failures}")
        print(f"  错误: {errors}")
        print(f"  跳过: {skipped}")
        
        if result.errors:
            print(f"  错误详情:")
            for test, error in result.errors:
                print(f"    - {test._testMethodName}: {error.split(chr(10))[0]}")
                
        if result.failures:
            print(f"  失败详情:")
            for test, failure in result.failures:
                print(f"    - {test._testMethodName}: {failure.split(chr(10))[0]}")
        
        return errors == 0 and failures == 0
        
    def save_results(self, log_file_path):
        """保存测试结果"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        # 统计结果
        total_tests = len(self.test_recorder.results)
        passed_tests = len([r for r in self.test_recorder.results if r['status'] == 'PASS'])
        failed_tests = len([r for r in self.test_recorder.results if r['status'] == 'FAIL'])
        error_tests = len([r for r in self.test_recorder.results if r['status'] == 'ERROR'])
        skipped_tests = len([r for r in self.test_recorder.results if r['status'] == 'SKIP'])
        
        log_data = {
            'test_session': {
                'start_time': self.start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': failed_tests,
                'error_tests': error_tests,
                'skipped_tests': skipped_tests
            },
            'test_results': self.test_recorder.results
        }
        
        # 保存JSON格式
        with open(log_file_path, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, ensure_ascii=False, indent=2)
            
        # 保存可读格式
        readable_log_path = str(log_file_path).replace('.json', '_readable.txt')
        with open(readable_log_path, 'w', encoding='utf-8') as f:
            f.write(f"IDS4.0 全面测试报告\n")
            f.write(f"{'='*80}\n")
            f.write(f"测试开始时间: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"测试结束时间: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"总耗时: {duration:.2f} 秒\n")
            f.write(f"总测试方法数: {total_tests}\n")
            f.write(f"通过: {passed_tests}\n")
            f.write(f"失败: {failed_tests}\n")
            f.write(f"错误: {error_tests}\n")
            f.write(f"跳过: {skipped_tests}\n")
            f.write(f"成功率: {(passed_tests/total_tests*100):.1f}%\n" if total_tests > 0 else "成功率: N/A\n")
            f.write(f"\n{'='*80}\n")
            f.write(f"详细测试结果\n")
            f.write(f"{'='*80}\n\n")
            
            # 按文件分组显示结果
            files = {}
            for result in self.test_recorder.results:
                file_name = result['test_file']
                if file_name not in files:
                    files[file_name] = []
                files[file_name].append(result)
                
            for file_name, results in files.items():
                f.write(f"文件: {file_name}\n")
                f.write(f"{'-'*60}\n")
                
                for i, result in enumerate(results, 1):
                    f.write(f"  测试 #{i}\n")
                    f.write(f"    类名: {result['test_class']}\n")
                    f.write(f"    方法: {result['test_method']}\n")
                    if result.get('test_description'):
                        f.write(f"    描述: {result['test_description']}\n")
                    f.write(f"    预期结果: {result['expected_result']}\n")
                    f.write(f"    实际结果: {result['actual_result']}\n")
                    f.write(f"    状态: {result['status']}\n")
                    f.write(f"    耗时: {result['duration_seconds']:.3f}秒\n")
                    if result['error_message']:
                        f.write(f"    错误信息: {result['error_message']}\n")
                    f.write(f"    时间: {result['timestamp']}\n")
                    f.write(f"\n")
                    
                f.write(f"\n")
        
        return readable_log_path


def main():
    """主函数"""
    # 获取项目根目录
    project_root = Path(__file__).parent.parent
    tests_dir = project_root / "tests"
    
    # 创建日志文件
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file_path = tests_dir / f"comprehensive_test_log_{timestamp}.json"
    
    # 初始化测试运行器
    runner = ComprehensiveTestRunner()
    
    # 获取所有测试文件
    test_files = [
        f for f in tests_dir.glob("test_*.py")
        if f.name not in ['test_config.py', 'test_utils.py', 'test_settings.py']
    ]
    
    print(f"\n{'='*80}")
    print(f"IDS4.0 全面测试套件")
    print(f"测试开始时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"找到 {len(test_files)} 个测试文件")
    print(f"日志文件: {log_file_path}")
    print(f"测试文件列表: {[f.name for f in test_files]}")
    print(f"{'='*80}")
    
    # 运行所有测试
    passed_files = []
    failed_files = []
    
    for test_file in sorted(test_files):
        success = runner.run_test_file(test_file, project_root)
        if success:
            passed_files.append(test_file.name)
        else:
            failed_files.append(test_file.name)
        
        # 添加间隔
        time.sleep(0.5)
    
    # 保存结果
    readable_log_path = runner.save_results(log_file_path)
    
    # 打印总结
    print(f"\n{'='*80}")
    print(f"测试总结")
    print(f"{'='*80}")
    print(f"测试完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"总测试文件数: {len(test_files)}")
    print(f"通过的文件: {len(passed_files)}")
    print(f"失败的文件: {len(failed_files)}")
    print(f"总测试方法数: {len(runner.test_recorder.results)}")
    print(f"详细日志已保存到: {log_file_path}")
    print(f"可读日志已保存到: {readable_log_path}")
    
    if passed_files:
        print(f"\n✓ 通过的测试文件:")
        for test in passed_files:
            print(f"  - {test}")
    
    if failed_files:
        print(f"\n✗ 失败的测试文件:")
        for test in failed_files:
            print(f"  - {test}")
    
    print(f"\n{'='*80}")
    
    # 返回适当的退出码
    return 0 if len(failed_files) == 0 else 1


if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
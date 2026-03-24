#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
APK SDK分析工具 - 环境检查脚本
用于验证Python环境是否满足运行要求
"""

import sys

def check_python_version():
    """检查Python版本"""
    print("=" * 60)
    print("APK SDK分析工具 - 环境检查")
    print("=" * 60)
    
    version = sys.version_info
    print(f"\n[1/5] Python版本检查")
    print(f"  当前版本: {sys.version}")
    
    if version.major >= 3 and version.minor >= 6:
        print(f"  ✓ Python {version.major}.{version.minor}.{version.micro} 满足要求")
        return True
    else:
        print(f"  ✗ Python版本过低，需要3.6或更高版本")
        return False

def check_std_libraries():
    """检查标准库"""
    print(f"\n[2/5] 标准库检查")
    
    required_libs = [
        'sys',
        'os',
        'zipfile',
        're',
        'time',
        'json',
        'collections',
        'io'
    ]
    
    all_ok = True
    for lib in required_libs:
        try:
            __import__(lib)
            print(f"  ✓ {lib}")
        except ImportError:
            print(f"  ✗ {lib} - 导入失败")
            all_ok = False
    
    return all_ok

def check_config_file():
    """检查配置文件"""
    import os
    print(f"\n[3/5] 配置文件检查")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, '..', 'config', 'sdk_patterns.json')

    if os.path.exists(config_path):
        print(f"  ✓ 配置文件存在: sdk_patterns.json")
        try:
            import json
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                categories = list(config.keys())
                print(f"  ✓ 配置文件格式正确，包含 {len(categories)} 个分类")
            return True
        except Exception as e:
            print(f"  ✗ 配置文件格式错误: {e}")
            return False
    else:
        print(f"  ✗ 配置文件不存在: sdk_patterns.json")
        return False

def check_script_file():
    """检查主脚本文件"""
    import os
    print(f"\n[4/5] 主脚本文件检查")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(script_dir, 'sdk_analyzer.py')

    if os.path.exists(script_path):
        print(f"  ✓ 主脚本文件存在: sdk_analyzer.py")
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                lines = len(f.readlines())
            print(f"  ✓ 主脚本文件可读，共 {lines} 行")
            return True
        except Exception as e:
            print(f"  ✗ 主脚本文件读取失败: {e}")
            return False
    else:
        print(f"  ✗ 主脚本文件不存在: sdk_analyzer.py")
        return False

def check_encoding():
    """检查编码支持"""
    print(f"\n[5/5] 编码支持检查")
    
    try:
        test_str = "测试 UTF-8 编码 ✓"
        encoded = test_str.encode('utf-8')
        decoded = encoded.decode('utf-8')
        if decoded == test_str:
            print(f"  ✓ UTF-8 编码支持正常")
            return True
        else:
            print(f"  ✗ UTF-8 编解码异常")
            return False
    except Exception as e:
        print(f"  ✗ UTF-8 编码不支持: {e}")
        return False

def main():
    """主检查函数"""
    results = []
    
    results.append(check_python_version())
    results.append(check_std_libraries())
    results.append(check_config_file())
    results.append(check_script_file())
    results.append(check_encoding())
    
    print("\n" + "=" * 60)
    print("检查结果汇总")
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"\n通过: {passed}/{total} 项检查")
    
    if all(results):
        print("\n✓ 环境检查通过！可以正常使用APK SDK分析工具")
        print("\n运行命令:")
        print("  python analyze_apk.py <APK文件路径> [输出报告路径]")
        return 0
    else:
        print("\n✗ 环境检查失败！请根据上述提示修复问题")
        return 1

if __name__ == '__main__':
    sys.exit(main())

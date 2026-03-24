#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK/IPK分析工具集主入口
支持Android APK和iOS IPA的SDK分析和权限分析

使用方法:
    python main.py -o=1 <文件路径> <报告输出目录>   # 仅SDK分析
    python main.py -o=2 <文件路径> <报告输出目录>   # 仅权限分析
    python main.py -o=3 <文件路径> <报告输出目录>   # 两者都分析

自动识别文件类型:
    - .apk 文件使用 Android APK 分析模块
    - .ipa 文件使用 iOS IPA 分析模块
"""

import os
import sys
import time

# 添加脚本目录到路径
script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, script_dir)


def get_timestamp():
    """获取当前时间戳字符串（最长6位）"""
    ts = str(int(time.time()))
    return ts[-6:]


def detect_file_type(file_path):
    """
    检测文件类型

    Returns:
        'apk', 'ipa', 或 None
    """
    if file_path.lower().endswith('.apk'):
        return 'apk'
    elif file_path.lower().endswith('.ipa'):
        return 'ipa'
    return None


def get_app_info_and_permissions(file_path, file_type):
    """获取应用信息和权限列表"""
    if file_type == 'apk':
        from common.apk_utils import get_app_info_and_permissions as apk_get_info
        return apk_get_info(file_path)
    else:  # ipa
        from common.ipa_utils import get_app_info_and_permissions as ipa_get_info
        return ipa_get_info(file_path)


def generate_sdk_report_path(file_path, output_dir):
    """生成SDK分析报告路径"""
    file_name = os.path.basename(file_path)
    if file_name.endswith('.apk'):
        file_name = file_name[:-4]
    elif file_name.endswith('.ipa'):
        file_name = file_name[:-4]
    timestamp = get_timestamp()
    return os.path.join(output_dir, f"{file_name}_SDK分析_{timestamp}.md")


def generate_permission_report_path(file_path, output_dir):
    """生成权限分析报告路径"""
    file_name = os.path.basename(file_path)
    if file_name.endswith('.apk'):
        file_name = file_name[:-4]
    elif file_name.endswith('.ipa'):
        file_name = file_name[:-4]
    timestamp = get_timestamp()
    return os.path.join(output_dir, f"{file_name}_权限分析_{timestamp}.md")


def analyze_sdk(file_path, output_dir, file_type):
    """执行SDK分析"""
    file_label = "APK" if file_type == 'apk' else "IPA"
    print("\n" + "=" * 60)
    print(f"开始{file_label} SDK分析...")
    print("=" * 60)

    # 获取应用信息
    app_info, _ = get_app_info_and_permissions(file_path, file_type)
    print(f"[INFO] 包名: {app_info.get('package', '未知')}")
    print(f"[INFO] 版本: {app_info.get('versionName', '未知')} ({app_info.get('versionCode', '未知')})")

    if file_type == 'apk':
        from scripts.sdk_analyzer import analyze_apk as analyze_sdk_func, generate_report as generate_sdk_report, load_patterns
        config_path = os.path.join(script_dir, 'config', 'sdk_patterns.json')
    else:  # ipa
        from scripts.ios_sdk_analyzer import analyze_apk as analyze_sdk_func, generate_report as generate_sdk_report, load_patterns
        config_path = os.path.join(script_dir, 'config', 'ios_sdk_patterns.json')

    patterns = load_patterns(config_path)
    result = analyze_sdk_func(file_path, patterns)

    report_path = generate_sdk_report_path(file_path, output_dir)
    generate_sdk_report(file_path, result, report_path, app_info)

    print(f"\n{file_label} SDK分析完成! 报告已保存: {report_path}")
    return report_path


def analyze_permission(file_path, output_dir, file_type):
    """执行权限分析"""
    file_label = "APK" if file_type == 'apk' else "IPA"
    print("\n" + "=" * 60)
    print(f"开始{file_label}权限分析...")
    print("=" * 60)

    if file_type == 'apk':
        from scripts.permission_analyzer import analyze_apk as analyze_permission_func
    else:  # ipa
        from scripts.ios_permission_analyzer import analyze_apk as analyze_permission_func

    report = analyze_permission_func(file_path)

    report_path = generate_permission_report_path(file_path, output_dir)
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)

    print(f"\n{file_label}权限分析完成! 报告已保存: {report_path}")
    return report_path


def main():
    """主函数"""
    # 设置UTF-8输出
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    print("=" * 60)
    print("APK/IPK分析工具集 v2.0")
    print("=" * 60)

    # 解析命令行参数
    file_path = None
    output_dir = None
    option = None

    for arg in sys.argv[1:]:
        if arg.startswith('-o='):
            option = arg[3:]
        elif os.path.exists(arg):
            if arg.endswith('.apk') or arg.endswith('.ipa'):
                file_path = arg
            elif os.path.isdir(arg):
                output_dir = arg

    # 参数验证
    if not option or option not in ['1', '2', '3']:
        print("\n使用方法:")
        print("  python main.py -o=1 <文件路径> <报告输出目录>   # 仅SDK分析")
        print("  python main.py -o=2 <文件路径> <报告输出目录>   # 仅权限分析")
        print("  python main.py -o=3 <文件路径> <报告输出目录>   # 两者都分析")
        print("\n支持的格式:")
        print("  - APK文件 (.apk)")
        print("  - IPA文件 (.ipa)")
        print("\n示例:")
        print("  python main.py -o=3 C:/test/app.apk C:/reports")
        print("  python main.py -o=3 C:/test/app.ipa C:/reports")
        sys.exit(1)

    if not file_path:
        print("\n错误: 请指定有效的APK或IPA文件路径")
        sys.exit(1)

    if not output_dir:
        print("\n错误: 请指定报告输出目录")
        sys.exit(1)

    # 检测文件类型
    file_type = detect_file_type(file_path)
    if not file_type:
        print(f"\n错误: 不支持的文件格式: {file_path}")
        print("仅支持 .apk (Android) 和 .ipa (iOS) 文件")
        sys.exit(1)

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)

    type_label = "Android APK" if file_type == 'apk' else "iOS IPA"
    print(f"\n文件: {file_path} ({type_label})")
    print(f"输出目录: {output_dir}")
    print(f"分析模式: ", end="")
    if option == '1':
        print("仅SDK分析")
    elif option == '2':
        print("仅权限分析")
    else:
        print("SDK分析 + 权限分析")

    report_paths = []

    # 执行分析
    if option in ['1', '3']:
        try:
            path = analyze_sdk(file_path, output_dir, file_type)
            report_paths.append(path)
        except Exception as e:
            print(f"\n[ERROR] SDK分析失败: {e}")
            import traceback
            traceback.print_exc()

    if option in ['2', '3']:
        try:
            path = analyze_permission(file_path, output_dir, file_type)
            report_paths.append(path)
        except Exception as e:
            print(f"\n[ERROR] 权限分析失败: {e}")
            import traceback
            traceback.print_exc()

    # 输出总结
    print("\n" + "=" * 60)
    print("分析完成!")
    print("=" * 60)
    if report_paths:
        print("\n生成的报告:")
        for p in report_paths:
            print(f"  - {p}")
    else:
        print("\n未生成任何报告")


if __name__ == '__main__':
    main()

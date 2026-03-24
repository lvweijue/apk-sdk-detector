#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK权限分析器主模块
用于分析APK文件的权限使用情况和用户数据收集行为
"""

import os
import sys

# 添加公共模块路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'common'))

from apk_utils import get_app_info_and_permissions, load_json_config, get_config_path


class ApkPermissionAnalyzer:
    """
    APK权限分析器类
    """

    def __init__(self):
        """
        初始化APK权限分析器
        """
        # 加载权限配置
        config_path = get_config_path('permission_rules.json')
        self.config = load_json_config(config_path)

        self.permission_risk_levels = self.config.get('permission_risk_levels', {})
        self.permission_purposes = self.config.get('permission_purposes', {})

    def analyze_apk(self, apk_path):
        """
        分析APK文件的权限使用情况

        Args:
            apk_path: APK文件路径

        Returns:
            str: 分析报告
        """
        try:
            # 检查APK文件是否存在
            if not os.path.exists(apk_path):
                return "错误：APK文件不存在"

            # 检查文件是否为APK文件
            if not apk_path.endswith('.apk'):
                return "错误：文件不是APK格式"

            # 获取应用信息和权限列表
            app_info, permissions = get_app_info_and_permissions(apk_path)

            if not permissions and app_info.get('package') == '未知':
                return "错误：无法提取AndroidManifest信息"

            # 分析权限风险
            risk_analysis = self.analyze_permissions(permissions)

            # 生成分析报告
            report = self.generate_report(app_info, permissions, risk_analysis)

            return report

        except Exception as e:
            return f"分析失败：{str(e)}"

    def analyze_permissions(self, permissions):
        """
        分析权限风险

        Args:
            permissions: 权限列表

        Returns:
            dict: 风险分析结果
        """
        risk_levels = {}
        high_risk_count = 0
        medium_risk_count = 0
        low_risk_count = 0

        for perm in permissions:
            risk_level = self.permission_risk_levels.get(perm, '未知')
            risk_levels[perm] = risk_level

            if risk_level == '高':
                high_risk_count += 1
            elif risk_level == '中':
                medium_risk_count += 1
            elif risk_level == '低':
                low_risk_count += 1

        # 计算整体风险等级
        if high_risk_count > 3:
            overall_risk = '高'
        elif high_risk_count > 0 or medium_risk_count > 5:
            overall_risk = '中'
        else:
            overall_risk = '低'

        return {
            'risk_levels': risk_levels,
            'high_risk_count': high_risk_count,
            'medium_risk_count': medium_risk_count,
            'low_risk_count': low_risk_count,
            'overall_risk': overall_risk
        }

    def generate_report(self, app_info, permissions, risk_analysis):
        """
        生成分析报告

        Args:
            app_info: 应用信息
            permissions: 权限列表
            risk_analysis: 风险分析结果

        Returns:
            str: 分析报告
        """
        import time
        import os

        report = []

        # 获取包大小
        # app_info可能包含apk_path，从调用方获取
        apk_path = getattr(self, '_current_apk_path', '')
        apk_size = os.path.getsize(apk_path) / (1024 * 1024) if apk_path and os.path.exists(apk_path) else 0

        # 添加标题
        report.append("# APK权限分析报告")
        report.append("")

        # 添加基本信息（四项）
        report.append("## 基本信息")
        report.append("| 项目 | 值 |")
        report.append("|:---|---|")
        report.append(f"| 包名 | {app_info.get('package', '未知')} |")
        report.append(f"| 包版本 | {app_info.get('versionName', '未知')} ({app_info.get('versionCode', '未知')}) |")
        report.append(f"| 包大小 | {apk_size:.2f} MB |")
        report.append(f"| 分析时间 | {time.strftime('%Y-%m-%d %H:%M:%S')} |")
        report.append("")

        # 高危权限提示
        high_risk_perms = [p for p in permissions if risk_analysis['risk_levels'].get(p) == '高']
        if high_risk_perms:
            report.append("## ⚠️ 高风险权限提示")
            report.append("")
            report.append("以下权限为高风险权限，**必须有合理用途，否则可能被应用商店拒绝上架**：")
            report.append("")
            for perm in high_risk_perms:
                purpose = self.permission_purposes.get(perm, '未知')
                report.append(f"- **{perm}** - {purpose}")
            report.append("")
            report.append("---")
            report.append("")

        # 添加权限分析（按风险等级排序：高 > 中 > 低 > 未知）
        report.append("## 权限详情")
        report.append("")
        report.append("| 权限 | 用途 | 风险等级 |")
        report.append("|:---|:---|:---|")

        # 按风险等级排序
        risk_order = {'高': 0, '中': 1, '低': 2, '未知': 3}
        sorted_permissions = sorted(
            permissions,
            key=lambda p: (risk_order.get(risk_analysis['risk_levels'].get(p, '未知'), 9), p)
        )

        for perm in sorted_permissions:
            purpose = self.permission_purposes.get(perm, '未知')
            risk_level = risk_analysis['risk_levels'].get(perm, '未知')
            # 高风险用加粗标记
            if risk_level == '高':
                report.append(f"| **{perm}** | {purpose} | **{risk_level}** |")
            else:
                report.append(f"| {perm} | {purpose} | {risk_level} |")

        if not permissions:
            report.append("| 无 | 无 | 无 |")

        report.append("")

        # 添加风险评估
        report.append("## 风险评估")
        report.append(f"| 项目 | 值 |")
        report.append("|------|------|")
        report.append(f"| 高风险权限数量 | {risk_analysis['high_risk_count']} |")
        report.append(f"| 中风险权限数量 | {risk_analysis['medium_risk_count']} |")
        report.append(f"| 低风险权限数量 | {risk_analysis['low_risk_count']} |")
        report.append(f"| 整体风险等级 | {risk_analysis['overall_risk']} |")
        report.append("")

        # 添加建议
        report.append("## 建议")
        if risk_analysis['overall_risk'] == '高':
            report.append("1. 谨慎使用此应用，可能过度收集用户数据")
            report.append("2. 考虑使用替代应用")
            report.append("3. 在系统设置中限制应用权限")
        elif risk_analysis['overall_risk'] == '中':
            report.append("1. 注意应用的权限使用情况")
            report.append("2. 定期检查应用的权限设置")
        else:
            report.append("1. 权限使用合理，风险较低")
            report.append("2. 仍然建议定期检查应用权限")

        report.append("")
        report.append("## 注意事项")
        report.append("- 本分析仅基于APK文件的静态分析，不包括运行时行为分析")
        report.append("- 分析结果仅供参考，不构成法律建议")

        return '\n'.join(report)


def analyze_apk(apk_path):
    """
    Trae 调用入口函数
    分析APK文件的权限使用情况

    Args:
        apk_path: APK文件路径

    Returns:
        str: 分析报告
    """
    analyzer = ApkPermissionAnalyzer()
    analyzer._current_apk_path = apk_path  # 用于获取包大小
    return analyzer.analyze_apk(apk_path)


if __name__ == "__main__":
    # 设置UTF-8输出
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    # 从命令行参数读取APK文件路径
    if len(sys.argv) > 1:
        apk_path = sys.argv[1]
        result = analyze_apk(apk_path)
        print(result)
    else:
        print("APK权限分析器")
        print("\n使用方法:")
        print("  python main.py <APK文件路径>")
        print("\n示例:")
        print("  python main.py C:/Users/test/app.apk")
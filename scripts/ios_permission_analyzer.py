"""
iOS IPA权限分析器 v1.0
用于分析IPA文件的权限使用情况、私有API检测和用户数据收集行为
"""

import os
import sys
import time

# 添加公共模块路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'common'))

from ipa_utils import get_app_info_and_permissions, load_json_config, get_config_path, analyze_private_apis


def get_permission_description_from_plist(ipa_path: str) -> Dict[str, str]:
    """
    从IPA的Info.plist中提取权限说明文案

    Args:
        ipa_path: IPA文件路径

    Returns:
        权限说明文案字典 {权限名: 说明文案}
    """
    from ipa_utils import extract_info_plist, extract_permissions_from_plist
    plist = extract_info_plist(ipa_path)
    if plist:
        _, descriptions = extract_permissions_from_plist(plist)
        return descriptions
    return {}


class IpaPermissionAnalyzer:
    """
    iOS IPA权限分析器类
    """

    def __init__(self):
        """初始化IPA权限分析器"""
        config_path = get_config_path('ios_permission_rules.json')
        self.config = load_json_config(config_path)

        self.permission_risk_levels = self.config.get('permission_risk_levels', {})
        self.permission_purposes = self.config.get('permission_purposes', {})

    def analyze_ipa(self, ipa_path):
        """
        分析IPA文件的权限使用情况

        Args:
            ipa_path: IPA文件路径

        Returns:
            str: 分析报告
        """
        try:
            if not os.path.exists(ipa_path):
                return "错误：IPA文件不存在"

            if not ipa_path.lower().endswith('.ipa'):
                return "错误：文件不是IPA格式"

            app_info, permissions, permission_descriptions = get_app_info_and_permissions(ipa_path)

            if not permissions and app_info.get('package') == '未知':
                return "错误：无法提取Info.plist信息"

            risk_analysis = self.analyze_permissions(permissions)

            # 检测私有API使用
            print("[INFO] 正在检测私有API使用...")
            private_api_result = analyze_private_apis(ipa_path)

            # 获取Info.plist中的权限说明文案
            print("[INFO] 正在提取权限说明文案...")
            plist_descriptions = get_permission_description_from_plist(ipa_path)

            report = self.generate_report(ipa_path, app_info, permissions, risk_analysis, private_api_result, plist_descriptions)

            return report

        except Exception as e:
            return f"分析失败：{str(e)}"

    def analyze_permissions(self, permissions):
        """分析权限风险"""
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

    def generate_report(self, ipa_path, app_info, permissions, risk_analysis, private_api_result=None, plist_descriptions=None):
        """生成分析报告"""
        ipa_size = os.path.getsize(ipa_path) / (1024 * 1024)
        if plist_descriptions is None:
            plist_descriptions = {}

        report = []

        report.append("# iOS IPA权限分析报告")
        report.append("")

        # 基本信息（四项）
        report.append("## 基本信息")
        report.append("| 项目 | 值 |")
        report.append("|:---|:---|")
        report.append(f"| 包名 | {app_info.get('package', '未知')} |")
        report.append(f"| 包版本 | {app_info.get('versionName', '未知')} ({app_info.get('versionCode', '未知')}) |")
        report.append(f"| 包大小 | {ipa_size:.2f} MB |")
        report.append(f"| 分析时间 | {time.strftime('%Y-%m-%d %H:%M:%S')} |")
        report.append("")

        # 高危权限提示
        high_risk_perms = [p for p in permissions if risk_analysis['risk_levels'].get(p) == '高']
        if high_risk_perms:
            report.append("## ⚠️ 高风险权限提示")
            report.append("")
            report.append("以下权限为高风险权限，**必须有合理用途，否则可能被App Store拒绝上架**：")
            report.append("")
            for perm in high_risk_perms:
                purpose = self.permission_purposes.get(perm, '未知')
                report.append(f"- **{perm}** - {purpose}")
            report.append("")
            report.append("---")
            report.append("")

        # 私有API检测结果
        if private_api_result and private_api_result.get('has_private_apis'):
            report.append("## ⚠️ 私有API使用检测")
            report.append("")
            report.append(f"**风险等级: {private_api_result.get('risk_level', '未知')}**")
            report.append("")
            report.append(f"检测到 **{private_api_result.get('total_categories', 0)}** 个类别共 **{private_api_result.get('high_risk_count', 0) + private_api_result.get('medium_risk_count', 0)}** 个可疑私有API使用：")
            report.append("")

            detected = private_api_result.get('detected', {})
            # 按风险等级排序
            risk_order = {'高': 0, '中': 1, '低': 2}

            sorted_categories = sorted(
                detected.items(),
                key=lambda x: risk_order.get(x[1].get('risk_level', '中'), 9)
            )

            for category, info in sorted_categories:
                risk = info.get('risk_level', '中')
                apis = info.get('apis', [])

                risk_prefix = "🔴" if risk == "高" else "🟡"
                report.append(f"### {risk_prefix} {category} ({risk}风险)")
                report.append("")
                for api in apis[:30]:  # 限制显示数量
                    report.append(f"- `{api}`")
                if len(apis) > 30:
                    report.append(f"- ... 等共 {len(apis)} 个")
                report.append("")

            report.append("---")
            report.append("")

        # 权限详情（按风险排序）
        report.append("## 权限详情")
        report.append("")
        report.append("| 权限 | 用途 | 申请说明 | 风险等级 |")
        report.append("|:---|:---|:---|:---|")

        risk_order = {'高': 0, '中': 1, '低': 2, '未知': 3}
        sorted_permissions = sorted(
            permissions,
            key=lambda p: (risk_order.get(risk_analysis['risk_levels'].get(p, '未知'), 9), p)
        )

        for perm in sorted_permissions:
            purpose = self.permission_purposes.get(perm, '未知')
            # 从Info.plist获取申请时展示的说明文案
            description = plist_descriptions.get(perm, '')
            # 截断过长的说明
            if description and len(description) > 50:
                description = description[:50] + '...'
            risk_level = risk_analysis['risk_levels'].get(perm, '未知')

            if risk_level == '高':
                if description:
                    report.append(f"| **{perm}** | {purpose} | {description} | **{risk_level}** |")
                else:
                    report.append(f"| **{perm}** | {purpose} | - | **{risk_level}** |")
            else:
                if description:
                    report.append(f"| {perm} | {purpose} | {description} | {risk_level} |")
                else:
                    report.append(f"| {perm} | {purpose} | - | {risk_level} |")

        if not permissions:
            report.append("| 无 | 无 | - | 无 |")

        report.append("")

        # 风险评估
        report.append("## 风险评估")
        report.append(f"| 项目 | 值 |")
        report.append("|:---|---:|")
        report.append(f"| 高风险权限数量 | {risk_analysis['high_risk_count']} |")
        report.append(f"| 中风险权限数量 | {risk_analysis['medium_risk_count']} |")
        report.append(f"| 低风险权限数量 | {risk_analysis['low_risk_count']} |")
        report.append(f"| 整体风险等级 | {risk_analysis['overall_risk']} |")
        if private_api_result and private_api_result.get('has_private_apis'):
            report.append(f"| 私有API风险 | {private_api_result.get('risk_level', '无')} |")
        report.append("")

        # 建议
        report.append("## 建议")
        if risk_analysis['overall_risk'] == '高' or (private_api_result and private_api_result.get('risk_level') == '高'):
            report.append("1. **高风险应用** - 可能使用了私有API或过度申请权限")
            report.append("2. 谨慎使用此应用，可能导致App Store审核被拒")
            report.append("3. 考虑使用替代应用")
        elif risk_analysis['overall_risk'] == '中':
            report.append("1. 注意应用的权限使用情况")
            report.append("2. 定期检查应用的权限设置")
        else:
            report.append("1. 权限使用合理，风险较低")
            report.append("2. 仍然建议定期检查应用权限")

        report.append("")
        report.append("## 注意事项")
        report.append("- 本分析仅基于IPA文件的静态分析，不包括运行时行为分析")
        report.append("- iOS权限通过Info.plist中的Usage Description声明")
        report.append("- 私有API检测基于已知模式匹配，可能存在漏报或误报")
        report.append("- 分析结果仅供参考，不构成法律建议")

        return '\n'.join(report)


def analyze_apk(ipa_path):
    """
    分析入口函数

    Args:
        ipa_path: IPA文件路径

    Returns:
        str: 分析报告
    """
    analyzer = IpaPermissionAnalyzer()
    return analyzer.analyze_ipa(ipa_path)


if __name__ == "__main__":
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    if len(sys.argv) > 1:
        ipa_path = sys.argv[1]
        result = analyze_apk(ipa_path)
        print(result)
    else:
        print("iOS IPA权限分析器")
        print("\n使用方法:")
        print("  python ios_permission_analyzer.py <IPA文件路径>")
        print("\n示例:")
        print("  python ios_permission_analyzer.py C:/Users/test/app.ipa")

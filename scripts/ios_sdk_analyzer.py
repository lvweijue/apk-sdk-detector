"""
IPA 第三方SDK分析脚本 v1.0
用于分析iOS IPA文件中的第三方SDK
"""

import sys
import os
import zipfile
import re
import time
import json
from collections import defaultdict

# 添加公共模块路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'common'))

from ipa_utils import get_config_path, load_json_config, extract_third_party_sdks, extract_frameworks


def load_patterns(config_path):
    """加载SDK特征库配置"""
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)


# =============================================================================
# 数据提取
# =============================================================================

def extract_strings_from_ipa(ipa_path):
    """从IPA中提取字符串和SDK信息"""
    sdk_packages = set()
    all_strings = set()
    frameworks = set()

    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            namelist = zf.namelist()

            # 提取Frameworks
            for name in namelist:
                if 'Frameworks/' in name:
                    if name.endswith('.dylib'):
                        lib_name = os.path.basename(name).replace('.dylib', '')
                        if not lib_name.startswith('lib'):
                            frameworks.add(lib_name)
                    elif name.endswith('.framework'):
                        fw_name = os.path.basename(name).replace('.framework', '')
                        frameworks.add(fw_name)

            # 从二进制文件提取字符串
            for name in namelist:
                if name.endswith('.dylib') or name.endswith('_nested') or '/SC_Info/' not in name:
                    try:
                        data = zf.read(name)
                        content = data.decode('utf-8', errors='ignore')

                        # SDK标识字符串
                        sdk_pattern = r'"([A-Za-z][A-Za-z0-9_]*(?:SDK|Framework|Adapter|Sdk)[A-Za-z0-9_]*)"'
                        matches = re.findall(sdk_pattern, content)
                        for m in matches:
                            if len(m) > 4:
                                sdk_packages.add(m.lower())

                        # URL域名
                        url_pattern = r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,})'
                        domains = re.findall(url_pattern, content, re.IGNORECASE)
                        for d in domains:
                            if len(d) > 4:
                                all_strings.add(d.lower())

                        # 包名格式
                        pkg_pattern = r'\b((?:com|org|net|io|me|cn|uk|de)[.][a-zA-Z][a-zA-Z0-9_]*(?:[.][a-zA-Z0-9_]+)*)\b'
                        pkgs = re.findall(pkg_pattern, content, re.IGNORECASE)
                        for p in pkgs:
                            if len(p) > 8:
                                sdk_packages.add(p.lower())

                    except:
                        continue

    except Exception as e:
        print(f"[WARN] Error reading IPA: {e}")

    return sdk_packages, all_strings, frameworks


def filter_third_party_sdks(packages, exclude_prefixes):
    """过滤出第三方SDK包名"""
    third_party = set()
    for pkg in packages:
        should_exclude = False
        for prefix in exclude_prefixes:
            if pkg.startswith(prefix) or prefix in pkg:
                should_exclude = True
                break
        if not should_exclude and len(pkg) > 5:
            third_party.add(pkg)
    return third_party


def unified_match_sdk(packages, all_strings, frameworks, sdks_dict):
    """
    统一多维度SDK匹配引擎

    维度：
    1. 包名/SDK标识匹配
    2. URL域名匹配
    3. Framework名称匹配
    """
    results = {}

    for category, sdks in sdks_dict.items():
        for sdk_name, keywords in sdks.items():
            evidence = []
            matched_packages = set()
            matched_frameworks = set()

            # 维度1: 包名/SDK标识匹配
            for pkg in packages:
                pkg_lower = pkg.lower()
                for keyword in keywords:
                    kw_lower = keyword.lower()
                    if kw_lower in pkg_lower:
                        matched_packages.add(pkg)
                        evidence.append({
                            'type': 'SDK标识',
                            'detail': pkg[:60],
                            'score': 30 if '.' in kw_lower else 15,
                            'keyword': kw_lower
                        })
                        break

            # 维度2: URL域名匹配
            for domain in all_strings:
                for keyword in keywords:
                    if keyword.lower() in domain:
                        evidence.append({
                            'type': 'URL域名',
                            'detail': domain,
                            'score': 20,
                            'keyword': keyword.lower()
                        })

            # 维度3: Framework匹配
            for fw in frameworks:
                fw_lower = fw.lower()
                for keyword in keywords:
                    if keyword.lower() in fw_lower:
                        matched_frameworks.add(fw)
                        evidence.append({
                            'type': 'Framework',
                            'detail': fw,
                            'score': 25,
                            'keyword': keyword.lower()
                        })

            if evidence:
                # 去重
                seen = set()
                unique_evidence = []
                for e in evidence:
                    key = e['detail'][:50]
                    if key not in seen:
                        seen.add(key)
                        unique_evidence.append(e)

                total_score = sum(e['score'] for e in unique_evidence)
                evidence_types = set(e['type'] for e in unique_evidence)

                if len(evidence_types) >= 2:
                    total_score += 10

                results[sdk_name] = {
                    'category': category,
                    'score': total_score,
                    'evidence_count': len(unique_evidence),
                    'evidence': unique_evidence,
                    'matched_packages': sorted(matched_packages),
                    'matched_frameworks': sorted(matched_frameworks),
                    'match_count': len(matched_packages) + len(matched_frameworks)
                }

    return results


def classify_confidence(score, evidence_count, evidence_types):
    """根据匹配置信度分类"""
    types = len(evidence_types) if evidence_types else 0

    if score >= 60 and evidence_count >= 3:
        return 'high', '高', '多维度证据充分确认'
    elif score >= 40 and evidence_count >= 2:
        return 'high', '高', '多维度证据确认'
    elif score >= 25 and types >= 2:
        return 'medium', '中', '多类型证据交叉验证'
    elif score >= 15:
        return 'low', '低', '仅有弱匹配证据'
    else:
        return 'low', '低', '证据不足'


def analyze_ipa(ipa_path, patterns):
    """IPA分析主函数"""
    print(f"[INFO] Analyzing IPA: {ipa_path}")

    # 提取数据
    print("[INFO] Extracting packages and strings...")
    sdk_packages, all_strings, frameworks = extract_strings_from_ipa(ipa_path)
    print(f"[INFO] Found {len(sdk_packages)} SDK packages, {len(all_strings)} domains, {len(frameworks)} frameworks")

    # 过滤第三方SDK
    print("[INFO] Filtering third-party SDKs...")
    exclude_prefixes = patterns.get('exclude_prefixes', [])
    third_party = filter_third_party_sdks(sdk_packages, exclude_prefixes)
    print(f"[INFO] Found {len(third_party)} third-party packages")

    # 匹配隐私SDK
    privacy_sdks_dict = {**patterns.get('privacy_sdk_patterns', {})}
    privacy_results = unified_match_sdk(
        third_party, all_strings, frameworks, privacy_sdks_dict)

    # 收集已匹配的包
    privacy_matched = set()
    for sdk_name, info in privacy_results.items():
        privacy_matched.update(info['matched_packages'])

    # 匹配其他SDK
    remaining = third_party - privacy_matched
    other_sdks_dict = {**patterns.get('sdk_patterns', {})}
    other_results = unified_match_sdk(remaining, all_strings, frameworks, other_sdks_dict)

    # 开源SDK
    open_source_sdks_dict = {**patterns.get('open_source_sdk_patterns', {})}
    open_source_results = unified_match_sdk(
        third_party, all_strings, frameworks, open_source_sdks_dict)

    # 构建结果
    privacy_matches = []
    for sdk_name, info in privacy_results.items():
        evidence_types = set(e['type'] for e in info['evidence'])
        level, label, desc = classify_confidence(info['score'], info['evidence_count'], evidence_types)
        privacy_matches.append({
            'category': info['category'],
            'sdk_name': sdk_name,
            'matched_packages': info['matched_packages'],
            'matched_frameworks': info['matched_frameworks'],
            'match_count': info['match_count'],
            'confidence': {'level': level, 'label': label, 'desc': desc, 'score': info['score']},
            'evidence': info['evidence'][:5]
        })

    other_matches = []
    for sdk_name, info in other_results.items():
        evidence_types = set(e['type'] for e in info['evidence'])
        level, label, desc = classify_confidence(info['score'], info['evidence_count'], evidence_types)
        other_matches.append({
            'category': info['category'],
            'sdk_name': sdk_name,
            'matched_packages': info['matched_packages'],
            'matched_frameworks': info['matched_frameworks'],
            'match_count': info['match_count'],
            'confidence': {'level': level, 'label': label, 'desc': desc, 'score': info['score']},
            'evidence': info['evidence'][:5]
        })

    open_source_matches = []
    for sdk_name, info in open_source_results.items():
        evidence_types = set(e['type'] for e in info['evidence'])
        level, label, desc = classify_confidence(info['score'], info['evidence_count'], evidence_types)
        open_source_matches.append({
            'category': info['category'],
            'sdk_name': sdk_name,
            'matched_packages': info['matched_packages'],
            'matched_frameworks': info['matched_frameworks'],
            'match_count': info['match_count'],
            'confidence': {'level': level, 'label': label, 'desc': desc, 'score': info['score']},
            'evidence': info['evidence'][:5]
        })

    # 统计
    privacy_high = len([s for s in privacy_matches if s['confidence']['level'] == 'high'])
    privacy_medium = len([s for s in privacy_matches if s['confidence']['level'] == 'medium'])
    privacy_low = len([s for s in privacy_matches if s['confidence']['level'] == 'low'])

    print(f"[INFO] Privacy SDKs: {len(privacy_matches)} (High:{privacy_high} Medium:{privacy_medium} Low:{privacy_low})")
    print(f"[INFO] Other SDKs: {len(other_matches)}")
    print(f"[INFO] Open Source SDKs: {len(open_source_matches)}")

    return {
        'total_packages': len(sdk_packages),
        'total_domains': len(all_strings),
        'third_party_count': len(third_party),
        'frameworks_count': len(frameworks),
        'privacy_sdks': privacy_matches,
        'other_sdks': other_matches,
        'open_source_sdks': open_source_matches,
    }


# =============================================================================
# 报告生成
# =============================================================================

def _confidence_badge(confidence):
    """生成置信度标签"""
    level = confidence.get('level', 'low')
    label = confidence.get('label', '低')
    score = confidence.get('score', 0)
    return f'[{label}置信 {score}分]'


def _evidence_summary(evidence_list):
    """生成证据摘要"""
    if not evidence_list:
        return ""

    type_labels = {'SDK标识': 'SDK标识', 'URL域名': '域名', 'Framework': 'Framework'}
    lines = []
    for e in evidence_list[:4]:
        t = type_labels.get(e['type'], e['type'])
        detail = e['detail'][:60]
        lines.append(f"  - [{t}] `{detail}`")

    if len(evidence_list) > 4:
        lines.append(f"  - ... 等 {len(evidence_list)} 条证据")

    return '\n'.join(lines)


def generate_report(ipa_path, analysis_result, output_path=None, app_info=None):
    """生成报告"""
    ipa_name = os.path.basename(ipa_path)
    ipa_size = os.path.getsize(ipa_path) / (1024 * 1024)

    if app_info is None:
        app_info = {
            'package': '未知',
            'versionCode': '未知',
            'versionName': '未知'
        }

    privacy_sdks = analysis_result.get('privacy_sdks', [])
    other_sdks = analysis_result.get('other_sdks', [])
    open_source_sdks = analysis_result.get('open_source_sdks', [])

    # 统计
    privacy_high = len([s for s in privacy_sdks if s['confidence']['level'] == 'high'])
    privacy_medium = len([s for s in privacy_sdks if s['confidence']['level'] == 'medium'])
    privacy_low = len([s for s in privacy_sdks if s['confidence']['level'] == 'low'])
    open_source_count = len(open_source_sdks)
    other_sdk_count = len(other_sdks)

    # 分类统计
    privacy_by_category = defaultdict(int)
    for sdk in privacy_sdks:
        privacy_by_category[sdk.get('category', '其他')] += 1

    content = f"""# iOS IPA 第三方SDK分析报告

## 汇总信息

| 项目 | 数值 |
|:---|---:|
| 包名 | {app_info.get('package', '未知')} |
| 包版本 | {app_info.get('versionName', '未知')} |
| 包大小 | {ipa_size:.2f} MB |
| 分析时间 | {time.strftime('%Y-%m-%d %H:%M:%S')} |
| 第三方SDK包数 | {analysis_result['third_party_count']} 个 |
| 检测到域名数 | {analysis_result.get('total_domains', 0)} 个 |
| Framework数 | {analysis_result.get('frameworks_count', 0)} 个 |
| **隐私政策相关SDK** | **{len(privacy_sdks)} 个** |
| **需列出的开源SDK** | **{open_source_count} 个** |
| 其他功能SDK | {other_sdk_count} 个 |

### 隐私SDK置信度分布

| 置信度 | 数量 | 说明 |
|:---|---:|:---|
| 高 | {privacy_high} 个 | 多维度证据充分确认，建议必须披露 |
| 中 | {privacy_medium} 个 | 有匹配证据，建议披露 |
| 低 | {privacy_low} 个 | 仅有弱匹配证据，需人工确认 |

### 隐私SDK分类统计

"""
    if privacy_by_category:
        for cat, count in sorted(privacy_by_category.items(), key=lambda x: -x[1]):
            content += f"- {cat}: {count} 个\n"
    else:
        content += "- 未检测到\n"

    content += """---

## 一、隐私政策需要列出的SDK

> 以下SDK会收集或处理用户数据，请在隐私政策中披露。置信度越高，检测结果越可靠。

"""

    if privacy_sdks:
        # 按置信度排序：高 > 中 > 低
        level_order = {'high': 0, 'medium': 1, 'low': 2}
        sorted_sdks = sorted(privacy_sdks, key=lambda x: (level_order.get(x['confidence']['level'], 9), -x['confidence']['score']))

        categories = defaultdict(list)
        for sdk in sorted_sdks:
            categories[sdk.get('category', '其他')].append(sdk)

        for category, sdks in sorted(categories.items()):
            content += f"### {category}\n\n"
            for sdk in sdks:
                conf = sdk['confidence']
                badge = _confidence_badge(conf)
                content += f"**{sdk['sdk_name']}** ({sdk['match_count']} 个匹配) {badge}\n\n"

                all_matches = sdk['matched_packages'] + sdk['matched_frameworks']
                for item in all_matches[:5]:
                    content += f"- `{item}`\n"
                if len(all_matches) > 5:
                    content += f"- ... 等 {len(all_matches) - 5} 个\n"

                if sdk.get('evidence'):
                    content += f"\n匹配证据 ({len(sdk['evidence'])}条):\n\n"
                    content += _evidence_summary(sdk['evidence'])
                    content += "\n\n"
                content += "\n"
    else:
        content += "未检测到明显的隐私相关SDK。\n\n"

    content += """---

## 二、需在隐私政策中列出的开源SDK

> 以下开源SDK会收集或处理用户个人信息，建议在隐私政策的"开源SDK"部分中列出。

"""

    if open_source_sdks:
        categories = defaultdict(list)
        for sdk in open_source_sdks:
            categories[sdk.get('category', '其他')].append(sdk)

        for category, sdks in sorted(categories.items()):
            content += f"### {category}\n\n"
            for sdk in sdks:
                conf = sdk['confidence']
                badge = _confidence_badge(conf)
                content += f"**{sdk['sdk_name']}** [开源] ({sdk['match_count']} 个匹配) {badge}\n\n"
                all_matches = sdk['matched_packages'] + sdk['matched_frameworks']
                for item in all_matches[:5]:
                    content += f"- `{item}`\n"
                content += "\n"
    else:
        content += "未检测到需要列出的开源SDK。\n\n"

    content += """---

## 三、其他第三方SDK

> 以下为功能性SDK，通常不需要在隐私政策中单独列出

"""

    if other_sdks:
        categories = defaultdict(list)
        for sdk in other_sdks:
            categories[sdk.get('category', '其他')].append(sdk)

        for category, sdks in sorted(categories.items()):
            content += f"### {category}\n\n"
            for sdk in sdks:
                content += f"**{sdk['sdk_name']}** ({sdk['match_count']} 个匹配)\n"
                all_matches = sdk['matched_packages'] + sdk['matched_frameworks']
                for item in all_matches[:3]:
                    content += f"- `{item}`\n"
                content += "\n"
    else:
        content += "无\n\n"

    content += f"""---

**检测摘要**: 隐私SDK {len(privacy_sdks)} (高置信:{privacy_high} | 中置信:{privacy_medium} | 低置信:{privacy_low}) | 开源SDK {open_source_count}
"""

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[OK] Report saved: {output_path}")

    return content


def analyze_apk(ipa_path, patterns):
    """分析入口"""
    return analyze_ipa(ipa_path, patterns)


def main():
    """主函数"""
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    if len(sys.argv) < 2:
        print("iOS IPA 第三方SDK分析工具 v1.0")
        print("\n使用方法:")
        print("  python ios_sdk_analyzer.py <IPA文件路径> [输出报告路径]")
        sys.exit(1)

    ipa_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(ipa_path):
        print(f"[ERROR] File not found: {ipa_path}")
        sys.exit(1)

    config_path = get_config_path('ios_sdk_patterns.json')
    patterns = load_patterns(config_path)

    print("=" * 60)
    print("iOS IPA 第三方SDK分析工具 v1.0")
    print("=" * 60)

    result = analyze_ipa(ipa_path, patterns)

    if output_path:
        generate_report(ipa_path, result, output_path)
    else:
        report = generate_report(ipa_path, result)
        print("\n" + report)

    print("\n" + "=" * 60)
    print(f"检测结果:")
    print(f"  - 隐私相关SDK: {len(result['privacy_sdks'])} 个")
    print(f"    - 高置信度: {len([s for s in result['privacy_sdks'] if s['confidence']['level'] == 'high'])} 个")
    print(f"    - 中置信度: {len([s for s in result['privacy_sdks'] if s['confidence']['level'] == 'medium'])} 个")
    print(f"    - 低置信度: {len([s for s in result['privacy_sdks'] if s['confidence']['level'] == 'low'])} 个")
    print(f"  - 开源SDK: {len(result.get('open_source_sdks', []))} 个")
    print(f"  - 其他功能SDK: {len(result['other_sdks'])} 个")
    print("=" * 60)


if __name__ == '__main__':
    main()

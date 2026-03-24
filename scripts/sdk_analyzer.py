"""
APK 第三方SDK分析脚本 v2.0
支持多维度匹配：包名 + 方法签名 + URL域名 + 字符串常量 + 置信度评估
"""

import sys
import os
import zipfile
import re
import time
import json
from collections import defaultdict


def load_patterns(config_path):
    """加载SDK特征库配置"""
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)


# =============================================================================
# 第一阶段：数据提取
# =============================================================================

def extract_manifest_components(apk_path):
    """从APK中提取AndroidManifest的组件信息"""
    components = {
        'activities': [],
        'services': [],
        'receivers': [],
        'providers': [],
        'all_components': [],
        'meta_data': []
    }

    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            all_files = zf.namelist()

            # 从binary XML和DEX中提取组件名和元数据
            for name in all_files:
                if name.endswith('.xml') or name.endswith('.dex'):
                    try:
                        data = zf.read(name)
                        content = data.decode('utf-8', errors='ignore')

                        # 提取组件类名（Activity/Service/Receiver/Provider）
                        class_pattern = r'\b([a-z][a-z0-9_]*\.)+[A-Za-z][A-Za-z0-9_]*\b'
                        classes = re.findall(class_pattern, content)

                        for cls in classes:
                            cls_lower = cls.lower()
                            if any(kw in cls_lower for kw in ['activity', 'service', 'receiver', 'provider']):
                                if cls not in components['all_components']:
                                    components['all_components'].append(cls)
                                    if 'activity' in cls_lower:
                                        components['activities'].append(cls)
                                    elif 'service' in cls_lower:
                                        components['services'].append(cls)
                                    elif 'receiver' in cls_lower:
                                        components['receivers'].append(cls)
                                    elif 'provider' in cls_lower:
                                        components['providers'].append(cls)
                    except:
                        continue

            # 从resources.arsc提取资源字符串（包含meta-data的name/value）
            try:
                resources_data = zf.read('resources.arsc')
                res_str = resources_data.decode('utf-8', errors='ignore')

                # 提取meta-data键值对（android:name="xxx" android:value="yyy"）
                meta_pattern = r'(?:android:name|name)="([^"]{3,80})"'
                meta_matches = re.findall(meta_pattern, res_str)
                components['meta_data'].extend([s for s in meta_matches if len(s) > 3])

                # 提取包名
                pkg_pattern = r'([a-z][a-z0-9_]*\.)+[A-Za-z][A-Za-z0-9_]*'
                pkg_matches = re.findall(pkg_pattern, res_str)
                for cls in pkg_matches:
                    if cls not in components['all_components']:
                        components['all_components'].append(cls)
            except:
                pass

            # 去重
            for key in ['activities', 'services', 'receivers', 'providers', 'all_components', 'meta_data']:
                components[key] = list(set(components[key]))

    except Exception as e:
        print(f"[WARN] Error parsing manifest: {e}")

    return components


def _extract_urls_from_dex(dex_str):
    """从DEX数据中提取URL域名"""
    domains = set()

    # TLD列表（常用）
    TLDS = 'com|cn|net|org|io|me|in|ru|fr|de|jp|kr|es|it|br|au|ca|us|gov|edu|biz|info|pro|tv|cc|co|hk|tw|sg|uk|eu|top|xyz|site|online|tech|store|app|dev|cloud|live|video|game|shop|club|icu|vip|red|link|ink|work|fun|art|design|ltd|group|world|zone|center|space|market|life|today|one|asia|mobi|name|tel'

    # 模式1: 匹配 http(s)://xxx.yyy.zzz
    url_pattern = r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.(?:' + TLDS + r')(?:\.[a-zA-Z]{2,4})?)'
    for match in re.findall(url_pattern, dex_str, re.IGNORECASE):
        domain = match.lower().split('/')[0]  # 取域名部分
        if len(domain) > 4:
            domains.add(domain)

    # 模式2: 匹配纯域名（含子域名），至少3段
    bare_pattern = r'\b([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+(?:' + TLDS + r')(?:\.[a-zA-Z]{2,4})?)\b'
    for match in re.findall(bare_pattern, dex_str, re.IGNORECASE):
        domain = match.lower()
        # 过滤掉太短或明显不是域名的
        parts = domain.split('.')
        if len(parts) >= 3 and len(domain) > 8:
            domains.add(domain)

    return domains


def _extract_strings_from_dex(dex_data):
    """从DEX数据中提取包名（Smali格式和Java格式）"""
    strings = set()

    try:
        dex_str = dex_data.decode('utf-8', errors='ignore')

        # Smali格式类名: Lcom/example/Class;
        smali_pattern = r'L((?:com|org|net|io|me|in|cn|uk|de|ru|fr|jp|kr|es|it|br|au|ca|us|gov|edu|biz|info|pro|tv|cc|co)[.][a-zA-Z0-9_/]+);'
        smali_matches = re.findall(smali_pattern, dex_str)
        for match in smali_matches:
            pkg = match.replace('/', '.')
            if pkg and len(pkg) > 5:
                strings.add(pkg)

        # Java格式包名
        java_pattern = r'\b((?:com|org|net|io|me|in|cn|uk|de|ru|fr|jp|kr|es|it|br|au|ca|us|gov|edu|biz|info|pro|tv|cc|co)[.][a-z][a-z0-9_]*([.][a-zA-Z0-9_]+)*)\b'
        java_matches = re.findall(java_pattern, dex_str)
        for match in java_matches:
            if isinstance(match, tuple):
                pkg = match[0]
            else:
                pkg = match
            if pkg and len(pkg) > 5:
                strings.add(pkg)
    except:
        pass

    return strings


def extract_all_strings_from_dex(dex_data):
    """从DEX中提取所有可读字符串（方法签名、URL、类名）"""
    strings = set()

    try:
        dex_str = dex_data.decode('utf-8', errors='ignore')

        # 方法签名: com.xxx.ClassName.method(params)Return
        method_pattern = r'([a-zA-Z][a-zA-Z0-9_]*\.)*[a-zA-Z][a-zA-Z0-9_]*\([a-zA-Z0-9_.\[\];]*\)[a-zA-Z0-9_.\[\];]*'
        method_matches = re.findall(method_pattern, dex_str)
        for m in method_matches:
            if len(m) > 5:
                strings.add(m)

        # URL域名
        strings.update(_extract_urls_from_dex(dex_str))

        # Smali类名
        class_pattern = r'\bL([a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z][a-zA-Z0-9_]*)*);\b'
        class_matches = re.findall(class_pattern, dex_str)
        for match in class_matches:
            pkg = match.replace('/', '.')
            strings.add(pkg)

        # SDK特征字符串常量（如 meta-data 的 value, SDK version strings 等）
        # 匹配 "xxx_sdk" 或 "xxxSDK" 等典型的SDK标识字符串
        sdk_id_pattern = r'"([a-zA-Z][a-zA-Z0-9_]*(?:[Ss][Dd][Kk]|_sdk|_SDK|_key|_KEY|_appkey|_APPKEY|_appid|_APPID|_version|_VERSION|_secret|_SECRET|_token|_TOKEN)[a-zA-Z0-9_]*)"'
        sdk_id_matches = re.findall(sdk_id_pattern, dex_str)
        for m in sdk_id_matches:
            if len(m) > 4:
                strings.add(m)

    except:
        pass

    return strings


def extract_from_classes_jar(zf, jar_path):
    """从JAR中提取classes.dex并解析"""
    classes_data = []
    try:
        import io
        jar_data = zf.read(jar_path)
        with zipfile.ZipFile(io.BytesIO(jar_data), 'r') as inner_jar:
            for name in inner_jar.namelist():
                if name.startswith('classes') and name.endswith('.dex'):
                    classes_data.append(inner_jar.read(name))
        if not classes_data and jar_path.endswith('.dex'):
            classes_data.append(jar_data)
    except:
        pass
    return classes_data


def extract_all_packages(apk_path):
    """从APK文件中提取所有包名、字符串和URL域名"""
    packages = set()
    all_strings = set()
    all_domains = set()
    dex_contents = []

    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            all_files = zf.namelist()
            dex_files = [f for f in all_files if f.endswith('.dex')]

            # 从DEX文件提取
            for dex_name in dex_files:
                try:
                    dex_data = zf.read(dex_name)
                    dex_contents.append(dex_data)
                    packages.update(_extract_strings_from_dex(dex_data))
                    all_strings.update(extract_all_strings_from_dex(dex_data))
                    all_domains.update(_extract_urls_from_dex(dex_data.decode('utf-8', errors='ignore')))
                except:
                    continue

            # 从JAR/AAR中提取
            for name in all_files:
                if name.endswith('.jar') or name.endswith('.aar'):
                    try:
                        jar_classes = extract_from_classes_jar(zf, name)
                        for dex_data in jar_classes:
                            dex_contents.append(dex_data)
                            all_strings.update(extract_all_strings_from_dex(dex_data))
                            all_domains.update(_extract_urls_from_dex(dex_data.decode('utf-8', errors='ignore')))
                    except:
                        continue

                if 'classes' in name and ('.jar' in name or '.dex' in name):
                    try:
                        data = zf.read(name)
                        all_strings.update(extract_all_strings_from_dex(data))
                    except:
                        continue

            # 从XML等文件提取包名
            for name in all_files:
                if any(x in name for x in ['classes', 'jar', 'xml']):
                    try:
                        data = zf.read(name)
                        data_str = data.decode('utf-8', errors='ignore')
                        # 复用smali/java包名模式
                        smali_pattern = r'L((?:com|org|net|io|me|in|cn|uk|de|ru|fr|jp|kr|es|it|br|au|ca|us|gov|edu|biz|info|pro|tv|cc|co)[.][a-zA-Z0-9_/]+);'
                        smali_matches = re.findall(smali_pattern, data_str)
                        for match in smali_matches:
                            pkg = match.replace('/', '.')
                            if pkg and len(pkg) > 5:
                                packages.add(pkg)

                        java_pattern = r'\b((?:com|org|net|io|me|in|cn|uk|de|ru|fr|jp|kr|es|it|br|au|ca|us|gov|edu|biz|info|pro|tv|cc|co)[.][a-z][a-z0-9_]*([.][a-zA-Z0-9_]+)*)\b'
                        java_matches = re.findall(java_pattern, data_str)
                        for match in java_matches:
                            if isinstance(match, tuple):
                                pkg = match[0]
                            else:
                                pkg = match
                            if pkg and len(pkg) > 5:
                                packages.add(pkg)

                        # 也提取域名
                        all_domains.update(_extract_urls_from_dex(data_str))
                    except:
                        continue

    except zipfile.BadZipFile:
        print(f"[ERROR] Invalid APK file: {apk_path}")
        return set(), set(), set(), []
    except Exception as e:
        print(f"[ERROR] Error reading APK: {str(e)}")
        return set(), set(), set(), []

    return packages, all_strings, all_domains, dex_contents


# =============================================================================
# 第二阶段：匹配引擎（统一多维度 + 置信度）
# =============================================================================

def _keyword_match_score(pkg_or_string, keywords):
    """
    计算关键词匹配得分。
    返回 (matched: bool, best_score: int, match_type: str, matched_keyword: str)
    
    匹配类型和对应分值：
    - 完整包名前缀匹配: +40 (如 com.tencent.mm 与 com.tencent.mm.opensdk)
    - 包含多个关键点: +30 (如 com.umeng.umsdk.analytics 包含 umeng 和 analytics)
    - 单关键词匹配: +15 (如包名中含 "tencent")
    - 模糊关键词: +5  (如不含点号的关键词出现在字符串任意位置)
    """
    if not pkg_or_string:
        return False, 0, '', ''

    text_lower = pkg_or_string.lower()
    best_score = 0
    best_type = ''
    best_keyword = ''

    for keyword in keywords:
        kw_lower = keyword.lower()
        if not kw_lower:
            continue

        if kw_lower in text_lower:
            score = 0
            match_type = ''

            # 类型1: 包含点号的关键词 = 精确包名前缀/完整匹配
            if '.' in kw_lower:
                # 关键词越长（更精确），分数越高
                score = 30 + min(len(kw_lower.split('.')) * 5, 20)
                match_type = '包名精确'
            else:
                # 类型2: 短关键词
                score = 10
                match_type = '关键词'

            if score > best_score:
                best_score = score
                best_type = match_type
                best_keyword = kw_lower

    return best_score > 0, best_score, best_type, best_keyword


def filter_third_party_packages(packages, exclude_prefixes, exclude_patterns):
    """过滤出第三方包名"""
    third_party = set()
    for pkg in packages:
        should_exclude = False
        for prefix in exclude_prefixes:
            if pkg.startswith(prefix):
                should_exclude = True
                break
        if not should_exclude:
            for pattern in exclude_patterns:
                if pkg.startswith(pattern) or pattern in pkg:
                    should_exclude = True
                    break
        if not should_exclude and len(pkg) > 5:
            third_party.add(pkg)
    return third_party


def extract_root_packages(packages):
    """提取顶级包名"""
    root_packages = {}
    for pkg in packages:
        parts = pkg.split('.')
        if len(parts) >= 2:
            root = '.'.join(parts[:2])
            if root not in root_packages:
                root_packages[root] = []
            root_packages[root].append(pkg)
    return root_packages


def unified_match_sdk(packages, all_strings, all_domains, meta_data, sdks_dict):
    """
    统一多维度SDK匹配引擎
    
    维度：
    1. 包名匹配 (packages) - 最高权重
    2. 方法签名/字符串常量匹配 (all_strings) - 中权重
    3. URL域名匹配 (all_domains) - 中权重
    4. meta-data匹配 (meta_data) - 低权重但确定性高
    
    返回: {sdk_name: {category, score, evidence: [{type, detail}], packages: []}}
    """
    results = {}

    for category, sdks in sdks_dict.items():
        for sdk_name, keywords in sdks.items():
            evidence = []
            matched_packages = set()

            # 维度1: 包名匹配
            for pkg in packages:
                matched, score, match_type, kw = _keyword_match_score(pkg, keywords)
                if matched:
                    matched_packages.add(pkg)
                    evidence.append({
                        'type': '包名',
                        'detail': pkg,
                        'score': score,
                        'match_type': match_type,
                        'keyword': kw
                    })

            # 维度2: 字符串常量/方法签名匹配
            for s in all_strings:
                matched, score, match_type, kw = _keyword_match_score(s, keywords)
                if matched and score >= 15:
                    evidence.append({
                        'type': '字符串/方法',
                        'detail': s[:80],
                        'score': max(score - 5, 5),  # 字符串证据降一档
                        'match_type': match_type,
                        'keyword': kw
                    })

            # 维度3: URL域名匹配
            for domain in all_domains:
                matched, score, match_type, kw = _keyword_match_score(domain, keywords)
                if matched:
                    evidence.append({
                        'type': 'URL域名',
                        'detail': domain,
                        'score': 20,  # 域名匹配确定性高
                        'match_type': '域名',
                        'keyword': kw
                    })

            # 维度4: meta-data匹配
            for meta in meta_data:
                matched, score, match_type, kw = _keyword_match_score(meta, keywords)
                if matched:
                    evidence.append({
                        'type': 'meta-data',
                        'detail': meta,
                        'score': 25,
                        'match_type': 'meta-data',
                        'keyword': kw
                    })

            if evidence:
                # 去重evidence（按detail去重）
                seen = set()
                unique_evidence = []
                for e in evidence:
                    key = e['detail'][:50]
                    if key not in seen:
                        seen.add(key)
                        unique_evidence.append(e)

                # 计算总置信度
                total_score = sum(e['score'] for e in unique_evidence)
                evidence_types = set(e['type'] for e in unique_evidence)

                # 多维度加分
                if len(evidence_types) >= 3:
                    total_score += 15
                elif len(evidence_types) >= 2:
                    total_score += 8

                results[sdk_name] = {
                    'category': category,
                    'score': total_score,
                    'evidence_count': len(unique_evidence),
                    'evidence': unique_evidence,
                    'matched_packages': sorted(matched_packages),
                    'match_count': len(matched_packages)
                }

    return results


def classify_confidence(score, evidence_count, evidence_types):
    """
    根据匹配置信度分类
    
    返回: (level, label, description)
    """
    types = len(evidence_types) if evidence_types else 0

    if score >= 60 and evidence_count >= 3:
        return 'high', '高', '多维度证据充分确认'
    elif score >= 40 and evidence_count >= 2:
        return 'high', '高', '包名精确匹配+辅助证据'
    elif score >= 25 and types >= 2:
        return 'medium', '中', '多类型证据交叉验证'
    elif score >= 20 and evidence_count >= 2:
        return 'medium', '中', '有匹配证据，建议确认'
    elif score >= 10:
        return 'low', '低', '仅有弱匹配证据，需人工确认'
    else:
        return 'low', '低', '证据不足'


def find_unknown_sdks(third_party_packages, known_sdks):
    """发现未知SDK"""
    known_patterns = set()
    for category, sdks in known_sdks.items():
        for sdk_name, keywords in sdks.items():
            for keyword in keywords:
                known_patterns.add(keyword.lower())

    root_packages = extract_root_packages(third_party_packages)
    unknown_sdks = []

    for root, packages in root_packages.items():
        root_lower = root.lower()
        is_known = False
        for pattern in known_patterns:
            if pattern in root_lower or root_lower in pattern:
                is_known = True
                break
        if not is_known:
            unique_packages = sorted(set(packages))
            unknown_sdks.append({
                'root_package': root,
                'matched_packages': unique_packages,
                'match_count': len(unique_packages)
            })

    unknown_sdks.sort(key=lambda x: x['match_count'], reverse=True)
    return unknown_sdks


def is_privacy_sdk(root_package, privacy_keywords):
    """判断未知SDK是否可能需要隐私政策披露"""
    root = root_package.lower()
    for keyword in privacy_keywords:
        if keyword in root:
            return True
    return False


def guess_sdk_type(root_package):
    """根据包名猜测SDK类型"""
    root = root_package.lower()
    type_hints = [
        (['gdt', 'qq.e'], '广告/优量汇'),
        (['pangle', 'bytedance'], '广告/穿山甲'),
        (['ksad', 'kuaishou'], '广告/快手'),
        (['sigmob'], '广告/Sigmob'),
        (['tobid'], '广告/ToBid'),
        (['mintegral'], '广告/Mintegral'),
        (['applovin'], '广告/AppLovin'),
        (['meishu'], '广告/美数'),
        (['lingye'], '广告/领页'),
        (['qiyun'], '广告/奇运'),
        (['fancy'], '广告/Fancy'),
        (['wangmai'], '广告/旺脉'),
        (['octopus'], '广告/Octopus'),
        (['hxad'], '广告/HX'),
        (['menta'], '广告/Menta'),
        (['qumeng'], '广告/趣盟'),
        (['befan'], '广告/孛樊'),
        (['mimob'], '广告/米盟'),
        (['huawei', 'hwid'], '华为相关'),
        (['xiaomi', 'mipush'], '推送/小米'),
        (['vivo'], '推送/VIVO'),
        (['meizu'], '推送/魅族'),
        (['amap'], '地图/高德'),
        (['baidu', 'lbsapi'], '地图/百度'),
        (['tencent', 'qq'], '腾讯相关'),
        (['sina', 'weibo'], '社交/微博'),
        (['alipay'], '支付/支付宝'),
        (['jiguang', 'jpush'], '推送/极光'),
        (['agora'], '视频/声网'),
        (['zego'], '视频/即构'),
        (['glide'], '图片/Glide'),
        (['retrofit', 'okhttp'], '网络库'),
        (['react'], '跨平台/React'),
        (['flutter'], '跨平台/Flutter'),
    ]
    for keywords, sdk_type in type_hints:
        for keyword in keywords:
            if keyword in root:
                return sdk_type
    return '未知/第三方库'


# =============================================================================
# 第三阶段：分析主函数
# =============================================================================

def analyze_apk(apk_path, patterns):
    """APK分析主函数（v2.0 多维度匹配）"""
    print(f"[INFO] Analyzing APK: {apk_path}")

    # 1. 数据提取
    print("[INFO] Extracting packages, strings and domains...")
    all_packages, all_strings, all_domains, dex_contents = extract_all_packages(apk_path)
    print(f"[INFO] Found {len(all_packages)} packages, {len(all_strings)} strings, {len(all_domains)} domains")

    print("[INFO] Parsing AndroidManifest...")
    manifest_components = extract_manifest_components(apk_path)
    component_count = len(manifest_components.get('all_components', []))
    meta_data = manifest_components.get('meta_data', [])
    print(f"[INFO] Found {component_count} manifest components, {len(meta_data)} meta-data entries")

    # 2. 过滤第三方包
    print("[INFO] Filtering third-party packages...")
    exclude_patterns = []
    for cat, items in patterns['exclude_patterns'].items():
        exclude_patterns.extend(items)

    third_party = filter_third_party_packages(all_packages, patterns['exclude_prefixes'], exclude_patterns)
    print(f"[INFO] Found {len(third_party)} third-party packages")

    # 3. 统一多维度匹配
    print("[INFO] Running unified multi-dimension matching...")
    privacy_sdks_dict = {**patterns['privacy_sdk_patterns']}
    uncertain_sdks_dict = {**patterns.get('uncertain_sdk_patterns', {})}

    # 先匹配隐私SDK
    privacy_results = unified_match_sdk(
        third_party, all_strings, all_domains, meta_data, privacy_sdks_dict)

    # 收集隐私SDK匹配的包名，确保优先级
    privacy_matched_packages = set()
    for sdk_name, info in privacy_results.items():
        privacy_matched_packages.update(info['matched_packages'])

    # 待确认SDK：只匹配不在隐私SDK中的包
    remaining_packages = third_party - privacy_matched_packages
    uncertain_results = unified_match_sdk(
        remaining_packages, all_strings, all_domains, meta_data, uncertain_sdks_dict)

    uncertain_matched_packages = set()
    for sdk_name, info in uncertain_results.items():
        uncertain_matched_packages.update(info['matched_packages'])

    # 其他功能SDK
    remaining_packages = third_party - privacy_matched_packages - uncertain_matched_packages
    other_results = unified_match_sdk(
        remaining_packages, all_strings, all_domains, meta_data, patterns['sdk_patterns'])

    # 开源SDK匹配
    open_source_sdks_dict = patterns.get('open_source_sdk_patterns', {})
    open_source_results = unified_match_sdk(
        third_party, all_strings, all_domains, meta_data, open_source_sdks_dict)

    # 将开源SDK从其他SDK中排除，避免重复
    open_source_matched_packages = set()
    for sdk_name, info in open_source_results.items():
        open_source_matched_packages.update(info['matched_packages'])
    other_results = {k: v for k, v in other_results.items()
                     if not open_source_matched_packages.intersection(v['matched_packages'])}

    # 4. 按置信度分类并构建结果
    privacy_matches = []
    for sdk_name, info in privacy_results.items():
        evidence_types = set(e['type'] for e in info['evidence'])
        level, label, desc = classify_confidence(info['score'], info['evidence_count'], evidence_types)
        privacy_matches.append({
            'category': info['category'],
            'sdk_name': sdk_name,
            'matched_packages': info['matched_packages'],
            'match_count': info['match_count'],
            'confidence': {'level': level, 'label': label, 'desc': desc, 'score': info['score']},
            'evidence': info['evidence'][:5]  # 最多保留5条证据
        })

    uncertain_matches = []
    for sdk_name, info in uncertain_results.items():
        evidence_types = set(e['type'] for e in info['evidence'])
        level, label, desc = classify_confidence(info['score'], info['evidence_count'], evidence_types)
        uncertain_matches.append({
            'category': info['category'],
            'sdk_name': sdk_name,
            'matched_packages': info['matched_packages'],
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
            'match_count': info['match_count'],
            'confidence': {'level': level, 'label': label, 'desc': desc, 'score': info['score']},
            'evidence': info['evidence'][:5]
        })

    # 开源SDK匹配结果
    open_source_matches = []
    for sdk_name, info in open_source_results.items():
        evidence_types = set(e['type'] for e in info['evidence'])
        level, label, desc = classify_confidence(info['score'], info['evidence_count'], evidence_types)
        open_source_matches.append({
            'category': info['category'],
            'sdk_name': sdk_name,
            'matched_packages': info['matched_packages'],
            'match_count': info['match_count'],
            'confidence': {'level': level, 'label': label, 'desc': desc, 'score': info['score']},
            'evidence': info['evidence'][:5]
        })

    # 5. 未知SDK（排除已知的隐私SDK、待确认SDK、其他SDK和开源SDK）
    all_known_sdks = {**privacy_sdks_dict, **uncertain_sdks_dict, **patterns['sdk_patterns'], **open_source_sdks_dict}
    unknown_matches = find_unknown_sdks(third_party, all_known_sdks)
    privacy_unknown = [sdk for sdk in unknown_matches if is_privacy_sdk(sdk['root_package'], patterns['privacy_keywords'])]

    # 统计
    high_conf = len([s for s in privacy_matches if s['confidence']['level'] == 'high'])
    medium_conf = len([s for s in privacy_matches if s['confidence']['level'] == 'medium'])
    low_conf = len([s for s in privacy_matches if s['confidence']['level'] == 'low'])

    print(f"[INFO] Privacy SDKs: {len(privacy_matches)} (High:{high_conf} Medium:{medium_conf} Low:{low_conf})")
    print(f"[INFO] Uncertain SDKs: {len(uncertain_matches)}")
    print(f"[INFO] Other SDKs: {len(other_matches)}")
    print(f"[INFO] Open Source SDKs: {len(open_source_matches)}")
    print(f"[INFO] Unknown SDKs: {len(unknown_matches)}")

    return {
        'total_packages': len(all_packages),
        'total_domains': len(all_domains),
        'third_party_count': len(third_party),
        'privacy_sdks': privacy_matches,
        'uncertain_sdks': uncertain_matches,
        'other_sdks': other_matches,
        'open_source_sdks': open_source_matches,
        'unknown_sdks': unknown_matches,
        'privacy_unknown_sdks': privacy_unknown,
        'manifest_component_count': component_count,
    }


# =============================================================================
# 第四阶段：报告生成
# =============================================================================

def _confidence_badge(confidence):
    """生成置信度标签（纯文本）"""
    level = confidence.get('level', 'low')
    label = confidence.get('label', '低')
    score = confidence.get('score', 0)
    return f'[{label}置信 {score}分]'


def _evidence_summary(evidence_list):
    """生成证据摘要"""
    if not evidence_list:
        return ""

    type_labels = {'包名': '包名', '字符串/方法': '方法', 'URL域名': '域名', 'meta-data': '配置'}
    lines = []
    for e in evidence_list[:4]:
        t = type_labels.get(e['type'], e['type'])
        detail = e['detail'][:60]
        lines.append(f"  - [{t}] `{detail}`")

    if len(evidence_list) > 4:
        lines.append(f"  - ... 等 {len(evidence_list)} 条证据")

    return '\n'.join(lines)


def generate_report(apk_path, analysis_result, output_path=None, app_info=None):
    """生成报告

    Args:
        apk_path: APK文件路径
        analysis_result: 分析结果
        output_path: 输出路径
        app_info: 应用信息字典 {package, versionCode, versionName}
    """
    apk_name = os.path.basename(apk_path)
    apk_size = os.path.getsize(apk_path) / (1024 * 1024)

    # 获取应用信息
    if app_info is None:
        app_info = {
            'package': '未知',
            'versionCode': '未知',
            'versionName': '未知'
        }

    privacy_sdks = analysis_result.get('privacy_sdks', [])
    uncertain_sdks = analysis_result.get('uncertain_sdks', [])
    unknown_sdks = analysis_result['unknown_sdks']
    privacy_unknown = analysis_result.get('privacy_unknown_sdks', [])
    open_source_sdks = analysis_result.get('open_source_sdks', [])

    # 分类统计
    privacy_by_category = defaultdict(int)
    for sdk in privacy_sdks:
        privacy_by_category[sdk.get('category', '其他')] += 1

    uncertain_by_category = defaultdict(int)
    for sdk in uncertain_sdks:
        uncertain_by_category[sdk.get('category', '其他')] += 1

    # 置信度统计
    privacy_high = len([s for s in privacy_sdks if s['confidence']['level'] == 'high'])
    privacy_medium = len([s for s in privacy_sdks if s['confidence']['level'] == 'medium'])
    privacy_low = len([s for s in privacy_sdks if s['confidence']['level'] == 'low'])

    open_source_count = len(open_source_sdks)
    other_sdk_count = len(analysis_result.get('other_sdks', []))

    # 分类统计
    privacy_by_category = defaultdict(int)
    for sdk in privacy_sdks:
        privacy_by_category[sdk.get('category', '其他')] += 1

    uncertain_by_category = defaultdict(int)
    for sdk in uncertain_sdks:
        uncertain_by_category[sdk.get('category', '其他')] += 1

    content = f"""# APK 第三方SDK分析报告

## 汇总信息

| 项目 | 数值 |
|:---|---:|
| 包名 | {app_info.get('package', '未知')} |
| 包版本 | {app_info.get('versionName', '未知')} |
| 包大小 | {apk_size:.2f} MB |
| 分析时间 | {time.strftime('%Y-%m-%d %H:%M:%S')} |
| 第三方包总数 | {analysis_result['third_party_count']} 个 |
| 检测到域名数 | {analysis_result.get('total_domains', 0)} 个 |
| Manifest组件数 | {analysis_result['manifest_component_count']} 个 |
| **隐私政策相关SDK** | **{len(privacy_sdks)} 个** |
| 待确认SDK | {len(uncertain_sdks)} 个 |
| **需列出的开源SDK** | **{open_source_count} 个** |
| 其他功能SDK | {other_sdk_count} 个 |
| 未知SDK | {len(unknown_sdks)} 个 |

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

    if uncertain_by_category:
        content += f"\n### 待确认SDK分类统计\n\n"
        for cat, count in sorted(uncertain_by_category.items(), key=lambda x: -x[1]):
            content += f"- {cat}: {count} 个\n"

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
                content += f"**{sdk['sdk_name']}** ({sdk['match_count']} 个包) {badge}\n\n"
                for pkg in sdk['matched_packages'][:5]:
                    content += f"- `{pkg}`\n"
                if sdk['match_count'] > 5:
                    content += f"- ... 等 {sdk['match_count'] - 5} 个\n"

                # 展示证据摘要
                if sdk.get('evidence'):
                    content += f"\n匹配证据 ({len(sdk['evidence'])}条):\n\n"
                    content += _evidence_summary(sdk['evidence'])
                    content += "\n\n"
                content += "\n"
    else:
        content += "未检测到明显的隐私相关SDK。\n\n"

    content += """---

## 二、待确认SDK

> 以下SDK可能是框架自带、适配层或常量定义，需人工确认是否实际使用。

"""

    if uncertain_sdks:
        categories = defaultdict(list)
        for sdk in uncertain_sdks:
            categories[sdk.get('category', '其他')].append(sdk)

        for category, sdks in sorted(categories.items()):
            content += f"### {category}\n\n"
            for sdk in sdks:
                conf = sdk['confidence']
                badge = _confidence_badge(conf)
                content += f"**{sdk['sdk_name']}** ({sdk['match_count']} 个包) {badge}\n\n"
                for pkg in sdk['matched_packages'][:5]:
                    content += f"- `{pkg}`\n"
                if sdk['match_count'] > 5:
                    content += f"- ... 等 {sdk['match_count'] - 5} 个\n"
                content += "\n"

        content += """### 确认建议

> 如确认manifest.json中未启用相关模块，且代码中未调用对应能力，可不披露。

"""
    else:
        content += "未检测到需要确认的SDK。\n\n"

    # 开源SDK章节
    content += """---

## 三、需在隐私政策中列出的开源SDK

> 以下开源SDK会收集或处理用户个人信息（如网络请求获取IP、读取设备信息等），建议在隐私政策的"开源SDK"部分中列出。

"""

    if open_source_sdks:
        # 按分类分组
        categories = defaultdict(list)
        for sdk in open_source_sdks:
            categories[sdk.get('category', '其他')].append(sdk)

        for category, sdks in sorted(categories.items()):
            content += f"### {category}\n\n"
            for sdk in sdks:
                conf = sdk['confidence']
                badge = _confidence_badge(conf)
                # SDK名称后标注"[开源]"
                content += f"**{sdk['sdk_name']}** [开源] ({sdk['match_count']} 个包) {badge}\n\n"
                for pkg in sdk['matched_packages'][:5]:
                    content += f"- `{pkg}`\n"
                if sdk['match_count'] > 5:
                    content += f"- ... 等 {sdk['match_count'] - 5} 个\n"
                content += "\n"
    else:
        content += "未检测到需要列出的开源SDK。\n\n"

    if privacy_unknown:
        content += """---

## 四、可能涉及隐私的未知SDK

> 以下未知SDK包名包含隐私相关关键词，建议检查确认

"""
        for sdk in privacy_unknown[:5]:
            possible_type = guess_sdk_type(sdk['root_package'])
            content += f"**{sdk['root_package']}** - {possible_type} ({sdk['match_count']} 个包)\n"
        content += "\n"

    content += """---

## 五、其他第三方SDK

> 以下为功能性SDK，通常不需要在隐私政策中单独列出

"""

    non_privacy_sdks = analysis_result.get('other_sdks', [])

    if non_privacy_sdks:
        categories = defaultdict(list)
        for sdk in non_privacy_sdks:
            categories[sdk.get('category', '其他')].append(sdk)

        for category, sdks in sorted(categories.items()):
            content += f"### {category}\n\n"
            for sdk in sdks:
                content += f"**{sdk['sdk_name']}** ({sdk['match_count']} 个包)\n"
                for pkg in sdk['matched_packages'][:3]:
                    content += f"- `{pkg}`\n"
                if sdk['match_count'] > 3:
                    content += f"- ... 等 {sdk['match_count'] - 3} 个\n"
                content += "\n"
    else:
        content += "无\n\n"

    non_privacy_unknown = [sdk for sdk in unknown_sdks if not is_privacy_sdk(sdk['root_package'], [])]
    if non_privacy_unknown:
        content += """### 其他未知SDK

"""
        for sdk in non_privacy_unknown[:5]:
            content += f"- `{sdk['root_package']}` ({sdk['match_count']} 个包)\n"
        if len(non_privacy_unknown) > 5:
            content += f"- ... 等 {len(non_privacy_unknown) - 5} 个\n"
        content += "\n"

    content += f"""---

**检测摘要**: 隐私SDK {len(privacy_sdks)} (高置信:{privacy_high} | 中置信:{privacy_medium} | 低置信:{privacy_low}) | 开源SDK {open_source_count} | 待确认SDK {len(uncertain_sdks)} | 未知SDK {len(unknown_sdks)}
"""

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"[OK] Report saved: {output_path}")

    return content


# =============================================================================
# 主函数
# =============================================================================

def main():
    """主函数"""
    if sys.platform == 'win32':
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

    if len(sys.argv) < 2:
        print("APK 第三方SDK分析脚本 v2.0")
        print("\n使用方法:")
        print("  python analyze_apk.py <apk文件路径> [输出报告路径]")
        sys.exit(1)

    apk_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(apk_path):
        print(f"[ERROR] File not found: {apk_path}")
        sys.exit(1)

    # 加载特征库配置
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, '..', 'config', 'sdk_patterns.json')
    patterns = load_patterns(config_path)

    print("=" * 60)
    print("APK 第三方SDK分析工具 v2.0 (多维度匹配)")
    print("=" * 60)

    result = analyze_apk(apk_path, patterns)

    if output_path:
        generate_report(apk_path, result, output_path)
    else:
        report = generate_report(apk_path, result)
        print("\n" + report)

    print("\n" + "=" * 60)
    print(f"检测结果:")
    print(f"  - 隐私相关SDK: {len(result['privacy_sdks'])} 个")
    print(f"    - 高置信度: {len([s for s in result['privacy_sdks'] if s['confidence']['level'] == 'high'])} 个")
    print(f"    - 中置信度: {len([s for s in result['privacy_sdks'] if s['confidence']['level'] == 'medium'])} 个")
    print(f"    - 低置信度: {len([s for s in result['privacy_sdks'] if s['confidence']['level'] == 'low'])} 个")
    print(f"  - 开源SDK: {len(result.get('open_source_sdks', []))} 个")
    print(f"  - 待确认SDK: {len(result['uncertain_sdks'])} 个")
    print(f"  - 其他功能SDK: {len(result['other_sdks'])} 个")
    print(f"  - 未知SDK: {len(result['unknown_sdks'])} 个")
    print("=" * 60)


if __name__ == '__main__':
    main()

"""
IPA 公共工具模块
提供 IPA 分析所需的共同功能：IPA读取、Info.plist解析、应用信息提取等
"""

import os
import re
import zipfile
import plistlib
from typing import Dict, List, Tuple, Optional, Any


# =============================================================================
# IPA 基础操作
# =============================================================================

def open_ipa(ipa_path: str) -> zipfile.ZipFile:
    """
    打开 IPA 文件

    Args:
        ipa_path: IPA文件路径

    Returns:
        ZipFile 对象

    Raises:
        FileNotFoundError: IPA文件不存在
        zipfile.BadZipFile: 非法的IPA文件
    """
    if not os.path.exists(ipa_path):
        raise FileNotFoundError(f"IPA文件不存在: {ipa_path}")

    if not ipa_path.lower().endswith('.ipa'):
        raise ValueError(f"文件不是IPA格式: {ipa_path}")

    return zipfile.ZipFile(ipa_path, 'r')


def is_valid_ipa(ipa_path: str) -> bool:
    """
    检查文件是否为有效的IPA

    Args:
        ipa_path: 文件路径

    Returns:
        bool: 是否有效
    """
    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            namelist = zf.namelist()
            # IPA文件通常包含Payload目录
            return any('Payload/' in name and name.endswith('.app/Info.plist') for name in namelist)
    except:
        return False


# =============================================================================
# Info.plist 解析
# =============================================================================

def find_info_plist(ipa_path: str) -> Optional[str]:
    """
    在IPA中查找Info.plist文件路径

    Args:
        ipa_path: IPA文件路径

    Returns:
        Info.plist在ZIP中的路径，失败返回None
    """
    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            namelist = zf.namelist()
            for name in namelist:
                if name.startswith('Payload/') and name.endswith('.app/Info.plist'):
                    return name
    except:
        pass
    return None


def extract_info_plist(ipa_path: str) -> Optional[Dict]:
    """
    从IPA中提取并解析Info.plist

    Args:
        ipa_path: IPA文件路径

    Returns:
        Info.plist字典，失败返回None
    """
    info_plist_path = find_info_plist(ipa_path)
    if not info_plist_path:
        return None

    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            plist_data = zf.read(info_plist_path)
            return plistlib.loads(plist_data)
    except Exception as e:
        print(f"[WARN] Failed to parse Info.plist: {e}")
        return None


def parse_app_info_from_plist(plist: Dict) -> Dict[str, Any]:
    """
    从Info.plist中解析应用基本信息

    Args:
        plist: Info.plist字典

    Returns:
        应用信息字典
    """
    app_info = {
        'package': plist.get('CFBundleIdentifier', '未知'),
        'versionCode': plist.get('CFBundleVersion', '未知'),  # iOS用CFBundleVersion
        'versionName': plist.get('CFBundleShortVersionString', '未知'),  # iOS用CFBundleShortVersionString
        'application': {
            'name': plist.get('CFBundleDisplayName', plist.get('CFBundleName', '未知')),
            'bundle_id': plist.get('CFBundleIdentifier', '未知'),
            'min_os': plist.get('MinimumOSVersion', '未知'),
        }
    }
    return app_info


# =============================================================================
# 权限提取
# =============================================================================

def extract_permissions_from_plist(plist: Dict) -> Tuple[List[str], Dict[str, str]]:
    """
    从Info.plist中提取权限列表及对应的说明文案

    iOS权限通常在NSAppTransportSecurity、NSLocation*、NSCamera*等键中

    Args:
        plist: Info.plist字典

    Returns:
        (权限列表, 权限说明文案字典) 元组
        权限说明文案格式: {权限名: 说明文案}
    """
    permissions = []
    permission_descriptions = {}

    # 标准的iOS权限键（带UsageDescription后缀）
    standard_permissions = [
        'NSLocationWhenInUseUsageDescription',
        'NSLocationAlwaysAndWhenInUseUsageDescription',
        'NSLocationAlwaysUsageDescription',
        'NSCameraUsageDescription',
        'NSMicrophoneUsageDescription',
        'NSPhotoLibraryUsageDescription',
        'NSPhotoLibraryAddUsageDescription',
        'NSContactsUsageDescription',
        'NSCalendarsUsageDescription',
        'NSCalendarsFullAccessUsageDescription',
        'NSRemindersUsageDescription',
        'NSAppleMusicUsageDescription',
        'NSHealthShareUsageDescription',
        'NSHealthUpdateUsageDescription',
        'NSHomeKitUsageDescription',
        'NSFaceIDUsageDescription',
        'NSBluetoothAlwaysUsageDescription',
        'NSBluetoothPeripheralUsageDescription',
        'NSLocalNetworkUsageDescription',
        'NSSpeechRecognitionUsageDescription',
        'NSMotionUsageDescription',
        'NSVideoSubscriberAccountUsageDescription',
        'NSUserTrackingUsageDescription',
    ]

    # 处理标准权限键
    for key in standard_permissions:
        if key in plist:
            perm_name = key.replace('UsageDescription', '')
            description = plist.get(key, '')
            if perm_name not in permissions:
                permissions.append(perm_name)
                permission_descriptions[perm_name] = description

    # 检查所有以NS开头的键，提取隐私相关权限（包括未在标准列表中的）
    for key in plist:
        if key.startswith('NS') and 'UsageDescription' in key:
            perm_name = key.replace('UsageDescription', '')
            description = plist.get(key, '')
            if perm_name not in permissions:
                permissions.append(perm_name)
                permission_descriptions[perm_name] = description
            elif description and not permission_descriptions.get(perm_name):
                # 如果已有权限但没有说明，补充说明
                permission_descriptions[perm_name] = description

    return permissions, permission_descriptions


def extract_frameworks(ipa_path: str) -> List[str]:
    """
    从IPA中提取使用的系统Framework

    Args:
        ipa_path: IPA文件路径

    Returns:
        Framework列表
    """
    frameworks = set()

    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            namelist = zf.namelist()

            # 查找Frameworks目录下的.dylib或.framework
            for name in namelist:
                if 'Frameworks/' in name:
                    if name.endswith('.dylib'):
                        # 提取dylib名称
                        lib_name = os.path.basename(name).replace('.dylib', '')
                        if not lib_name.startswith('lib'):
                            frameworks.add(lib_name)
                    elif name.endswith('.framework'):
                        fw_name = os.path.basename(name).replace('.framework', '')
                        frameworks.add(fw_name)

            # 从可执行文件或静态库中提取字符串（查找Framework引用）
            for name in namelist:
                if name.endswith('.app') or name.endswith('.dylib') or name.endswith('_nested'):
                    try:
                        data = zf.read(name)
                        content = data.decode('utf-8', errors='ignore')
                        # 匹配Framework名称
                        fw_pattern = r'/System/Library/Frameworks/([A-Za-z]+)\.framework'
                        matches = re.findall(fw_pattern, content)
                        for fw in matches:
                            frameworks.add(fw)
                    except:
                        continue

    except Exception as e:
        print(f"[WARN] Failed to extract frameworks: {e}")

    return sorted(frameworks)


def extract_third_party_sdks(ipa_path: str) -> Tuple[List[str], List[str]]:
    """
    从IPA中提取第三方SDK信息

    Args:
        ipa_path: IPA文件路径

    Returns:
        (第三方SDK列表, 所有字符串列表)
    """
    sdk_packages = set()
    all_strings = set()

    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            namelist = zf.namelist()

            # 查找.app包中的可执行文件和.dylib
            for name in namelist:
                if name.endswith('.app/') or '/SC_Info/' in name:
                    continue

                if name.endswith('.dylib') or name.endswith('_nested') or name.endswith('.appex'):
                    try:
                        data = zf.read(name)
                        content = data.decode('utf-8', errors='ignore')

                        # 提取字符串常量（SDK标识）
                        string_pattern = r'"([A-Za-z][A-Za-z0-9_]*(?:SDK|Framework|Adapter|Sdk)[A-Za-z0-9_]*)"'
                        matches = re.findall(string_pattern, content)
                        for m in matches:
                            if len(m) > 4:
                                sdk_packages.add(m.lower())

                        # 提取URL域名
                        url_pattern = r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,})'
                        domains = re.findall(url_pattern, content, re.IGNORECASE)
                        for d in domains:
                            if len(d) > 4:
                                all_strings.add(d.lower())

                        # 提取包名格式的字符串
                        pkg_pattern = r'\b((?:com|org|net|io|me|cn|uk|de)[.][a-zA-Z][a-zA-Z0-9_]*(?:[.][a-zA-Z0-9_]+)*)\b'
                        pkgs = re.findall(pkg_pattern, content, re.IGNORECASE)
                        for p in pkgs:
                            if len(p) > 8:
                                sdk_packages.add(p.lower())

                    except:
                        continue

    except Exception as e:
        print(f"[WARN] Failed to extract third party SDKs: {e}")

    return sorted(sdk_packages), sorted(all_strings)


# =============================================================================
# 主函数：获取应用信息和权限
# =============================================================================

def get_app_info_and_permissions(ipa_path: str) -> Tuple[Dict[str, Any], List[str], Dict[str, str]]:
    """
    获取应用信息、权限列表和权限说明文案

    Args:
        ipa_path: IPA文件路径

    Returns:
        (app_info, permissions, permission_descriptions) 元组
    """
    app_info = {
        'package': '未知',
        'versionCode': '未知',
        'versionName': '未知',
        'application': {
            'name': '未知',
            'bundle_id': '未知',
            'min_os': '未知'
        }
    }
    permissions = []
    permission_descriptions = {}

    # 解析Info.plist
    plist = extract_info_plist(ipa_path)
    if plist:
        app_info = parse_app_info_from_plist(plist)
        permissions, permission_descriptions = extract_permissions_from_plist(plist)

    return app_info, permissions, permission_descriptions


# =============================================================================
# 配置加载
# =============================================================================

def get_config_path(config_name: str) -> str:
    """
    获取配置文件路径

    Args:
        config_name: 配置文件名

    Returns:
        配置文件完整路径
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    return os.path.join(project_root, 'config', config_name)


def load_json_config(config_path: str) -> Dict:
    """
    加载 JSON 配置文件

    Args:
        config_path: 配置文件路径

    Returns:
        配置字典
    """
    import json

    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)


# =============================================================================
# 私有API检测
# =============================================================================

def load_private_api_rules() -> Dict:
    """
    加载私有API规则配置

    Returns:
        私有API规则字典
    """
    config_path = get_config_path('ios_private_api_rules.json')
    if os.path.exists(config_path):
        return load_json_config(config_path)
    return {
        'private_api_categories': {},
        'known_private_api_patterns': {
            'class_name_patterns': [],
            'method_name_patterns': [],
            'selector_patterns': []
        }
    }


def extract_strings_from_ipa(ipa_path: str, max_size: int = 100 * 1024 * 1024) -> List[str]:
    """
    从IPA中提取字符串常量（用于检测私有API引用）

    Args:
        ipa_path: IPA文件路径
        max_size: 最大处理文件大小（默认100MB）

    Returns:
        字符串列表
    """
    strings = []
    processed_files = 0
    max_files = 500  # 限制处理文件数量

    try:
        with zipfile.ZipFile(ipa_path, 'r') as zf:
            namelist = zf.namelist()

            for name in namelist:
                # 跳过大型文件和非二进制文件
                if processed_files >= max_files:
                    break

                if not (name.endswith('.dylib') or name.endswith('.app/') or
                        name.endswith('.appex') or name.endswith('_nested')):
                    continue

                try:
                    info = zf.getinfo(name)
                    if info.file_size > max_size:
                        continue

                    data = zf.read(name)

                    # 使用strings命令风格的提取
                    current_string = bytearray()
                    for byte in data:
                        if 32 <= byte < 127:  # 可打印ASCII
                            current_string.append(byte)
                        else:
                            if len(current_string) >= 4:  # 至少4个字符
                                try:
                                    s = current_string.decode('ascii')
                                    strings.append(s)
                                except:
                                    pass
                            current_string = bytearray()

                    processed_files += 1
                except:
                    continue

    except Exception as e:
        print(f"[WARN] Failed to extract strings from IPA: {e}")

    return strings


def detect_private_apis(ipa_path: str) -> Dict[str, List[str]]:
    """
    检测IPA中的私有API使用

    Args:
        ipa_path: IPA文件路径

    Returns:
        检测结果字典 {category: [detected_apis]}
    """
    rules = load_private_api_rules()
    categories = rules.get('private_api_categories', {})
    patterns = rules.get('known_private_api_patterns', {})

    detected = {}
    all_strings = set()

    # 1. 提取Info.plist中的配置
    plist = extract_info_plist(ipa_path)
    if plist:
        # 检查是否有可疑的URL Scheme（私有API调用）
        url_schemes = plist.get('CFBundleURLTypes', [])
        for url_type in url_schemes:
            schemes = url_type.get('CFBundleURLSchemes', [])
            for scheme in schemes:
                all_strings.add(scheme.lower())

    # 2. 提取IPA中的字符串
    extracted_strings = extract_strings_from_ipa(ipa_path)
    all_strings.update(extracted_strings)

    # 3. 按类别检测
    for category, info in categories.items():
        apis = info.get('apis', [])
        risk_level = info.get('risk_level', '中')
        detected_apis = []

        for api in apis:
            api_lower = api.lower()
            # 检查字符串中是否包含该API
            for s in all_strings:
                if api_lower in s.lower():
                    if api not in detected_apis:
                        detected_apis.append(api)
                    break

        if detected_apis:
            detected[category] = {
                'risk_level': risk_level,
                'apis': detected_apis,
                'count': len(detected_apis)
            }

    # 4. 使用正则模式检测
    class_patterns = [re.compile(p, re.IGNORECASE) for p in patterns.get('class_name_patterns', [])]
    method_patterns = [re.compile(p, re.IGNORECASE) for p in patterns.get('method_name_patterns', [])]
    selector_patterns = [re.compile(p, re.IGNORECASE) for p in patterns.get('selector_patterns', [])]

    pattern_detected = {
        'class_name': [],
        'method_name': [],
        'selector_name': []
    }

    for s in all_strings:
        for pattern in class_patterns:
            if pattern.search(s) and s not in pattern_detected['class_name']:
                pattern_detected['class_name'].append(s)
                break

        for pattern in method_patterns:
            if pattern.search(s) and s not in pattern_detected['method_name']:
                pattern_detected['method_name'].append(s)
                break

        for pattern in selector_patterns:
            if pattern.search(s) and s not in pattern_detected['selector_name']:
                pattern_detected['selector_name'].append(s)
                break

    # 合并模式检测结果
    if pattern_detected['class_name'] or pattern_detected['method_name'] or pattern_detected['selector_name']:
        detected['可疑模式匹配'] = {
            'risk_level': '高',
            'apis': [],
            'count': 0
        }
        if pattern_detected['class_name']:
            detected['可疑模式匹配']['apis'].extend([f"Class: {c}" for c in pattern_detected['class_name'][:20]])
        if pattern_detected['method_name']:
            detected['可疑模式匹配']['apis'].extend([f"Method: {m}" for m in pattern_detected['method_name'][:20]])
        if pattern_detected['selector_name']:
            detected['可疑模式匹配']['apis'].extend([f"Selector: {s}" for s in pattern_detected['selector_name'][:20]])
        detected['可疑模式匹配']['count'] = len(detected['可疑模式匹配']['apis'])

    return detected


def analyze_private_apis(ipa_path: str) -> Dict:
    """
    完整分析IPA的私有API使用情况

    Args:
        ipa_path: IPA文件路径

    Returns:
        分析结果字典
    """
    detected = detect_private_apis(ipa_path)

    # 统计高风险
    high_risk_count = 0
    medium_risk_count = 0
    categories_detected = []

    for category, info in detected.items():
        categories_detected.append(category)
        if info.get('risk_level') == '高':
            high_risk_count += info.get('count', 0)
        else:
            medium_risk_count += info.get('count', 0)

    return {
        'detected': detected,
        'total_categories': len(detected),
        'high_risk_count': high_risk_count,
        'medium_risk_count': medium_risk_count,
        'has_private_apis': len(detected) > 0,
        'risk_level': '高' if high_risk_count > 0 else ('中' if medium_risk_count > 0 else '低')
    }

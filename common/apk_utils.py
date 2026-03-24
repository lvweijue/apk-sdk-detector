"""
APK 公共工具模块
提供 APK 分析所需的共同功能：APK读取、Manifest解析、应用信息提取等
"""

import os
import re
import zipfile
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple, Optional, Any


# =============================================================================
# APK 基础操作
# =============================================================================

def open_apk(apk_path: str) -> zipfile.ZipFile:
    """
    打开 APK 文件

    Args:
        apk_path: APK文件路径

    Returns:
        ZipFile 对象

    Raises:
        FileNotFoundError: APK文件不存在
        zipfile.BadZipFile: 非法的APK文件
    """
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK文件不存在: {apk_path}")

    if not apk_path.endswith('.apk'):
        raise ValueError(f"文件不是APK格式: {apk_path}")

    return zipfile.ZipFile(apk_path, 'r')


def is_valid_apk(apk_path: str) -> bool:
    """
    检查文件是否为有效的APK

    Args:
        apk_path: 文件路径

    Returns:
        bool: 是否有效
    """
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            return 'AndroidManifest.xml' in zf.namelist()
    except:
        return False


# =============================================================================
# Manifest 提取与解析
# =============================================================================

def extract_manifest_text(apk_path: str) -> Optional[str]:
    """
    使用 aapt 工具提取 Manifest 信息（文本格式）

    Args:
        apk_path: APK文件路径

    Returns:
        aapt 输出的文本内容，失败返回 None
    """
    # 查找 aapt 工具
    aapt_paths = [
        "C:\\Android\\Sdk\\build-tools\\latest\\aapt.exe",
        "C:\\Android\\Sdk\\build-tools\\30.0.3\\aapt.exe",
        "C:\\Android\\Sdk\\build-tools\\29.0.3\\aapt.exe",
        "C:\\Android\\Sdk\\build-tools\\28.0.3\\aapt.exe",
        "aapt"
    ]

    aapt_path = None
    for path in aapt_paths:
        try:
            subprocess.run([path, "version"], capture_output=True, check=True)
            aapt_path = path
            break
        except:
            continue

    if aapt_path:
        try:
            result = subprocess.run(
                [aapt_path, "dump", "badging", apk_path],
                capture_output=True, text=True, check=True
            )
            return result.stdout
        except:
            pass

    return None


def extract_manifest_xml(apk_path: str) -> Optional[bytes]:
    """
    从 APK 中提取 AndroidManifest.xml（二进制格式）

    Args:
        apk_path: APK文件路径

    Returns:
        AndroidManifest.xml 原始数据，失败返回 None
    """
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            if 'AndroidManifest.xml' in zf.namelist():
                return zf.read('AndroidManifest.xml')
    except:
        pass
    return None


def parse_app_info(manifest_text: str) -> Dict[str, Any]:
    """
    从 aapt 输出文本中解析应用基本信息

    Args:
        manifest_text: aapt dump badging 输出的文本

    Returns:
        应用信息字典，包含 package, versionCode, versionName, application.label
    """
    app_info = {
        'package': '未知',
        'versionCode': '未知',
        'versionName': '未知',
        'application': {
            'name': '未知',
            'label': '未知'
        }
    }

    if not manifest_text:
        return app_info

    lines = manifest_text.split('\n')
    for line in lines:
        # 提取包名
        if line.startswith('package: name='):
            match = re.search(r"name='([^']+)', versionCode='([^']+)', versionName='([^']+)'", line)
            if match:
                app_info['package'] = match.group(1)
                app_info['versionCode'] = match.group(2)
                app_info['versionName'] = match.group(3)
        # 提取应用标签
        elif line.startswith('application-label:'):
            app_info['application']['label'] = line.split(':', 1)[1].strip().strip("'")

    return app_info


def parse_permissions_from_text(manifest_text: str) -> List[str]:
    """
    从 aapt 输出文本中提取权限列表

    Args:
        manifest_text: aapt dump badging 输出的文本

    Returns:
        权限列表
    """
    permissions = []

    if not manifest_text:
        return permissions

    lines = manifest_text.split('\n')
    for line in lines:
        if line.startswith('uses-permission:'):
            match = re.search(r"name='([^']+)'", line)
            if match:
                permissions.append(match.group(1))

    return permissions


def parse_permissions_from_xml(manifest_xml: bytes) -> List[str]:
    """
    从 AndroidManifest.xml 中提取权限列表（二进制XML解析）

    Args:
        manifest_xml: AndroidManifest.xml 原始数据

    Returns:
        权限列表
    """
    permissions = []

    try:
        # Android二进制XML使用UTF-16编码，尝试解码提取权限字符串
        manifest_text = manifest_xml.decode('utf-16', errors='ignore')

        # 使用正则提取权限
        perm_pattern = r'android\.permission\.[A-Z_]+'
        permissions = re.findall(perm_pattern, manifest_text)

        # 去重保持顺序
        seen = set()
        unique_perms = []
        for p in permissions:
            if p not in seen:
                seen.add(p)
                unique_perms.append(p)
        permissions = unique_perms
    except:
        pass

    return permissions


def parse_app_info_from_xml(manifest_xml: bytes) -> Dict[str, Any]:
    """
    从 AndroidManifest.xml 中提取应用基本信息（二进制XML解析）

    Args:
        manifest_xml: AndroidManifest.xml 原始数据

    Returns:
        应用信息字典
    """
    import struct

    app_info = {
        'package': '未知',
        'versionCode': '未知',
        'versionName': '未知',
        'application': {'name': '未知', 'label': '未知'}
    }

    try:
        data = manifest_xml

        def read_uint32(offset):
            return struct.unpack('<I', data[offset:offset+4])[0]

        # 查找字符串池 (chunk type = 0x001C0001)
        string_pool_offset = None
        for i in range(0, len(data) - 4, 4):
            try:
                if read_uint32(i) == 0x001C0001:
                    string_pool_offset = i
                    break
            except:
                continue

        if string_pool_offset is not None:
            # 解析字符串池
            string_count = read_uint32(string_pool_offset + 8)
            strings_start = read_uint32(string_pool_offset + 20)

            string_offset_start = string_pool_offset + 28
            strings = []

            for i in range(string_count):
                offset = string_offset_start + i * 4
                if offset + 4 > len(data):
                    break
                str_offset = read_uint32(offset)
                abs_offset = string_pool_offset + strings_start + str_offset

                # 解析字符串（跳过 \x00 填充字节）
                str_bytes = []
                idx = abs_offset + 1  # 跳过长度字节
                while idx < len(data):
                    b = data[idx]
                    if b == 0 and idx + 1 < len(data) and data[idx + 1] == 0:
                        break  # null 结尾
                    if b != 0:
                        str_bytes.append(b)
                    idx += 1

                try:
                    s = bytes(str_bytes).decode('utf-8', errors='ignore')
                    strings.append(s)
                except:
                    strings.append("")

            # 查找包名 - 包含 cn./com./org. 等的完整包名
            for s in strings:
                if s and len(s) > 10 and ('cn.' in s or 'com.' in s or 'org.' in s):
                    if 'permission' not in s.lower() and 'action' not in s.lower() and 'category' not in s.lower():
                        if app_info['package'] == '未知':
                            app_info['package'] = s
                            break

            # 查找版本号（直接从字符串池中找候选值）
            # versionCode 通常是纯数字（如 "15"）
            # versionName 通常是 x.y.z 格式（如 "1.0.0"）
            version_candidates = []
            for s in strings:
                if s and len(s) > 0:
                    # 纯数字字符串
                    if s.isdigit() and len(s) <= 10:
                        version_candidates.append(('code', s))
                    # 版本号格式 (x.y.z)
                    elif s.count('.') == 2 and all(p.isdigit() and len(p) <= 5 for p in s.split('.')):
                        version_candidates.append(('name', s))

            # 分配版本号
            for vtype, v in version_candidates:
                if vtype == 'code' and app_info['versionCode'] == '未知':
                    app_info['versionCode'] = v
                elif vtype == 'name' and app_info['versionName'] == '未知':
                    app_info['versionName'] = v

            # 查找 application label
            for s in strings:
                if s and len(s) > 1 and s not in ['android', 'application', 'activity', 'service']:
                    if not any(c in s.lower() for c in ['permission', 'intent', 'action', 'category', 'provider', 'receiver']):
                        if not s.startswith(('com.', 'cn.', 'io.', 'org.', 'net.', 'android')):
                            app_info['application']['label'] = s
                            break

    except Exception as e:
        print(f"[WARN] parse_app_info_from_xml error: {e}")

    return app_info


def get_app_info_and_permissions(apk_path: str) -> Tuple[Dict[str, Any], List[str]]:
    """
    获取应用信息和权限列表（优先使用aapt，失败后用二进制XML解析）

    Args:
        apk_path: APK文件路径

    Returns:
        (app_info, permissions) 元组
    """
    app_info = {
        'package': '未知',
        'versionCode': '未知',
        'versionName': '未知',
        'application': {'name': '未知', 'label': '未知'}
    }
    permissions = []

    # 优先使用 aapt
    manifest_text = extract_manifest_text(apk_path)
    if manifest_text:
        app_info = parse_app_info(manifest_text)
        permissions = parse_permissions_from_text(manifest_text)
        return app_info, permissions

    # 后备：从二进制 XML 解析
    manifest_xml = extract_manifest_xml(apk_path)
    if manifest_xml:
        permissions = parse_permissions_from_xml(manifest_xml)
        app_info = parse_app_info_from_xml(manifest_xml)

    return app_info, permissions


# =============================================================================
# Manifest 组件提取
# =============================================================================

def extract_manifest_components(apk_path: str) -> Dict[str, List[str]]:
    """
    从APK中提取AndroidManifest的组件信息

    Args:
        apk_path: APK文件路径

    Returns:
        组件信息字典，包含 activities, services, receivers, providers, all_components, meta_data
    """
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

            # 从 binary XML 和 DEX 中提取组件名和元数据
            for name in all_files:
                if name.endswith('.xml') or name.endswith('.dex'):
                    try:
                        data = zf.read(name)
                        content = data.decode('utf-8', errors='ignore')

                        # 提取组件类名
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

            # 从 resources.arsc 提取资源字符串
            try:
                resources_data = zf.read('resources.arsc')
                res_str = resources_data.decode('utf-8', errors='ignore')

                meta_pattern = r'(?:android:name|name)="([^"]{3,80})"'
                meta_matches = re.findall(meta_pattern, res_str)
                components['meta_data'].extend([s for s in meta_matches if len(s) > 3])

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


# =============================================================================
# 配置加载
# =============================================================================

def get_config_path(config_name: str, module_name: str = None) -> str:
    """
    获取配置文件路径

    Args:
        config_name: 配置文件名
        module_name: 模块名称（如 'sdk-analyzer', 'permission-analyzer'）

    Returns:
        配置文件完整路径
    """
    # 获取当前文件所在目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # 项目根目录
    project_root = os.path.dirname(current_dir)

    if module_name:
        return os.path.join(project_root, module_name, config_name)
    else:
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
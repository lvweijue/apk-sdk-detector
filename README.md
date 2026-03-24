# APK/IPK 第三方SDK分析工具

## 工具简介

APK/IPK分析工具集支持Android APK和iOS IPA两种移动应用格式的分析，包含四个独立模块：

**Android APK分析：**
1. **SDK分析** - 分析APK使用了哪些第三方SDK，支持推送、支付、地图、统计、社交、登录、广告、视频等20+类别
2. **权限分析** - 分析APK请求的权限及隐私风险

**iOS IPA分析：**
3. **SDK分析** - 分析IPA使用了哪些第三方SDK，支持广告、推送、支付、地图、统计分析、登录、即时通讯等
4. **权限分析** - 分析IPA请求的权限（通过Info.plist的Usage Description）

---

## Python版本要求

- Python 3.6 或更高版本

## 依赖说明

本工具仅使用Python标准库，**无需安装任何第三方依赖包**。

### 标准库列表：
- `sys` - 系统相关操作
- `os` - 操作系统接口
- `zipfile` - ZIP文件操作（用于解析APK/IPA）
- `re` - 正则表达式（用于包名、域名、字符串匹配）
- `time` - 时间处理
- `json` - JSON配置文件读取
- `plistlib` - iOS PropertyList解析
- `collections` - 高级数据结构（使用defaultdict）
- `io` - 字节流处理

---

## 安装步骤

### 1. 确保Python环境

```bash
python --version
```

### 2. 下载或克隆脚本

```bash
cd apk-sdk-detector
```

### 3. 验证依赖（可选）

```bash
python -c "import sys, os, zipfile, re, time, json, plistlib, collections, io; print('所有标准库导入成功')"
```

---

## 统一入口使用方式

使用 `main.py` 统一入口，通过 `-o` 参数选择分析模式，**自动识别APK/IPA**：

```bash
python main.py -o=1 <文件路径> <报告输出目录>   # 仅SDK分析
python main.py -o=2 <文件路径> <报告输出目录>   # 仅权限分析
python main.py -o=3 <文件路径> <报告输出目录>   # 两者都分析
```

### 示例

```bash
# 分析Android APK
python main.py -o=3 C:/test/app.apk C:/reports

# 分析iOS IPA
python main.py -o=3 C:/test/app.ipa C:/reports
```

### 报告命名规则

| 分析模式 | 报告名格式 |
|:---------|-----------|
| SDK分析 | `{应用名称}_SDK分析_{时间戳}.md` |
| 权限分析 | `{应用名称}_权限分析_{时间戳}.md` |

---

## 独立模块使用方式

### Android APK SDK分析

```bash
python scripts/sdk_analyzer.py "<APK文件路径>" [输出报告路径]
```

### Android APK 权限分析

```bash
python scripts/permission_analyzer.py "<APK文件路径>"
```

### iOS IPA SDK分析

```bash
python scripts/ios_sdk_analyzer.py "<IPA文件路径>" [输出报告路径]
```

### iOS IPA 权限分析

```bash
python scripts/ios_permission_analyzer.py "<IPA文件路径>"
```

---

## 项目结构

```
apk-sdk-detector/
├── main.py                      # 统一入口脚本 (自动识别APK/IPA)
├── requirements.txt             # 依赖说明（仅标准库）
├── README.md                    # 本文档
├── SKILL.md                     # Skill调用说明
├── config/                      # 配置文件目录
│   ├── sdk_patterns.json        # Android SDK特征库
│   ├── permission_rules.json    # Android 权限规则
│   ├── ios_sdk_patterns.json    # iOS SDK特征库
│   └── ios_permission_rules.json # iOS 权限规则
├── common/                      # 公共模块
│   ├── apk_utils.py            # APK通用工具函数
│   └── ipa_utils.py            # IPA通用工具函数
└── scripts/                    # 分析脚本目录
    ├── sdk_analyzer.py          # Android SDK分析
    ├── permission_analyzer.py   # Android 权限分析
    ├── ios_sdk_analyzer.py     # iOS SDK分析
    └── ios_permission_analyzer.py # iOS 权限分析
```

---

## 注意事项

1. **文件格式**：支持 `.apk` (Android) 和 `.ipa` (iOS) 两种格式
2. **Windows编码**：脚本已处理Windows控制台UTF-8编码问题
3. **配置文件**：确保 `config/` 目录包含所有配置文件
4. **内存要求**：大型应用文件可能占用较多内存
5. **iOS特点**：iOS权限通过Info.plist中的Usage Description声明

## 故障排除

### 问题：找不到配置文件
**解决**：确保 `config/` 目录与脚本在同一目录下

### 问题：Windows控制台乱码
**解决**：脚本已自动处理，如仍有问题请确保使用支持UTF-8的终端

### 问题：解析失败
**解决**：
- 确认应用文件完整且未损坏
- 确认文件格式是否为有效的APK或IPA

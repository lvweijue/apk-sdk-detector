---
name: APK分析工具集
description: |
  这是一个APK/iOS分析Skill集，包含两个模块：
  1. APK-SDK分析：分析Android APK使用了哪些第三方SDK
  2. APK-权限分析：分析APK请求的权限及隐私风险
  3. IPA-SDK分析：分析iOS IPA使用了哪些第三方SDK
  4. IPA-权限分析：分析IPA请求的权限及隐私风险
  使用方式：直接@APK分析，然后提供APK或IPA文件路径，Skill会自动分析并生成报告。
---

# APK/IPK 分析工具集

本工具集支持Android APK和iOS IPA两种移动应用格式的分析，包含四个独立模块。

---

## 统一入口 (main.py)

通过 `-o` 参数选择分析模式，自动识别文件类型：

```bash
python main.py -o=1 <文件路径> <报告输出目录>   # 仅SDK分析
python main.py -o=2 <文件路径> <报告输出目录>   # 仅权限分析
python main.py -o=3 <文件路径> <报告输出目录>   # 两者都分析
```

**自动识别：**
- `.apk` 文件 → Android APK 分析模块
- `.ipa` 文件 → iOS IPA 分析模块

示例：

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

## 模块一：Android SDK分析 (sdk_analyzer.py)

分析APK使用的第三方SDK，支持推送、支付、地图、统计、社交、登录、广告等类别。

---

## 模块二：Android 权限分析 (permission_analyzer.py)

分析APK文件的权限使用情况和用户数据收集行为。

---

## 模块三：iOS SDK分析 (ios_sdk_analyzer.py)

分析IPA使用的第三方SDK，支持广告、推送、支付、地图、统计分析、登录、即时通讯等类别。

**iOS特有检测：**
- Framework名称检测
- CocoaPods依赖检测
- Info.plist配置检测

---

## 模块四：iOS 权限分析 (ios_permission_analyzer.py)

分析IPA文件的权限使用情况（通过Info.plist中的Usage Description）。

**iOS权限特点：**
- 通过Info.plist声明（NSLocationWhenInUseUsageDescription等）
- 风险等级划分与Android类似

**私有API检测：**
- 自动检测IPA中是否使用了iOS私有API
- 覆盖系统操作类、设备信息类、电话通信类、隐私数据类等10+类别
- 私有API使用会导致App Store审核被拒（Guideline 2.5.1）
- 检测结果按风险等级排序显示

---

## 项目结构

```
apk-sdk-detector/
├── main.py                      # 统一入口脚本 (自动识别APK/IPA)
├── config/                      # 配置文件目录
│   ├── sdk_patterns.json        # Android SDK特征库
│   ├── permission_rules.json    # Android 权限规则
│   ├── ios_sdk_patterns.json    # iOS SDK特征库
│   ├── ios_permission_rules.json # iOS 权限规则
│   └── ios_private_api_rules.json # iOS 私有API检测规则
├── common/                      # 公共模块
│   ├── apk_utils.py            # APK通用工具函数
│   └── ipa_utils.py            # IPA通用工具函数
└── scripts/                    # 分析脚本目录
    ├── sdk_analyzer.py          # Android SDK分析
    ├── permission_analyzer.py   # Android 权限分析
    ├── ios_sdk_analyzer.py     # iOS SDK分析
    └── ios_permission_analyzer.py # iOS 权限分析（含私有API检测）
```

---

## 注意事项

- 分析基于静态分析，不包括运行时行为分析
- 分析结果仅供参考，不构成法律建议
- 四个模块可独立使用，互不干扰
- iOS权限通过Info.plist中的Usage Description声明

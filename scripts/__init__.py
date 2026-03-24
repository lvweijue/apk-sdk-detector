#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK分析工具集包初始化文件
提供两个分析模块的入口函数
"""

from .sdk_analyzer import analyze_apk as analyze_sdk
from .permission_analyzer import analyze_apk as analyze_permission

__all__ = ['analyze_sdk', 'analyze_permission']

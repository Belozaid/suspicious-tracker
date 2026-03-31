#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
إصلاح مشكلة استيراد dashboard
"""

import os
import re

def fix_file(filepath, patterns_replacements):
    """استبدال الأنماط في ملف"""
    if not os.path.exists(filepath):
        print(f"❌ ملف غير موجود: {filepath}")
        return False
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    for pattern, replacement in patterns_replacements:
        content = re.sub(pattern, replacement, content)
    
    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✅ تم تعديل: {filepath}")
        return True
    else:
        print(f"⏭️  لا تغييرات في: {filepath}")
        return False

def main():
    print("=" * 60)
    print("🔧 إصلاح مشكلة استيراد dashboard")
    print("=" * 60)
    
    # 1. إنشاء ملف __init__.py
    init_file = "dashboard/__init__.py"
    if not os.path.exists(init_file):
        with open(init_file, 'w', encoding='utf-8') as f:
            f.write('"""Dashboard package for Security Monitor"""\n')
        print(f"✅ تم إنشاء: {init_file}")
    else:
        print(f"✅ ملف {init_file} موجود")
    
    # 2. إصلاح dashboard/app.py
    app_patterns = [
        (r'from dashboard import data as dbdata', r'from . import data as dbdata'),
        (r'from dashboard.layout import', r'from .layout import'),
        (r'from dashboard.callbacks import', r'from .callbacks import'),
        (r'import dashboard.data as dbdata', r'import .data as dbdata'),
    ]
    fix_file("dashboard/app.py", app_patterns)
    
    # 3. إصلاح dashboard/callbacks.py
    callbacks_patterns = [
        (r'from dashboard.layout import', r'from .layout import'),
        (r'from dashboard import data as dbdata', r'from . import data as dbdata'),
        (r'import dashboard.data as dbdata', r'import .data as dbdata'),
    ]
    fix_file("dashboard/callbacks.py", callbacks_patterns)
    
    # 4. التأكد من وجود datetime في layout.py
    layout_file = "dashboard/layout.py"
    with open(layout_file, 'r', encoding='utf-8') as f:
        layout_content = f.read()
    
    if "from datetime import datetime" not in layout_content:
        # إضافة الاستيراد بعد الاستيرادات الأخرى
        lines = layout_content.split('\n')
        for i, line in enumerate(lines):
            if line.startswith('import ') or line.startswith('from '):
                if i < len(lines) - 1:
                    continue
        # أضف بعد آخر استيراد
        for i in range(len(lines)-1, -1, -1):
            if lines[i].startswith('import ') or lines[i].startswith('from '):
                lines.insert(i+1, 'from datetime import datetime')
                break
        new_content = '\n'.join(lines)
        with open(layout_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"✅ تم إضافة datetime إلى {layout_file}")
    else:
        print(f"✅ datetime موجود في {layout_file}")
    
    # 5. التحقق من dashboard/data.py
    data_file = "dashboard/data.py"
    with open(data_file, 'r', encoding='utf-8') as f:
        data_content = f.read()
    
    needed_imports = ['sqlite3', 'json', 'datetime', 'timezone', 'timedelta']
    missing = []
    for imp in needed_imports:
        if imp not in data_content and f"from datetime import" not in data_content:
            missing.append(imp)
    
    if missing:
        print(f"⚠️  الملف {data_file} ينقصه استيرادات: {missing}")
        # إضافة الاستيرادات في البداية
        import_lines = [
            'import sqlite3',
            'import json',
            'from datetime import datetime, timezone, timedelta',
            'from typing import Dict, List, Any, Optional',
            ''
        ]
        new_content = '\n'.join(import_lines) + data_content
        with open(data_file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"✅ تم إضافة الاستيرادات إلى {data_file}")
    else:
        print(f"✅ الاستيرادات كاملة في {data_file}")
    
    print("\n" + "=" * 60)
    print("✅ تم الانتهاء من الإصلاحات")
    print("🚀 قم بتشغيل dashboard الآن:")
    print("   python dashboard/app.py")
    print("=" * 60)

if __name__ == "__main__":
    main()
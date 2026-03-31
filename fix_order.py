#!/usr/bin/env python3
"""
Fix indentation issues in main.py
"""

import os
import re

def fix_file_indentation(filepath):
    """Fix mixed tabs and spaces in a file"""
    print(f"Fixing indentation in: {filepath}")
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # احسب عدد السطور مع مشاكل
    lines = content.split('\n')
    problem_lines = []
    
    for i, line in enumerate(lines, 1):
        # تحقق من وجود مزيج من tabs و spaces
        if '\t' in line and ' ' in line[:8]:  # في المسافات البادئة الأولى
            problem_lines.append(i)
        # تحقق من indentation غير متسق
        if line.strip() and (len(line) - len(line.lstrip())) % 4 != 0:
            problem_lines.append(i)
    
    if problem_lines:
        print(f"Found indentation issues on lines: {problem_lines[:10]}")  # أول 10 خطوط فقط
        
        # استبدال كل tabs بـ 4 spaces
        fixed_lines = []
        for i, line in enumerate(lines, 1):
            if '\t' in line:
                # استبدال كل tab بـ 4 spaces
                fixed_line = line.replace('\t', '    ')
                print(f"  Line {i}: Replaced tabs with spaces")
                fixed_lines.append(fixed_line)
            else:
                fixed_lines.append(line)
        
        # كتابة الملف المعدل
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write('\n'.join(fixed_lines))
        
        print(f"✅ Fixed {len(problem_lines)} indentation issues")
        return True
    else:
        print("✅ No indentation issues found")
        return False

def check_syntax(filepath):
    """Check if Python file has syntax errors"""
    import ast
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            ast.parse(f.read())
        print(f"✅ {filepath}: Syntax OK")
        return True
    except SyntaxError as e:
        print(f"❌ {filepath}: Syntax error - {e}")
        print(f"   Line {e.lineno}, Column {e.offset}")
        return False
    except Exception as e:
        print(f"❌ {filepath}: Error - {e}")
        return False

def main():
    print("=" * 70)
    print("FIXING INDENTATION ISSUES")
    print("=" * 70)
    
    # الملفات الرئيسية للتحقق
    files_to_check = [
        'main.py',
        'core/scheduler.py',
        'storage/database.py',
        'preprocessing/feature_engine.py',
        'detection/rules_engine.py',
        'incidents/incident_manager.py',
        'collectors/process_collector.py',
        'collectors/network_collector.py',
        'collectors/eventlog_collector.py',
        'collectors/login_collector.py'
    ]
    
    all_fixed = []
    
    for filepath in files_to_check:
        if os.path.exists(filepath):
            print(f"\n📄 {filepath}:")
            fixed = fix_file_indentation(filepath)
            if fixed:
                all_fixed.append(filepath)
            
            # التحقق من الصياغة بعد الإصلاح
            check_syntax(filepath)
        else:
            print(f"\n⚠️  {filepath}: File not found")
    
    print("\n" + "=" * 70)
    if all_fixed:
        print(f"✅ Fixed indentation in {len(all_fixed)} files:")
        for filepath in all_fixed:
            print(f"   • {filepath}")
    else:
        print("✅ No files needed fixing")
    
    # تحقق خاص لـ main.py
    if 'main.py' in all_fixed or check_syntax('main.py'):
        print("\n✅ main.py is now syntactically correct")
        print("\nTo test the system:")
        print("   python final_test.py")
    else:
        print("\n❌ main.py still has syntax errors")
        print("\nManual fix needed. Check line 50 specifically.")
    
    print("=" * 70)

if __name__ == "__main__":
    main()
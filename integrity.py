# integrity.py
"""
نظام التحقق من سلامة الملفات وبصمات SHA-256
"""

import hashlib
import os
import json
from typing import Dict, List, Tuple, Optional
from datetime import datetime

def sha256_file(file_path: str) -> str:
    """
    حساب بصمة SHA-256 للملف
    
    Args:
        file_path: مسار الملف
        
    Returns:
        str: بصمة SHA-256 بالصيغة السداسية عشرية
        
    Raises:
        FileNotFoundError: إذا لم يوجد الملف
        IOError: إذا حدث خطأ في القراءة
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            # قراءة الملف في قطع (1MB لكل قطعة)
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                sha256_hash.update(chunk)
    except IOError as e:
        raise IOError(f"Failed to read file {file_path}: {e}")
    
    return sha256_hash.hexdigest()

def sha256_string(data: str) -> str:
    """
    حساب بصمة SHA-256 للنص
    
    Args:
        data: النص المدخل
        
    Returns:
        str: بصمة SHA-256
    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def verify_file_integrity(file_path: str, expected_hash: str) -> Tuple[bool, Optional[str]]:
    """
    التحقق من سلامة الملف عن طريق مقارنة البصمة
    
    Args:
        file_path: مسار الملف
        expected_hash: البصمة المتوقعة
        
    Returns:
        Tuple[bool, Optional[str]]: (صحة الملف، البصمة الفعلية أو رسالة الخطأ)
    """
    try:
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}"
        
        actual_hash = sha256_file(file_path)
        return actual_hash == expected_hash, actual_hash
        
    except Exception as e:
        return False, str(e)

def calculate_directory_hashes(directory: str, extensions: Optional[List[str]] = None) -> Dict[str, str]:
    """
    حساب بصمات جميع الملفات في الدليل
    
    Args:
        directory: مسار الدليل
        extensions: قائمة الامتدادات المراد تضمينها (None = جميع الملفات)
        
    Returns:
        Dict[str, str]: قاموس بالمسارات النسبية والبصمات
    """
    hashes = {}
    
    if not os.path.exists(directory):
        return hashes
    
    try:
        for root, dirs, files in os.walk(directory):
            for file in files:
                # تصفية بالامتداد إذا تم تحديده
                if extensions:
                    if not any(file.endswith(ext) for ext in extensions):
                        continue
                
                file_path = os.path.join(root, file)
                try:
                    file_hash = sha256_file(file_path)
                    # تخزين المسار النسبي
                    rel_path = os.path.relpath(file_path, directory)
                    hashes[rel_path] = file_hash
                    
                except Exception as e:
                    hashes[file_path] = f"ERROR: {str(e)}"
        
        return hashes
        
    except Exception as e:
        return {'error': str(e)}

def generate_integrity_report(directory: str, output_file: str = None) -> Dict:
    """
    إنشاء تقرير سلامة شامل للدليل
    
    Args:
        directory: مسار الدليل للفحص
        output_file: مسار ملف الإخراج (اختياري)
        
    Returns:
        Dict: تقرير السلامة
    """
    report = {
        'generated_at': datetime.now().isoformat(),
        'directory': directory,
        'total_files': 0,
        'verified_files': 0,
        'failed_files': 0,
        'file_hashes': {},
        'summary': {}
    }
    
    hashes = calculate_directory_hashes(directory)
    report['file_hashes'] = hashes
    
    # تحليل النتائج
    total = len(hashes)
    verified = sum(1 for h in hashes.values() if not h.startswith('ERROR:'))
    failed = total - verified
    
    report.update({
        'total_files': total,
        'verified_files': verified,
        'failed_files': failed,
        'summary': {
            'verification_rate': f"{(verified / total * 100):.1f}%" if total > 0 else "0%",
            'status': 'PASS' if failed == 0 else 'FAIL',
            'failed_list': [f for f, h in hashes.items() if h.startswith('ERROR:')]
        }
    })
    
    # حفظ التقرير إذا تم تحديد ملف إخراج
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"✅ Integrity report saved to: {output_file}")
        except Exception as e:
            print(f"❌ Failed to save report: {e}")
    
    return report

def verify_integrity_report(report_file: str) -> Dict:
    """
    التحقق من تقرير السلامة
    
    Args:
        report_file: مسار ملف التقرير
        
    Returns:
        Dict: نتائج التحقق
    """
    try:
        with open(report_file, 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        directory = report.get('directory', '')
        stored_hashes = report.get('file_hashes', {})
        
        # إعادة حساب البصمات
        current_hashes = calculate_directory_hashes(directory)
        
        # المقارنة
        changes = []
        unchanged = []
        
        for file_path, stored_hash in stored_hashes.items():
            if file_path in current_hashes:
                current_hash = current_hashes[file_path]
                if current_hash == stored_hash:
                    unchanged.append(file_path)
                else:
                    changes.append({
                        'file': file_path,
                        'old_hash': stored_hash[:32] + '...' if len(stored_hash) > 35 else stored_hash,
                        'new_hash': current_hash[:32] + '...' if len(current_hash) > 35 else current_hash
                    })
            else:
                changes.append({
                    'file': file_path,
                    'change': 'DELETED',
                    'old_hash': stored_hash[:32] + '...' if len(stored_hash) > 35 else stored_hash
                })
        
        # الملفات الجديدة
        new_files = [f for f in current_hashes.keys() if f not in stored_hashes]
        
        verification_result = {
            'verified_at': datetime.now().isoformat(),
            'report_file': report_file,
            'original_report_date': report.get('generated_at', ''),
            'total_files_in_report': len(stored_hashes),
            'total_files_current': len(current_hashes),
            'unchanged_files': len(unchanged),
            'changed_files': len(changes),
            'new_files': len(new_files),
            'deleted_files': sum(1 for c in changes if c.get('change') == 'DELETED'),
            'tampered_files': len(changes) - sum(1 for c in changes if c.get('change') == 'DELETED'),
            'changes': changes[:10],  # أول 10 تغييرات فقط
            'new_files_list': new_files[:10],  # أول 10 ملفات جديدة
            'integrity_status': 'COMPROMISED' if changes else 'INTACT'
        }
        
        return verification_result
        
    except Exception as e:
        return {
            'error': str(e),
            'verified_at': datetime.now().isoformat(),
            'integrity_status': 'VERIFICATION_FAILED'
        }

# فئة مساعدة للاستخدام البرمجي
class IntegrityMonitor:
    """مراقب سلامة الملفات"""
    
    def __init__(self, db_path: str = 'security.db'):
        self.db_path = db_path
        self.critical_files = [
            'security.db',
            'users.db',
            'config.yaml',
            'app.py',
            'main.py'
        ]
    
    def check_critical_files(self) -> Dict:
        """
        فحص الملفات الحرجة
        
        Returns:
            Dict: نتائج الفحص
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'critical_files_checked': [],
            'tampered_files': [],
            'status': 'SECURE'
        }
        
        for file in self.critical_files:
            if os.path.exists(file):
                try:
                    current_hash = sha256_file(file)
                    results['critical_files_checked'].append({
                        'file': file,
                        'hash': current_hash[:32] + '...' if len(current_hash) > 35 else current_hash,
                        'status': 'PRESENT'
                    })
                except Exception as e:
                    results['critical_files_checked'].append({
                        'file': file,
                        'error': str(e),
                        'status': 'ERROR'
                    })
            else:
                results['critical_files_checked'].append({
                    'file': file,
                    'status': 'MISSING'
                })
        
        # تحديد الحالة العامة
        missing_files = [f for f in results['critical_files_checked'] if f['status'] == 'MISSING']
        if missing_files:
            results['status'] = 'CRITICAL'
            results['missing_files'] = [f['file'] for f in missing_files]
        
        return results
    
    def generate_baseline(self, output_file: str = 'baseline_integrity.json') -> Dict:
        """
        إنشاء خط أساس لسلامة الملفات
        
        Args:
            output_file: ملف الإخراج
            
        Returns:
            Dict: خط الأساس
        """
        baseline = {
            'created_at': datetime.now().isoformat(),
            'critical_files': {},
            'system_info': {
                'python_version': os.sys.version,
                'platform': os.sys.platform,
                'working_directory': os.getcwd()
            }
        }
        
        for file in self.critical_files:
            if os.path.exists(file):
                try:
                    file_hash = sha256_file(file)
                    baseline['critical_files'][file] = {
                        'hash': file_hash,
                        'size': os.path.getsize(file),
                        'modified': datetime.fromtimestamp(os.path.getmtime(file)).isoformat()
                    }
                except Exception as e:
                    baseline['critical_files'][file] = {
                        'error': str(e),
                        'status': 'FAILED'
                    }
        
        # حفظ خط الأساس
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(baseline, f, indent=2, ensure_ascii=False)
            print(f"✅ Baseline created: {output_file}")
        except Exception as e:
            print(f"❌ Failed to save baseline: {e}")
        
        return baseline
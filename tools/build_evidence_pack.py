# tools/build_evidence_pack.py
import os
import sys  # <--- هذا السطر كان مفقوداً
import json
import glob
import shutil
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# إضافة المسار الرئيسي للمشروع للتمكن من استيراد الوحدات
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    from core.config_loader import load_config
except ImportError:
    # إذا فشل الاستيراد، سنستخدم المسارات الافتراضية
    print("⚠️ تحذير: لا يمكن تحميل core.config_loader. استخدام المسارات الافتراضية.")
    load_config = lambda: {}

def sha256_file(filepath: str) -> str:
    """حساب بصمة SHA-256 لملف."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"خطأ في الحساب: {e}"

def utc_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

def main():
    print("="*60)
    print("📦 أداة بناء حزمة الأدلة (Evidence Pack Builder)")
    print("="*60)

    cfg = load_config()
    paths_cfg = cfg.get('paths', {}) if cfg else {}

    # تحديد مجلد الإخراج
    evidence_base = paths_cfg.get('evidence_dir', 'evidence_pack')
    os.makedirs(evidence_base, exist_ok=True)
    out_dir = os.path.join(evidence_base, utc_stamp())
    os.makedirs(out_dir, exist_ok=True)
    print(f"📁 سيتم إنشاء الحزمة في: {out_dir}")

    # تجميع قائمة الملفات المحتملة (Artifacts)
    candidates = []
    # ملفات JSON في المسار الرئيسي (سناب شوت، تقارير)
    candidates.extend(glob.glob("*.json"))
    # ملفات السجلات
    candidates.extend(glob.glob("logs/*.log"))
    # ملفات الصادرات
    candidates.extend(glob.glob("exports/*.log"))
    # ملفات التقارير (HTML)
    candidates.extend(glob.glob("reports/*.html"))
    # ملفات قاعدة البيانات (اختياري، يمكن استبعاده إذا كان كبيرًا)
    # candidates.extend(glob.glob("data/*.db"))
    # ملفات التكوين
    candidates.extend(glob.glob("*.yaml"))
    candidates.extend(glob.glob("*.yml"))

    # إزالة التكرارات والملفات غير الموجودة
    unique_candidates = sorted(list(set([f for f in candidates if os.path.isfile(f)])))

    if not unique_candidates:
        print("⚠️ لم يتم العثور على أي ملفات لنسخها.")
    else:
        print(f"\n📄 تم العثور على {len(unique_candidates)} ملف محتمل.")

    manifest = {
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": []
    }

    files_copied = 0
    for src in unique_candidates:
        dst = os.path.join(out_dir, os.path.basename(src))
        try:
            shutil.copy2(src, dst)
            file_hash = sha256_file(dst)
            file_size = os.path.getsize(dst)
            manifest["files"].append({
                "original_path": src,
                "name": os.path.basename(src),
                "sha256": file_hash,
                "size_bytes": file_size
            })
            files_copied += 1
            print(f"  ✓ {os.path.basename(src)} ({file_size} بايت)")
        except Exception as e:
            print(f"  ❌ فشل نسخ {src}: {e}")
            manifest["files"].append({
                "original_path": src,
                "name": os.path.basename(src),
                "error": str(e)
            })

    # كتابة ملف البيان (manifest.json)
    manifest_path = os.path.join(out_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"\n📝 تم إنشاء ملف البيان: manifest.json")

    print("\n" + "="*60)
    print(f"✅ تم إنشاء حزمة الأدلة بنجاح!")
    print(f"   المسار: {out_dir}")
    print(f"   عدد الملفات المنسوخة: {files_copied}")
    print("="*60)
    return 0

if __name__ == "__main__":
    sys.exit(main())
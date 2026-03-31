# 📁 إنشاء ملف `run.ps1` في مجلد المشروع

# ============================================
# تشغيل نظام مراقبة الأمن السيبراني
# إصدار Windows PowerShell
# ============================================

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "نظام مراقبة الأمن السيبراني v2.0" -ForegroundColor Cyan
Write-Host "إصدار Windows PowerShell" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1️⃣ تعيين متغيرات البيئة (اختياري)
Write-Host "`n[1] تعيين متغيرات البيئة:" -ForegroundColor Yellow

$setEnv = Read-Host "هل تريد تعيين متغيرات البيئة؟ (y/n)"
if ($setEnv -eq 'y') {
    $dbPath = Read-Host "مسار قاعدة البيانات [data/security.db]"
    if ($dbPath) {
        $env:SECURITY_DB_PATH = $dbPath
        Write-Host "تم تعيين SECURITY_DB_PATH=$dbPath" -ForegroundColor Green
    }
    
    $dashPass = Read-Host "كلمة مرور Dashboard (للمصادقة)"
    if ($dashPass) {
        $env:DASH_AUTH_PASSWORD = $dashPass
        Write-Host "تم تعيين DASH_AUTH_PASSWORD" -ForegroundColor Green
    }
    
    $smtpPass = Read-Host "كلمة مرور SMTP (للتنبيهات)"
    if ($smtpPass) {
        $env:SMTP_PASSWORD = $smtpPass
        Write-Host "تم تعيين SMTP_PASSWORD" -ForegroundColor Green
    }
}

# 2️⃣ تثبيت المكتبات المطلوبة
Write-Host "`n[2] تثبيت المكتبات المطلوبة:" -ForegroundColor Yellow

$installLibs = Read-Host "هل تريد تثبيت المكتبات المطلوبة؟ (y/n)"
if ($installLibs -eq 'y') {
    Write-Host "جاري تثبيت المكتبات..." -ForegroundColor Green
    
    # تثبيت المكتبات الأساسية
    pip install psutil pyyaml dash plotly pandas dash-bootstrap-components
    
    Write-Host "✅ تم تثبيت المكتبات بنجاح" -ForegroundColor Green
}

# 3️⃣ تشغيل النظام
Write-Host "`n[3] تشغيل النظام الرئيسي:" -ForegroundColor Yellow

Write-Host "جاري تشغيل نظام المراقبة..." -ForegroundColor Green
python main.py

# 4️⃣ اختبار Dashboard (في نافذة PowerShell جديدة)
Write-Host "`n[4] اختبار Dashboard:" -ForegroundColor Yellow
Write-Host "افتح نافذة PowerShell جديدة واشغل:" -ForegroundColor White
Write-Host "python dashboard/app.py" -ForegroundColor Gray
Write-Host "`nأو افتح المتصفح على:" -ForegroundColor White
Write-Host "http://localhost:8050" -ForegroundColor Cyan

# 5️⃣ أوامر PowerShell لاختبار النظام
Write-Host "`n[5] أوامر PowerShell للاختبار:" -ForegroundColor Yellow

Write-Host "# اختبار قاعدة البيانات:" -ForegroundColor White
Write-Host 'python -c "import sqlite3; conn = sqlite3.connect(`"data/security.db`"); print(`"✅ قاعدة البيانات تعمل`")"' -ForegroundColor Gray

Write-Host "`n# اختبار المجمعات:" -ForegroundColor White
Write-Host 'python -c "from collectors.process_collector import ProcessCollector; pc = ProcessCollector(); print(pc.collect_processes())"' -ForegroundColor Gray

Write-Host "`n# اختبار نظام الكشف:" -ForegroundColor White
Write-Host 'python -c "from detection.rules_engine import test_rules_engine; test_rules_engine()"' -ForegroundColor Gray

pause
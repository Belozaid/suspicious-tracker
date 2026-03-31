@echo off
chcp 65001 > nul
echo.
echo ========================================
echo   نظام تنصيب مراقبة الأمن - Windows
echo ========================================
echo.

REM التحقق من تثبيت Python
python --version > nul 2>&1
if errorlevel 1 (
    echo ❌ Python غير مثبت على النظام!
    echo الرجاء تثبيت Python 3.8 أو أعلى من:
    echo https://www.python.org/downloads/
    pause
    exit /b 1
)

REM التحقق من تثبيت pip
python -m pip --version > nul 2>&1
if errorlevel 1 (
    echo ❌ pip غير مثبت!
    echo جاري محاولة إصلاح pip...
    python -m ensurepip --default-pip
)

echo ✓ Python مثبت: 
python --version
echo ✓ pip مثبت: 
python -m pip --version

echo.
echo جاري تثبيت الحزم المطلوبة...
echo.

REM استخدام PyPI المصري أو المحلي
set PIP_INDEX_URL=https://pypi.org/simple/

echo [1/2] تثبيت الحزم الأساسية...
python -m pip install psutil pyyaml schedule --index-url=%PIP_INDEX_URL% --trusted-host pypi.org

echo.
echo [2/2] تثبيت الحزم الإضافية...
python -m pip install dash plotly pandas numpy --index-url=%PIP_INDEX_URL% --trusted-host pypi.org

echo.
echo ✓ تم تثبيت الحزم بنجاح!

echo.
echo جاري إنشاء هيكل النظام...
echo.

REM إنشاء المجلدات الأساسية
mkdir data 2>nul
mkdir logs 2>nul
mkdir reports 2>nul
mkdir exports 2>nul
mkdir core 2>nul
mkdir collectors 2>nul
mkdir storage 2>nul
mkdir dashboard 2>nul
mkdir dashboard\i18n 2>nul

echo ✓ تم إنشاء هيكل المجلدات

echo.
echo ========================================
echo ✅ تم إعداد النظام بنجاح!
echo.
echo لتشغيل النظام:
echo 1. python main.py
echo ========================================
echo.
pause
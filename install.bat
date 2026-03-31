@echo off
echo Installing Enhanced SOC Dashboard...
echo.

:: إنشاء مجلد للبيانات
mkdir data 2>nul
mkdir logs 2>nul
mkdir backups 2>nul
mkdir exports 2>nul

:: تثبيت الحزم الأساسية باستخدام pip
python -m pip install --upgrade pip

:: تثبيت الحزم الضرورية واحدة تلو الأخرى
echo Installing dash...
python -m pip install dash==2.14.0

echo Installing dash-bootstrap-components...
python -m pip install dash-bootstrap-components==1.5.0

echo Installing plotly...
python -m pip install plotly==5.17.0

echo Installing flask...
python -m pip install flask==2.3.3

echo Installing flask-login...
python -m pip install flask-login==0.6.2

echo Installing werkzeug...
python -m pip install werkzeug==2.3.7

echo Installing pandas...
python -m pip install pandas==2.0.3

echo Installing numpy...
python -m pip install numpy==1.24.3

echo Installing pyyaml...
python -m pip install pyyaml==6.0

echo Installing psutil...
python -m pip install psutil==5.9.5

echo Installing requests...
python -m pip install requests==2.31.0

echo.
echo Installation completed!
echo.
echo To run the dashboard:
echo   python dashboard/app.py
echo.
pause
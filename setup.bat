@echo off
REM Setup script for Cloud Misconfiguration Scanner on Windows

echo.
echo ^>^> Cloud Misconfiguration Scanner - Setup
echo ^>^> =====================================
echo.

REM Check Python version
python --version

REM Create virtual environment
echo.
echo Creating virtual environment...
python -m venv venv

REM Activate virtual environment (on Windows)
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt

REM Validate setup
echo.
echo Validating setup...
python -c "import boto3; import click; import yaml; print('All dependencies installed')"

echo.
echo Setup complete!
echo.
echo Next steps:
echo 1. Configure AWS credentials: %%USERPROFILE%%\.aws\credentials or set env vars
echo 2. Validate credentials: python cloudscan/cmd/cloudscan.py validate
echo 3. Run a test scan: python cloudscan/cmd/cloudscan.py scan --help
echo.

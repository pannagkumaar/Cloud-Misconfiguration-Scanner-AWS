#!/usr/bin/env bash

# Setup script for Cloud Misconfiguration Scanner

echo "🛡️  Cloud Misconfiguration Scanner - Setup"
echo "============================================"

# Check Python version
python_version=$(python --version 2>&1 | awk '{print $2}')
echo "Python version: $python_version"

# Create virtual environment
echo ""
echo "Creating virtual environment..."
python -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Validate setup
echo ""
echo "Validating setup..."
python -c "import boto3; import click; import yaml; print('✓ All dependencies installed')"

echo ""
echo "Setup complete! 🎉"
echo ""
echo "Next steps:"
echo "1. Configure AWS credentials: ~/.aws/credentials or set env vars"
echo "2. Validate credentials: python cloudscan/cmd/cloudscan.py validate"
echo "3. Run a test scan: python cloudscan/cmd/cloudscan.py scan --help"
echo ""

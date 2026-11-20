#!/usr/bin/env bash
# Setup Python pinned venv for offline training/evaluation
# Run in WSL2 dev environment

set -euo pipefail

VENV_DIR="/home/crazy-idea/ebpf-iforest-ids/.venv"
REQUIREMENTS_FILE="/home/crazy-idea/ebpf-iforest-ids/requirements.txt"

echo "Creating pinned venv at $VENV_DIR"

# Create requirements.txt with pinned versions compatible with Python 3.14
cat > "$REQUIREMENTS_FILE" << 'REQS'
# Core ML stack - pinned for reproducibility
# Python 3.14 is very new; these are latest compatible versions as of 2026-11
numpy==2.1.3
scipy==1.14.1
scikit-learn==1.5.2
pandas==2.2.3
matplotlib==3.9.2
# Streaming ML for ablations (RRCF, HST)
river==0.21.0
# For RRCF (may need to install from git if not on PyPI)
# rrcf==0.2.0  # uncomment if available
# For EIF
# eif==0.1.0  # uncomment if available
# Utilities
joblib==1.4.2
threadpoolctl==3.5.0
# Data handling
pyarrow==18.1.0
# Config
pyyaml==6.0.1
REQS

# Create venv
python3 -m venv "$VENV_DIR"

# Upgrade pip
"$VENV_DIR/bin/pip" install --upgrade pip

# Install requirements
"$VENV_DIR/bin/pip" install -r "$REQUIREMENTS_FILE"

# Verify installation
echo ""
echo "=== Verification ==="
"$VENV_DIR/bin/python" -c "
import numpy as np
import sklearn
import pandas as pd
import matplotlib
import scipy
import river
print(f'numpy: {np.__version__}')
print(f'scikit-learn: {sklearn.__version__}')
print(f'pandas: {pd.__version__}')
print(f'matplotlib: {matplotlib.__version__}')
print(f'scipy: {scipy.__version__}')
print(f'river: {river.__version__}')
"

echo ""
echo "Venv created at $VENV_DIR"
echo "Activate with: source $VENV_DIR/bin/activate"
echo "Requirements saved to $REQUIREMENTS_FILE"

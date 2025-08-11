#!/bin/bash

set -e

echo "🚀 VES System Installation Script"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check Python version
echo -e "${BLUE}📋 Checking system requirements...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is not installed${NC}"
    exit 1
fi

python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo -e "${RED}❌ Python $python_version found, but Python $required_version or higher is required${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Python $python_version found${NC}"

# Create project directory
echo -e "${BLUE}📁 Setting up project structure...${NC}"
mkdir -p ves-system
cd ves-system

# Create complete directory structure
mkdir -p src/ves/{core,config,scoring,clients,database,cache,cli,api,web,processing,monitoring,security}
mkdir -p src/ves/cli/{commands,formatters}
mkdir -p src/ves/api/{routers,schemas}
mkdir -p tests/{unit,integration,performance,fixtures,e2e}
mkdir -p docs/{api,guides,development,research,examples}
mkdir -p scripts/{setup,deployment,maintenance,testing}
mkdir -p docker k8s monitoring data examples

# Create __init__.py files
find src -type d -exec touch {}/__init__.py \;
find tests -type d -exec touch {}/__init__.py \;

echo -e "${GREEN}✅ Project structure created${NC}"

# Create virtual environment
echo -e "${BLUE}📦 Creating virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install core dependencies
echo -e "${BLUE}📥 Installing dependencies...${NC}"
cat > requirements.txt << 'EOF'
click>=8.0.0
aiohttp>=3.8.0
asyncpg>=0.28.0
tenacity>=8.0.0
python-dateutil>=2.8.0
EOF

pip install -r requirements.txt

# Create development requirements
cat > requirements-dev.txt << 'EOF'
pytest>=7.0.0
pytest-asyncio>=0.21.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0
black>=23.0.0
ruff>=0.0.280
mypy>=1.4.0
httpx>=0.24.0
EOF

pip install -r requirements-dev.txt

echo -e "${GREEN}✅ Dependencies installed${NC}"

# Create configuration files
echo -e "${BLUE}🔧 Creating configuration files...${NC}"

# .env.example
cat > .env.example << 'EOF'
# NVD API Configuration
# Get your API key from: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=your_nvd_api_key_here

# Rate Limiting (seconds between NVD requests)
VES_RATE_LIMIT_DELAY=6.0

# Concurrent Processing Limits  
VES_MAX_CONCURRENT=10

# Logging Level (DEBUG, INFO, WARNING, ERROR)
VES_LOG_LEVEL=INFO
EOF

# Create basic pyproject.toml
cat > pyproject.toml << 'EOF'
[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "ves-system"
version = "1.0.0"
description = "Vulnerability Evaluation System"
readme = "README.md"
requires-python = ">=3.8"
dependencies = [
    "click>=8.0.0",
    "aiohttp>=3.8.0", 
    "asyncpg>=0.28.0",
    "tenacity>=8.0.0",
    "python-dateutil>=2.8.0",
]

[project.scripts]
ves = "ves.cli.main:cli"

[tool.setuptools.packages.find]
where = ["src"]
EOF

# Create .gitignore
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
env/
ENV/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Data and logs
data/
logs/
*.log

# Environment variables
.env
.env.local

# Cache
.cache/
.pytest_cache/
.coverage
htmlcov/

# OS
.DS_Store
Thumbs.db
EOF

echo -e "${GREEN}✅ Configuration files created${NC}"

# Install VES in development mode
echo -e "${BLUE}🔧 Installing VES CLI...${NC}"
pip install -e .

echo -e "${GREEN}✅ VES CLI installed in development mode${NC}"

# Create sample CVE list
echo -e "${BLUE}📄 Creating sample files...${NC}"
mkdir -p examples
cat > examples/sample_cves.txt << 'EOF'
# Sample CVE list for testing
# Log4j vulnerabilities  
CVE-2021-44228
CVE-2021-45046

# Spring vulnerabilities
CVE-2022-22965

# Windows vulnerabilities
CVE-2021-34527

# Linux kernel
CVE-2021-4034
EOF

echo -e "${GREEN}✅ Sample files created${NC}"

# Final setup steps
echo -e "${BLUE}🏁 Final setup steps...${NC}"

# Create basic test
mkdir -p tests/unit
cat > tests/unit/test_basic.py << 'EOF'
"""Basic test to verify installation"""
import pytest
from ves.core.models import VulnerabilityMetrics, Severity

def test_basic_model():
    """Test basic model creation"""
    metrics = VulnerabilityMetrics(cve_id="CVE-2021-44228")
    assert metrics.cve_id == "CVE-2021-44228"
    assert metrics.severity == Severity.NONE
EOF

# Run basic test
echo -e "${BLUE}🧪 Running basic tests...${NC}"
python -m pytest tests/unit/test_basic.py -v

echo -e "${GREEN}✅ Installation completed successfully!${NC}"
echo ""
echo -e "${YELLOW}📋 NEXT STEPS:${NC}"
echo "1. Get an NVD API key: https://nvd.nist.gov/developers/request-an-api-key"
echo "2. Set your API key: export NVD_API_KEY=your_key_here"
echo "3. Test the CLI: ves --help"
echo "4. Try a scan: ves scan CVE-2021-44228"
echo "5. Run bulk scan: ves bulk --file examples/sample_cves.txt"
echo ""
echo -e "${YELLOW}📚 DEVELOPMENT COMMANDS:${NC}"
echo "• Activate environment: source venv/bin/activate"
echo "• Run tests: python -m pytest tests/ -v"
echo "• Format code: black src/ tests/"
echo "• Type check: mypy src/"
echo "• Check config: ves config --validate"
echo ""
echo -e "${GREEN}🎉 Happy vulnerability hunting!${NC}"

#!/usr/bin/env python3
"""
Script to create the complete VES project structure
"""

import os
from pathlib import Path

def create_file(path, content=""):
    """Create a file with optional content"""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        f.write(content)
    print(f"Created: {path}")

def create_init_files():
    """Create all necessary __init__.py files"""
    init_paths = [
        "src/ves/__init__.py",
        "src/ves/core/__init__.py", 
        "src/ves/config/__init__.py",
        "src/ves/scoring/__init__.py",
        "src/ves/clients/__init__.py",
        "src/ves/database/__init__.py",
        "src/ves/cache/__init__.py",
        "src/ves/cli/__init__.py",
        "src/ves/cli/commands/__init__.py",
        "src/ves/cli/formatters/__init__.py",
        "src/ves/api/__init__.py",
        "src/ves/api/routers/__init__.py",
        "src/ves/api/schemas/__init__.py",
        "src/ves/web/__init__.py",
        "src/ves/processing/__init__.py",
        "src/ves/monitoring/__init__.py",
        "src/ves/security/__init__.py",
        "tests/__init__.py",
        "tests/unit/__init__.py",
        "tests/integration/__init__.py",
        "tests/performance/__init__.py",
        "tests/e2e/__init__.py",
    ]
    
    for path in init_paths:
        create_file(path)

def create_project_structure():
    """Create the complete VES project structure"""
    print("🏗️  Creating VES project structure...")
    
    # Create all directories
    directories = [
        "src/ves/core",
        "src/ves/config/environments", 
        "src/ves/scoring",
        "src/ves/clients",
        "src/ves/database/repositories",
        "src/ves/database/migrations/versions",
        "src/ves/database/schemas",
        "src/ves/cache",
        "src/ves/cli/commands",
        "src/ves/cli/formatters",
        "src/ves/api/routers",
        "src/ves/api/schemas",
        "src/ves/web/static/css",
        "src/ves/web/static/js", 
        "src/ves/web/static/images",
        "src/ves/web/templates",
        "src/ves/web/components",
        "src/ves/processing/workers",
        "src/ves/monitoring",
        "src/ves/security",
        "tests/unit/test_core",
        "tests/unit/test_scoring",
        "tests/unit/test_clients",
        "tests/unit/test_cli",
        "tests/unit/test_api",
        "tests/integration",
        "tests/performance", 
        "tests/fixtures/mock_responses",
        "tests/fixtures/test_databases",
        "tests/e2e",
        "docs/api",
        "docs/guides",
        "docs/development",
        "docs/research",
        "docs/examples",
        "scripts/setup",
        "scripts/deployment",
        "scripts/maintenance",
        "scripts/testing",
        "docker",
        "k8s/deployments",
        "k8s/services",
        "monitoring/prometheus/rules",
        "monitoring/grafana/dashboards",
        "monitoring/grafana/datasources",
        "monitoring/alertmanager",
        "data/cache",
        "data/logs", 
        "data/exports",
        "data/temp",
        "examples/cli/cve-lists",
        "examples/cli/scripts",
        "examples/api",
        "examples/integrations/splunk",
        "examples/integrations/elasticsearch",
        "examples/integrations/jira"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    # Create __init__.py files
    create_init_files()
    
    print("✅ Project structure created successfully!")

if __name__ == "__main__":
    create_project_structure()

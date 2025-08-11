from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ves-system",
    version="1.0.0",
    author="VES Development Team",
    author_email="dev@ves-security.org",
    description="Vulnerability Evaluation System - Comprehensive vulnerability assessment",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ves-security/ves-system",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
        "aiohttp>=3.8.0",
        "asyncpg>=0.28.0",
        "tenacity>=8.0.0",
        "python-dateutil>=2.8.0",
    ],
    extras_require={
        "cli": ["rich>=13.0.0"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "ruff>=0.0.280",
            "mypy>=1.4.0",
        ],
        "test": [
            "pytest-cov>=4.0.0",
            "httpx>=0.24.0",
            "pytest-mock>=3.10.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ves=ves.cli.main:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)

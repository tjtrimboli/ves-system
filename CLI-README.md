# VES CLI - Complete Setup and Usage Guide

## 📋 Prerequisites

- **Python 3.8+** (Check with `python3 --version`)
- **Internet connection** (for API access)
- **Terminal/Command prompt access**

## 🚀 Step-by-Step Installation

### 1. Clone or Download the Project

```bash
# If you have the project files, navigate to the directory
cd /path/to/your/ves-system

# Or if starting fresh, create the structure
python3 create_structure.py
```

### 2. Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
# venv\Scripts\activate

# Upgrade pip
pip install --upgrade pip
```

### 3. Install Dependencies

```bash
# Install the VES system in development mode
pip install -e .

# Or install with specific extras
pip install -e ".[cli,dev]"

# Verify installation
ves --help
```

## 🔑 Configuration Setup

### 1. Get NVD API Key (REQUIRED)

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Fill out the form with your information
3. Check your email for the API key (usually arrives within minutes)

### 2. Set Environment Variables

```bash
# Set your NVD API key (REQUIRED)
export NVD_API_KEY="your-actual-api-key-here"

# Optional: Customize rate limiting (default: 6.0 seconds)
export VES_RATE_LIMIT_DELAY=6.0

# Optional: Set concurrent requests (default: 10)
export VES_MAX_CONCURRENT=10

# Optional: Set log level (default: INFO)
export VES_LOG_LEVEL=INFO
```

### 3. Verify Configuration

```bash
# Check configuration
ves config

# Validate settings
ves config --validate

# View version information
ves version
```

## 📖 Basic Usage Examples

### Single CVE Analysis

```bash
# Basic scan with table output
ves scan CVE-2021-44228

# JSON output
ves scan CVE-2021-44228 --format json

# Save results to file
ves scan CVE-2021-44228 --format json --output results.json

# Detailed analysis with recommendations
ves info CVE-2021-44228
```

### Bulk CVE Processing

```bash
# Create a CVE list file
cat > my_cves.txt << EOF
CVE-2021-44228
CVE-2021-4034
CVE-2022-26134
CVE-2021-34527
CVE-2022-22965
EOF

# Process multiple CVEs
ves bulk --file my_cves.txt

# Save as JSON
ves bulk --file my_cves.txt --format json --output bulk_results.json

# Save as CSV for spreadsheets
ves bulk --file my_cves.txt --format csv --output bulk_results.csv

# Custom batch size for faster processing
ves bulk --file my_cves.txt --batch-size 25
```

## 📊 Understanding VES Output

### VES Score Calculation
- **Base Score** = (40% × EPSS) + (30% × CVSS) + (30% × LEV)
- **Final Score** = Base Score × KEV Multiplier (1.5x if in KEV catalog)

### Priority Levels
- **Priority 1 (Urgent)**: VES ≥ 0.8 OR in KEV catalog
- **Priority 2 (High)**: VES 0.6-0.79
- **Priority 3 (Medium)**: VES 0.3-0.59
- **Priority 4 (Low)**: VES < 0.3

### Sample Output Interpretation

```
CVE ID: CVE-2021-44228
VES Score: 0.8756          # High risk - Priority 1
Priority Level: 1          # Urgent attention required
Severity: CRITICAL         # CVSS severity level
CVSS Score: 10.0          # Maximum severity
EPSS Score: 0.975230      # 97.5% exploitation probability
EPSS Percentile: 99.90%   # Top 0.1% most likely to be exploited
KEV Status: Yes           # Known to be actively exploited
LEV Score: 0.892340       # High historical exploitation evidence
```

## 🔧 Advanced Usage

### Environment Configuration

```bash
# Create persistent configuration
cat > ~/.ves_config << EOF
export NVD_API_KEY="your-api-key"
export VES_RATE_LIMIT_DELAY=3.0
export VES_MAX_CONCURRENT=15
export VES_LOG_LEVEL=DEBUG
EOF

# Load configuration
source ~/.ves_config
```

### Bulk Processing with Filtering

```bash
# Create high-priority CVE list
cat > high_priority_cves.txt << EOF
# Log4j vulnerabilities
CVE-2021-44228
CVE-2021-45046
CVE-2021-45105

# Spring4Shell
CVE-2022-22965
CVE-2022-22963

# Windows PrintNightmare
CVE-2021-34527
CVE-2021-1675

# ProxyShell
CVE-2021-34473
CVE-2021-34523
CVE-2021-31207
EOF

# Process with detailed output
ves bulk --file high_priority_cves.txt --format json --output priority_analysis.json
```

### Automated Workflows

```bash
# Daily vulnerability scan script
cat > daily_scan.sh << 'EOF'
#!/bin/bash
set -e

echo "🔍 Daily Vulnerability Scan - $(date)"

# Load configuration
source ~/.ves_config

# Process CVE list
ves bulk --file /path/to/daily_cves.txt --format csv --output "daily_scan_$(date +%Y%m%d).csv"

echo "✅ Scan complete: daily_scan_$(date +%Y%m%d).csv"
EOF

chmod +x daily_scan.sh
```

## 🐛 Troubleshooting

### Common Issues and Solutions

#### 1. "ves: command not found"

```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall VES
pip install -e .

# Check if entry point is registered
pip show ves-system
```

#### 2. "No data found for CVE"

```bash
# Verify CVE ID format (must be CVE-YYYY-NNNNN)
ves scan CVE-2021-44228  # ✅ Correct
ves scan 2021-44228      # ❌ Incorrect

# Check if CVE exists in NVD
# Some very recent CVEs may not be in NVD yet
```

#### 3. Rate Limit Errors

```bash
# Increase delay between requests
export VES_RATE_LIMIT_DELAY=10.0

# Reduce concurrent requests
export VES_MAX_CONCURRENT=5

# Verify API key is set
ves config --validate
```

#### 4. API Connection Issues

```bash
# Enable debug logging
export VES_LOG_LEVEL=DEBUG
ves scan CVE-2021-44228

# Test individual API endpoints
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
curl "https://api.first.org/data/v1/epss?cve=CVE-2021-44228"
```

#### 5. Import Errors

```bash
# Check Python path
echo $PYTHONPATH

# Reinstall dependencies
pip install -r requirements/cli.txt

# Verify package structure
python -c "import ves.cli.main; print('Import successful')"
```

### Debug Mode

```bash
# Enable verbose logging
export VES_LOG_LEVEL=DEBUG

# Run with debug output
ves scan CVE-2021-44228

# Check configuration
ves config --show-env --validate
```

## 📈 Performance Optimization

### Large-Scale Processing

```bash
# For processing 1000+ CVEs efficiently:

# 1. Use larger batch sizes
ves bulk --file large_cve_list.txt --batch-size 100

# 2. Increase concurrent requests (if you have API key)
export VES_MAX_CONCURRENT=20

# 3. Reduce rate limiting (with API key)
export VES_RATE_LIMIT_DELAY=3.0

# 4. Use CSV for faster file I/O
ves bulk --file large_list.txt --format csv --output results.csv
```

### Monitoring Progress

```bash
# Process with progress indication
ves bulk --file my_cves.txt | tee processing.log

# Monitor in another terminal
tail -f processing.log
```

## 🔗 Integration Examples

### Integration with Other Tools

```bash
# Export to JSON for further processing
ves bulk --file cves.txt --format json | jq '.[] | select(.priority_level <= 2)'

# Filter high-risk vulnerabilities
ves bulk --file cves.txt --format csv | awk -F',' '$3 <= 2 {print $1 "," $2}'

# Generate summary report
ves bulk --file cves.txt --format json | jq '[.[] | {cve: .cve_id, ves: .ves_score, priority: .priority_level}] | sort_by(.ves) | reverse'
```

### Continuous Monitoring

```bash
# Weekly vulnerability assessment
cat > weekly_assessment.sh << 'EOF'
#!/bin/bash
WEEK=$(date +%Y-W%U)
OUTPUT_DIR="reports/$WEEK"

mkdir -p "$OUTPUT_DIR"

echo "📊 Weekly Vulnerability Assessment: $WEEK"

# Process critical infrastructure CVEs
ves bulk --file critical_cves.txt --format json --output "$OUTPUT_DIR/critical.json"

# Generate summary
echo "Critical vulnerabilities processed: $WEEK" > "$OUTPUT_DIR/summary.txt"
ves bulk --file critical_cves.txt --format json | jq '[.[] | select(.priority_level == 1)] | length' >> "$OUTPUT_DIR/summary.txt"

echo "✅ Weekly assessment complete: $OUTPUT_DIR/"
EOF
```

## 📚 Additional Resources

### Sample CVE Lists

```bash
# Create sample lists for testing
mkdir -p examples

# High-profile vulnerabilities
cat > examples/major_2021_cves.txt << EOF
CVE-2021-44228  # Log4Shell
CVE-2021-4034   # PwnKit
CVE-2021-34527  # PrintNightmare
CVE-2021-26855  # ProxyLogon
CVE-2021-40444  # MSHTML
EOF

# Spring vulnerabilities
cat > examples/spring_cves.txt << EOF
CVE-2022-22965  # Spring4Shell
CVE-2022-22963  # Spring Cloud Function
CVE-2022-22950  # Spring Framework
EOF
```

### Quick Reference

```bash
# Essential commands
ves --help                    # Show all commands
ves scan <CVE-ID>            # Analyze single CVE
ves info <CVE-ID>            # Detailed analysis
ves bulk --file <file>       # Process multiple CVEs
ves config --validate        # Check configuration
ves version                  # Show version info

# Output formats
--format table              # Human-readable (default)
--format json               # Machine-readable
--format csv                # Spreadsheet-compatible

# Common options
--output <file>             # Save to file
--batch-size <num>          # Concurrent processing
--log-level DEBUG           # Verbose logging
```

## 🎯 Next Steps

Once you have the CLI working:

1. **Test with sample CVEs** to understand the output
2. **Create your own CVE lists** for organizational needs
3. **Set up automated scanning** for regular assessments
4. **Integrate with existing security workflows**
5. **Explore the API components** (Phase 2) when ready

## 🆘 Getting Help

If you encounter issues:

1. **Check configuration**: `ves config --validate`
2. **Enable debug logging**: `export VES_LOG_LEVEL=DEBUG`
3. **Verify API key**: Make sure NVD API key is valid
4. **Test connectivity**: Try individual API endpoints
5. **Review logs**: Check for specific error messages

Remember: The NVD API key is **required** for proper functionality. Without it, you'll be severely rate-limited (5 requests per 30 seconds vs 50 requests per 30 seconds with a key).
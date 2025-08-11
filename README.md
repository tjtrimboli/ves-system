# VES CLI - Vulnerability Evaluation System

A comprehensive vulnerability assessment tool that combines CVSS, KEV, EPSS, and NIST LEV metrics into a unified VES score for prioritizing security efforts.

## 🚀 Quick Start

### Installation

1. **Clone and install:**
   ```bash
   git clone https://github.com/ves-security/ves-cli.git
   cd ves-cli
   chmod +x install.sh
   ./install.sh
   ```

2. **Get NVD API Key:**
   - Visit: https://nvd.nist.gov/developers/request-an-api-key
   - Request your free API key
   - Set environment variable: `export NVD_API_KEY=your_key_here`

3. **Test installation:**
   ```bash
   source ves-env/bin/activate
   ves --help
   ```

### Docker Installation

```bash
# Build container
docker build -t ves-cli .

# Run with environment variables
docker run --rm -e NVD_API_KEY=your_key ves-cli scan CVE-2021-44228
```

## 📖 Usage Guide

### Single CVE Analysis

```bash
# Basic scan
ves scan CVE-2021-44228

# JSON output
ves scan CVE-2021-44228 --format json

# Save to file
ves scan CVE-2021-44228 --output results.json

# Detailed information
ves info CVE-2021-44228
```

### Bulk CVE Processing

```bash
# Create CVE list file
echo -e "CVE-2021-44228\nCVE-2021-4034\nCVE-2022-26134" > cve_list.txt

# Process bulk CVEs
ves bulk --file cve_list.txt --output results.json

# CSV output
ves bulk --file cve_list.txt --format csv --output results.csv

# Custom batch size
ves bulk --file cve_list.txt --batch-size 25
```

### Configuration

```bash
# View current config
ves config

# Set custom rate limits
export VES_RATE_LIMIT_DELAY=3.0
export VES_MAX_CONCURRENT=20

# Enable debug logging
export VES_LOG_LEVEL=DEBUG
```

## 🔍 Understanding VES Scores

The VES (Vulnerability Evaluation Score) combines multiple metrics:

- **CVSS Score (30% weight)**: Severity assessment
- **EPSS Score (40% weight)**: Exploitation probability prediction  
- **LEV Score (30% weight)**: Historical exploitation likelihood
- **KEV Status**: 1.5x multiplier for known exploited vulnerabilities

### Priority Levels

1. **Priority 1 (Critical)**: VES ≥ 0.8 or KEV listed
2. **Priority 2 (High)**: VES 0.6-0.79
3. **Priority 3 (Medium)**: VES 0.3-0.59
4. **Priority 4 (Low)**: VES < 0.3

## 📊 Output Examples

### Table Format
```
CVE ID: CVE-2021-44228
VES Score: 0.8756
Priority Level: 1
Severity: CRITICAL
CVSS Score: 10.0
EPSS Score: 0.975230
EPSS Percentile: 99.90%
KEV Status: Yes
LEV Score: 0.892340
Published: 2021-12-10
```

### JSON Format
```json
{
  "cve_id": "CVE-2021-44228",
  "ves_score": 0.875600,
  "priority_level": 1,
  "severity": "CRITICAL",
  "cvss_score": 10.0,
  "epss_score": 0.975230,
  "kev_status": true,
  "lev_score": 0.892340
}
```

## 🔧 Configuration Options

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `NVD_API_KEY` | None | NVD API key (required) |
| `VES_RATE_LIMIT_DELAY` | 6.0 | Seconds between NVD requests |
| `VES_MAX_CONCURRENT` | 10 | Max concurrent API requests |
| `VES_LOG_LEVEL` | INFO | Logging level |

## 🏗️ Architecture

### Core Components

1. **LEV Calculator**: Implements NIST LEV methodology
2. **API Clients**: NVD, EPSS, and KEV integration
3. **VES Scorer**: Unified scoring algorithm
4. **Output Formatters**: JSON, table, and CSV formats

### Data Sources

- **NVD API 2.0**: CVE and CVSS data
- **FIRST EPSS API**: Exploitation probability scores
- **CISA KEV Catalog**: Known exploited vulnerabilities

## 🔒 Security Features

- Rate limiting to respect API limits
- Input validation and sanitization
- Secure HTTP client configuration
- Comprehensive error handling
- Audit logging capabilities

## 🐛 Troubleshooting

### Common Issues

1. **"No data found for CVE"**: CVE may not exist or be too recent
2. **Rate limit errors**: Reduce concurrent requests or increase delay
3. **API key issues**: Verify key is valid and properly set

### Debug Mode

```bash
export VES_LOG_LEVEL=DEBUG
ves scan CVE-2021-44228
```

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/new-feature`
3. Commit changes: `git commit -am 'Add new feature'`
4. Push branch: `git push origin feature/new-feature`
5. Create Pull Request

## 📄 License

MIT License - see LICENSE file for details

## 🔗 Links

- [NIST LEV Methodology](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf)
- [FIRST EPSS Documentation](https://www.first.org/epss/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD API Documentation](https://nvd.nist.gov/developers)

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Email: support@ves-security.org
- Documentation: https://docs.ves-security.org

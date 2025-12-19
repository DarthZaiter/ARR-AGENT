# ARR-AGENT
Autonomous Reconnaissance &amp; Reporting Agent

# ARR-Agent Setup Guide
## Autonomous Reconnaissance & Reporting Agent

---

## Overview

ARR-Agent is a modular Python tool for automated OSINT collection, vulnerability mapping, and intelligent reporting. It features ML-based risk scoring and generates professional Markdown reports with MITRE ATT&CK mappings.

### Key Features

✅ **Port Scanning** - nmap integration with service detection  
✅ **DNS/WHOIS Enumeration** - Comprehensive DNS record collection  
✅ **Subdomain Discovery** - Certificate transparency, bruteforce, zone transfers  
✅ **GitHub Secret Scanning** - Public repository credential hunting  
✅ **ML-Based Risk Scoring** - Intelligent finding prioritization  
✅ **Attack Path Analysis** - Correlates findings to identify exploitation chains  
✅ **Professional Reports** - Markdown output with MITRE ATT&CK mappings  
✅ **SQLite Database** - Persistent storage of all findings  

---

## Installation

### Prerequisites

- Python 3.8+
- nmap (for port scanning)
- whois (for WHOIS lookups)
- dig (for DNS zone transfers - optional)

### System Setup

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip nmap whois dnsutils
```

**macOS:**
```bash
brew install python3 nmap whois
```

**Windows:**
- Install Python from python.org
- Install nmap from nmap.org
- Install whois: `choco install whois` (if using Chocolatey)

### Python Dependencies

```bash
pip3 install requests
```

That's it! ARR-Agent uses mostly standard library modules to keep dependencies minimal.

---

## Project Structure

Create the following directory structure:

```
arr-agent/
├── arr_agent.py              # Main framework
├── modules/
│   ├── __init__.py
│   ├── port_scanner.py       # Port scanning module
│   ├── dns_enum.py           # DNS enumeration module
│   ├── subdomain_discovery.py # Subdomain discovery module
│   ├── github_secrets.py     # GitHub secret scanner
│   ├── risk_scorer.py        # ML risk scoring engine
│   └── report_generator.py   # Report generation
└── arr_output/               # Output directory (auto-created)
```

### Setup Commands

```bash
# Create project directory
mkdir arr-agent
cd arr-agent

# Create modules directory
mkdir modules
touch modules/__init__.py

# Copy each artifact code into respective files
# arr_agent.py = Main Framework
# modules/port_scanner.py = Port Scanner Module
# modules/dns_enum.py = DNS Enumeration Module
# modules/subdomain_discovery.py = Subdomain Discovery Module
# modules/github_secrets.py = GitHub Secret Scanner Module
# modules/risk_scorer.py = ML Risk Scoring Module
# modules/report_generator.py = Report Generator Module
```

### Make Executable

```bash
chmod +x arr_agent.py
```

---

## Usage

### Basic Usage

```bash
# Run full reconnaissance
python3 arr_agent.py example.com

# Or if executable:
./arr_agent.py example.com
```

### Module-Specific Scans

```bash
# Port scan only
python3 arr_agent.py example.com -m portscan

# DNS enumeration only
python3 arr_agent.py example.com -m dns

# Subdomain discovery only
python3 arr_agent.py example.com -m subdomains

# GitHub secret scan only
python3 arr_agent.py example.com -m secrets

# All modules (default)
python3 arr_agent.py example.com -m all
```

### Advanced Options

```bash
# Custom output directory
python3 arr_agent.py example.com -o /path/to/output

# Skip risk scoring
python3 arr_agent.py example.com --no-risk-scoring

# Skip report generation (save to database only)
python3 arr_agent.py example.com --no-report
```

### Help

```bash
python3 arr_agent.py --help
```

---

## Output

ARR-Agent generates several outputs:

### 1. Database (`arr_data_[SESSION_ID].db`)

SQLite database containing all findings:
- `ports` - Open port discoveries
- `dns_records` - DNS enumeration results
- `subdomains` - Discovered subdomains
- `secrets` - Exposed credentials/secrets
- `risk_scores` - ML-calculated risk scores

### 2. Report (`ARR_Report_[SESSION_ID].md`)

Professional Markdown report including:
- Executive summary
- Detailed findings by module
- Risk analysis with scoring
- Identified attack paths
- MITRE ATT&CK mappings
- Security recommendations

### 3. Raw nmap Output (`nmap_[SESSION_ID].xml`)

XML output from nmap scans for further analysis

---

## Configuration

### GitHub API Token (Optional but Recommended)

For higher rate limits on GitHub searches:

```python
# Set environment variable
export GITHUB_TOKEN="your_token_here"

# Or modify github_secrets.py to set token directly
scanner.set_github_token("your_token_here")
```

Generate token at: https://github.com/settings/tokens

### Custom Wordlists

Edit `subdomain_discovery.py` to add custom subdomain wordlists:

```python
common_subdomains = [
    'www', 'mail', 'api', 'dev',
    # Add your custom subdomains here
]
```

### Risk Scoring Weights

Adjust risk scoring in `risk_scorer.py`:

```python
self.critical_services = {
    'your-service': {'score': 8.5, 'reason': 'Custom risk reason'},
    # Add custom service risk scores
}
```

---

## Examples

### Example 1: Full Recon on Target

```bash
python3 arr_agent.py acmecorp.com
```

**Output:**
- Discovers 15 subdomains
- Finds 8 open ports across main domain and subdomains
- Identifies 3 exposed secrets in public GitHub repos
- Generates risk scores for all findings
- Creates comprehensive Markdown report

### Example 2: Quick Port Scan

```bash
python3 arr_agent.py 192.168.1.100 -m portscan --no-risk-scoring --no-report
```

**Output:**
- Fast port scan only
- Results saved to database
- No ML scoring or report (for speed)

### Example 3: Targeted Secret Hunting

```bash
python3 arr_agent.py targetcompany.com -m secrets
```

**Output:**
- Searches GitHub for exposed credentials
- Identifies API keys, passwords, private keys
- Generates risk scores for each secret type

---

## Security Considerations

### Operational Security

1. **Authorization Required:** Only scan targets you're authorized to test
2. **Rate Limiting:** ARR-Agent implements delays to avoid triggering rate limits
3. **Logging:** All scans create audit trails in the database
4. **API Tokens:** Store GitHub tokens securely (use environment variables)

### Data Protection

1. **Sensitive Data:** Database contains discovered secrets - protect accordingly
2. **Report Distribution:** Reports may contain sensitive findings - encrypt/protect
3. **Cleanup:** Delete databases and reports after use if containing sensitive data

### Legal Compliance

- Obtain written authorization before scanning any target
- Comply with computer fraud and abuse laws in your jurisdiction
- Respect robots.txt and rate limits on public APIs
- Do not use for unauthorized access or malicious purposes

---

## Troubleshooting

### "nmap not found"

```bash
# Install nmap
sudo apt install nmap  # Ubuntu/Debian
brew install nmap      # macOS
```

ARR-Agent will fall back to basic socket scanning if nmap unavailable.

### "whois command not found"

```bash
sudo apt install whois  # Ubuntu/Debian
brew install whois      # macOS
```

### "GitHub API rate limit exceeded"

Set a GitHub personal access token:

```bash
export GITHUB_TOKEN="your_token_here"
```

### Permission Denied on Port Scan

Some ports require elevated privileges:

```bash
sudo python3 arr_agent.py example.com -m portscan
```

### Module Import Errors

Ensure all modules are in the `modules/` directory and `__init__.py` exists:

```bash
ls modules/
# Should show: __init__.py, port_scanner.py, dns_enum.py, etc.
```

---

## Advanced Features

### Custom Modules

Create your own reconnaissance modules:

```python
# modules/custom_module.py
class CustomModule:
    def __init__(self, agent):
        self.agent = agent
    
    def run(self):
        # Your custom recon logic
        finding_data = {'key': 'value'}
        self.agent.save_finding('custom_table', finding_data)
```

Register in `arr_agent.py`:

```python
elif module_name == "custom":
    from modules.custom_module import CustomModule
    module = CustomModule(self)
    module.run()
```

### Database Queries

Query findings directly:

```python
import sqlite3

conn = sqlite3.connect('arr_output/arr_data_[SESSION_ID].db')
cursor = conn.cursor()

# Get all critical findings
cursor.execute("""
    SELECT * FROM risk_scores 
    WHERE risk_score >= 9.0 
    ORDER BY risk_score DESC
""")

results = cursor.fetchall()
```

### Report Customization

Modify `report_generator.py` to customize report format, add sections, or change styling.

---

## Roadmap

Future enhancements planned:

- [ ] Shodan/Censys integration
- [ ] Additional ML models for anomaly detection
- [ ] PDF report generation
- [ ] Web UI dashboard
- [ ] Integration with vulnerability databases (CVE)
- [ ] Passive DNS analysis
- [ ] SSL/TLS certificate analysis
- [ ] Cloud asset discovery (AWS, Azure, GCP)
- [ ] Dark web monitoring
- [ ] Continuous monitoring mode

---

## Contributing

To extend ARR-Agent:

1. Create new module in `modules/` directory
2. Follow existing module structure
3. Integrate with main framework in `arr_agent.py`
4. Update risk scoring logic in `risk_scorer.py`
5. Add report section in `report_generator.py`

---

## Support

For issues or questions:
- Check troubleshooting section above
- Review module code for configuration options
- Ensure all dependencies are installed
- Verify target is reachable and authorized

---

**ARR-Agent - Making reconnaissance autonomous, intelligent, and actionable.**

*Happy Hunting! 🎯*

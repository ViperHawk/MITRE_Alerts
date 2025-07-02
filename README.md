> **Author**: Ross Durrer  
> **Created**: 2025

# MITRE ATT&CK Detection Rules Library

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v15-red)](https://attack.mitre.org/)
[![Sigma Rules](https://img.shields.io/badge/Sigma-Rules-blue)](https://github.com/SigmaHQ/sigma)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive collection of security detection rules mapped to the MITRE ATT&CK framework, complete with severity assessments and Sigma rule implementations for enterprise security operations.

## 📋 Overview

This repository provides a structured approach to threat detection based on the MITRE ATT&CK framework. Each detection rule includes:

- **MITRE ATT&CK Mapping**: Tactics, techniques, and sub-techniques
- **Severity Assessment**: Risk-based prioritization for security operations
- **Detection Logic**: Detailed detection methodologies
- **Technology Requirements**: Required log sources and security tools
- **Sigma Rules**: Platform-agnostic detection rules ready for SIEM deployment

## 🎯 Target Environment

These detection rules are designed for enterprise environments with:

- ✅ **Endpoint Detection and Response (EDR/XDR)** deployed
- ✅ **Non-administrative privileges** for standard users
- ✅ **Centralized logging (SIEM)** for server and security events
- ✅ **Advanced monitoring capabilities** (Sysmon, PowerShell logging, etc.)

## 📊 Severity Classification

| Severity | Description | Impact |
|----------|-------------|---------|
| **Critical** | High business impact, enables data exfiltration or infrastructure compromise | Immediate response required |
| **High** | Significant security impact, likely account compromise or lateral movement | Priority investigation |
| **Medium** | Moderate impact, sophisticated techniques with existing control coverage | Standard investigation |
| **Low** | Limited impact, easily detected reconnaissance activities | Monitoring and baseline |

## 🛠️ Technology Stack

### Required Log Sources
- **Windows Security Event Logs** (Event IDs 4624, 4625, 4688, etc.)
- **Sysmon** (Event IDs 1, 7, 8, 11, 13)
- **PowerShell Logs** (Event IDs 4103, 4104)
- **Linux Audit Logs** (auditd)
- **Network Device Logs** (SSH, SNMP, Configuration changes)
- **Email Security Logs** (SMTP, attachment analysis)

### Recommended Tools
- **SIEM Platforms**: Splunk, Elastic, QRadar, Sentinel, Chronicle
- **EDR/XDR Solutions**: CrowdStrike, SentinelOne, Microsoft Defender
- **Log Collection**: Winlogbeat, Filebeat, Fluentd, rsyslog
- **Sigma Conversion**: sigmac, sigma-cli

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/mitre-attack-detection-library.git
cd mitre-attack-detection-library
```

### 2. Review Detection Rules
- Open the main detection library table
- Filter by severity level for your environment
- Select techniques relevant to your threat landscape

### 3. Deploy Sigma Rules
```bash
# Convert Sigma rules to your SIEM platform
sigmac -t splunk detection-rules/powershell-execution.yml
sigmac -t elasticsearch detection-rules/process-injection.yml
```

### 4. Configure Log Sources
- Enable PowerShell Script Block Logging
- Deploy Sysmon with comprehensive configuration
- Configure command-line auditing
- Set up centralized log collection

## 📁 Repository Structure

```
mitre-attack-detection-library/
├── README.md                          # This file
├── detection-library.md               # Main detection rules table
├── sigma-rules/                       # Individual Sigma rule files
│   ├── execution/                     # T1059 Command and Scripting Interpreter
│   ├── defense-evasion/              # T1055 Process Injection, T1562 Impair Defenses
│   ├── persistence/                  # T1547 Boot or Logon Autostart Execution
│   ├── privilege-escalation/         # T1548 Abuse Elevation Control Mechanism
│   ├── credential-access/            # T1555 Credentials from Password Stores
│   ├── discovery/                    # T1082, T1083, T1135 Discovery techniques
│   ├── lateral-movement/             # T1021 Remote Services
│   ├── collection/                   # T1005 Data from Local System
│   ├── exfiltration/                 # T1041 Exfiltration Over C2 Channel
│   └── impact/                       # T1486, T1490 Ransomware techniques
├── docs/                             # Documentation and guides
│   ├── deployment-guide.md           # SIEM deployment instructions
│   ├── tuning-guide.md              # False positive reduction
│   └── severity-methodology.md      # Severity assessment criteria
└── tools/                           # Helper scripts and tools
    ├── sigma-converter.py           # Batch Sigma rule conversion
    └── coverage-assessment.py       # ATT&CK coverage analysis
```

## 🎯 Coverage Statistics

| Tactic | Techniques Covered | Sub-techniques | Sigma Rules |
|--------|-------------------|----------------|-------------|
| Initial Access | 1 | 3 | 3 |
| Execution | 1 | 8 | 12 |
| Persistence | 1 | 4 | 4 |
| Privilege Escalation | 1 | 1 | 1 |
| Defense Evasion | 2 | 10 | 11 |
| Credential Access | 1 | 2 | 2 |
| Discovery | 3 | 0 | 3 |
| Lateral Movement | 1 | 3 | 3 |
| Collection | 1 | 0 | 1 |
| Exfiltration | 1 | 0 | 1 |
| Impact | 2 | 0 | 2 |

**Total Coverage**: 15 techniques, 31 sub-techniques, 43+ Sigma rules

## 🔧 Customization

### Severity Adjustment
Modify severity levels based on your environment:
- Review threat landscape and business impact
- Adjust based on existing security controls
- Consider compliance requirements

### Sigma Rule Tuning
```yaml
# Example: Reduce false positives
falsepositives:
    - Legitimate administrative PowerShell scripts
    - Automated deployment tools
    - Known software installations

# Add environment-specific exclusions
filter:
    Image|endswith: 
        - '\legitimate-admin-tool.exe'
        - '\approved-software.exe'
```

## 📖 Usage Examples

### PowerShell Detection
```yaml
title: Suspicious PowerShell Base64 Execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - 'FromBase64String'
    condition: selection
level: critical
```

### Process Injection Detection
```yaml
title: Mavinject DLL Injection
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\mavinject.exe'
        CommandLine|contains: '/INJECTRUNNING'
    condition: selection
level: high
```

## 🤝 Contributing

We welcome contributions to expand and improve this detection library!

### How to Contribute
1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/new-technique`)
3. **Add** new detection rules following the established format
4. **Test** Sigma rules with your SIEM platform
5. **Submit** a pull request with detailed description

### Contribution Guidelines
- Follow MITRE ATT&CK technique mapping standards
- Include severity assessment rationale
- Provide working Sigma rules with minimal false positives
- Update documentation and coverage statistics
- Test rules in lab environment before submission

## 📚 Resources

### MITRE ATT&CK Framework
- [Official MITRE ATT&CK Website](https://attack.mitre.org/)
- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [ATT&CK for Enterprise](https://attack.mitre.org/tactics/enterprise/)

### Sigma Project
- [Sigma GitHub Repository](https://github.com/SigmaHQ/sigma)
- [Sigma Rule Specification](https://github.com/SigmaHQ/sigma/wiki/Specification)
- [sigmac Converter Tool](https://github.com/SigmaHQ/sigma#sigmac)

### Detection Engineering
- [Palantir's Alerting and Detection Strategy Framework](https://github.com/palantir/alerting-detection-strategy-framework)
- [MITRE's Cyber Analytics Repository (CAR)](https://car.mitre.org/)
- [Sigma Rule Creation Guide](https://github.com/SigmaHQ/sigma/wiki/Rule-Creation-Guide)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

These detection rules are provided for educational and defensive purposes. Always test rules in a controlled environment before deploying to production. Adjust thresholds and exclusions based on your specific environment to minimize false positives.

## 📞 Support

- **Issues**: Report bugs or request features via [GitHub Issues](../../issues)
- **Discussions**: Join conversations in [GitHub Discussions](../../discussions)
- **Documentation**: Check the [docs/](docs/) directory for detailed guides

## 🏆 Acknowledgments

- **MITRE Corporation** for the ATT&CK framework
- **Sigma Project** for the detection rule format
- **Security Community** for continuous threat intelligence contributions
- **Contributors** who help expand and improve this library

---

**🛡️ Happy Hunting! 🛡️**

*Defending networks one detection rule at a time.*

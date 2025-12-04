# Security

Security assessment, hardening validation, and incident response tools for enterprise environments.

## Contents

This directory contains tools for:
- **Security Auditing** - Local security policy and configuration validation
- **Hardening Verification** - CIS benchmark and compliance checking
- **Vulnerability Assessment** - Local system security posture evaluation
- **Incident Response** - Data collection and forensic helpers
- **Threat Detection** - Log analysis and anomaly identification
- **Baseline Management** - Security configuration templates and validation

## Security Notice

**IMPORTANT:** These tools are intended for authorized security testing and administration only. Users must:
- Obtain explicit authorization before running on production systems
- Comply with all applicable laws, regulations, and organizational policies
- Understand tool functionality before execution
- Use responsibly and ethically

Unauthorized access to computer systems is illegal. Yeyland Wutani LLC assumes no liability for misuse.

## Usage Guidelines

- Run with least privilege necessary (some tools require administrative rights)
- Review output carefully for sensitive information before sharing
- Store logs and results securely
- Follow incident response procedures when anomalies are detected
- Document all security testing activities

## Tool Categories

### Assessment Scripts
Evaluate current security posture against baselines and best practices.

### Hardening Tools
Apply or validate security configurations for systems and applications.

### Response Utilities
Collect evidence, analyze artifacts, and support incident investigation.

## Requirements

- PowerShell 5.1 or later (7+ recommended for cross-platform tools)
- Administrative privileges for system-level operations
- Appropriate security clearances and authorizations
- Understanding of security concepts and potential impacts

## External Resources

### CompromisedDiscovery-Graph - Microsoft 365 Security Analysis Toolkit
[![View Repository](https://img.shields.io/badge/GitHub-the--last--one--left%2FScripts-FF6600?style=flat-square&logo=github)](https://github.com/the-last-one-left/Scripts)

**Version:** 10.2 | **Platform:** PowerShell 5.1+ | **Author:** Zachary Child (Pacific Office Automation)

#### Overview
Comprehensive security analysis tool for Microsoft 365 tenants that detects compromised accounts, identifies security threats, and analyzes suspicious activity patterns using Microsoft Graph PowerShell APIs. This production-grade tool has been battle-tested in enterprise MSP environments and provides forensic-level insights into tenant security posture.

#### Core Capabilities

**Authentication & Access Analysis**
- **Sign-in Logs**: Geolocation analysis with IPv4/IPv6 support, unusual location detection, high-risk ISP identification (VPN/hosting/datacenter providers)
- **Failed Login Patterns**: Password spray, brute force, and confirmed breach detection with IP correlation
- **MFA Status Audit**: Comprehensive multi-factor authentication assessment with privileged account focus
- **Conditional Access**: Policy configuration review and risk assessment

**Threat Detection**
- **Inbox Rules**: Forwarding, deletion, and suspicious pattern detection targeting data exfiltration
- **Mailbox Delegations**: External delegate and high-privilege access identification
- **Password Changes**: Suspicious password reset pattern analysis for credential harvesting detection
- **Message Traces**: Exchange Online message trace with spam pattern analysis and configurable thresholds

**Administrative Oversight**
- **Admin Audit Logs**: High-risk operation monitoring with automated risk scoring
- **App Registrations**: High-privilege permission and configuration analysis for OAuth abuse
- **Risk Scoring**: User risk assessment (Critical/High/Medium/Low) with weighted threat indicators

#### Attack Patterns Detected
- Password Spray Attacks (same IP, multiple user attempts)
- Brute Force Attacks (multiple failures, single user)
- Successful Breach Patterns (failed attempts followed by success from same IP)
- Data Exfiltration (suspicious forwarding rules, external delegates)
- Privilege Escalation (high-risk app permissions, admin role changes)
- Anomalous Geographic Access (unexpected countries, impossible travel)
- OAuth Application Abuse (suspicious app registrations and permissions)

#### Key Features
- **Risk-Based Scoring**: Automated user risk calculation with customizable weights
- **Modern GUI**: Dark/light theme interface with real-time progress tracking
- **HTML Reporting**: Comprehensive reports with collapsible sections and color-coded risk indicators
- **Geolocation Intelligence**: Cached IP geolocation with high-risk ISP identification
- **Smart Fallbacks**: Automatic Exchange Online fallback for non-premium Azure AD tenants
- **Batch Processing**: Handles large tenants with configurable batch sizes and rate limiting

#### Required Permissions
**Microsoft Graph API:**
- User.Read.All
- AuditLog.Read.All
- Directory.Read.All
- Mail.Read / Mail.ReadWrite
- SecurityEvents.Read.All
- IdentityRiskEvent.Read.All
- Application.Read.All
- Policy.Read.All
- UserAuthenticationMethod.Read.All

**Exchange Online:**
- Exchange Administrator or Security Reader role

#### Typical Workflow
1. Launch tool: `.\CompromisedDiscovery-Graph.ps1`
2. Connect to Microsoft Graph with admin credentials
3. Run comprehensive data collection (default: 14-day lookback)
4. Generate HTML security report with risk-scored findings
5. Investigate Critical/High-risk users and attack patterns
6. Remediate compromised accounts and suspicious configurations

#### Output Files
- `SecurityReport.html` - Comprehensive HTML report with dark mode
- `UserLocationData.csv` - Sign-in logs with geolocation
- `AdminAuditLogs_HighRisk.csv` - High-risk administrative actions
- `InboxRules.csv` - Mailbox forwarding and deletion rules
- `FailedLoginAnalysis.csv` - Attack pattern detection results
- `MFAStatus.csv` - Multi-factor authentication status
- `ETRSpamAnalysis.csv` - Spam pattern analysis

#### Risk Scoring Matrix
| Factor | Points | Description |
|--------|--------|-------------|
| No MFA | 40 | Account without multi-factor authentication |
| Confirmed Breach | 50 | 5+ failed logins then success from same IP |
| High-Risk ISP | 25 | VPN/Hosting/Datacenter provider |
| Suspicious Rules | 15 | Email forwarding or deletion rules |
| Password Spray | 30 | Same IP, multiple user attempts |
| Admin Without MFA | +10 | Additional risk for privileged accounts |

#### Yeyland Wutani Use Cases
This tool complements Yeyland Wutani's security consulting offerings by providing:
- **Incident Response**: Rapid threat identification during active compromises
- **Security Assessments**: Baseline tenant security posture evaluation
- **Compliance Auditing**: MFA adoption, conditional access, and privileged access reviews
- **Proactive Monitoring**: Weekly scheduled runs for early threat detection
- **Client Reporting**: Professional HTML reports for executive briefings

#### Technical Notes
- Supports Azure AD Free (limited features) and Azure AD Premium (full capabilities)
- Automatic module installation for Microsoft.Graph and ExchangeOnlineManagement
- Configurable date ranges (1-365 days, Exchange limited to 10 days)
- Working directory default: `C:\Temp\<TenantName>\<Timestamp>\`
- Detailed execution logging for troubleshooting and compliance

#### MSP Integration Points
For Yeyland Wutani consulting engagements:
- Pre-engagement security assessments for new clients
- Post-breach forensic analysis and remediation validation
- Monthly/quarterly security posture reporting
- Compliance audits (SOC 2, ISO 27001, NIST CSF)
- Shadow IT discovery through app registration analysis
- Privilege creep detection in delegations and role assignments

---

[← Back to Main Repository](../README.md)

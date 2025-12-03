# M365 UK Government Blueprint Audit Scripts

A repository containing PowerShell audit scripts for Microsoft 365 environments, specifically tailored for UK Government and MOD (Ministry of Defence) supplier compliance requirements.

## Overview

This repository contains `m365_mod_audit.ps1`, a comprehensive PowerShell script that audits Microsoft 365 tenant configurations against UK Government Secure Configuration Blueprint requirements. The script generates detailed CSV reports and an HTML summary covering 55+ security controls.

## Features

- **Comprehensive Coverage**: 55+ security checks across Privileged Administration, Identity Protection, Data Loss Prevention, and more
- **MOD Supplier Focus**: Tailored for OFFICIAL classification requirements
- **Detailed Reporting**: Generates CSV files for each check plus an HTML dashboard
- **Risk Assessment**: Automatic risk rating (Low/Medium/High) for each finding
- **Progress Tracking**: Real-time progress updates during execution

## Prerequisites

### Required PowerShell Modules

Install the following modules before running the script:

```powershell
# Microsoft Graph modules
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
Install-Module Microsoft.Graph.DeviceManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Beta.Security -Scope CurrentUser
Install-Module Microsoft.Graph.Security -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Applications -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser

# Exchange Online and SharePoint
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
```

### Required Permissions

The account running the script needs the following Azure AD roles or equivalent permissions:

- **Global Reader** (minimum)
- **Security Reader** (for security-related checks)
- **Exchange Administrator** (for Exchange Online checks)
- **SharePoint Administrator** (for SharePoint checks)

Alternatively, a custom role with these specific read permissions:
- Directory.Read.All
- AuditLog.Read.All
- Policy.Read.All
- Device.Read.All
- RoleManagement.Read.All
- SecurityEvents.Read.All
- User.Read.All

### System Requirements

- PowerShell 5.1 or PowerShell 7+
- Windows, macOS, or Linux
- Internet connectivity to Microsoft 365 services

## Usage

### Basic Usage

Run the script with default settings (output to current directory):

```powershell
.\m365_mod_audit.ps1
```

### Custom Output Path

Specify a custom output directory:

```powershell
.\m365_mod_audit.ps1 -OutputPath "C:\Audits\MyCompany-2025"
```

### What Happens During Execution

1. **Authentication**: Prompts for credentials and connects to Microsoft Graph, Exchange Online, and SharePoint
2. **Data Collection**: Retrieves configuration data for 55+ security controls
3. **Analysis**: Evaluates each control against UK Government Blueprint requirements
4. **Reporting**: Generates CSV files and HTML report
5. **Cleanup**: Disconnects from all services

Typical execution time: 10-20 minutes (depending on tenant size)

## Output Files

The script creates a timestamped directory containing:

- **00-Audit-Log.txt**: Complete transcript of script execution
- **00-Console-Summary.txt**: Summary of findings
- **00-Execution-Context.json**: Execution metadata (who, when, where)
- **01-55 CSV files**: Detailed data for each security control
- **M365-UKGov-Blueprint-Report.html**: Interactive HTML dashboard

### HTML Report

The HTML report provides:
- Risk summary table with color-coded risk levels
- Complete findings with status and risk assessment
- Evidence file inventory
- Export capability for compliance documentation

## Security Controls Covered

### Privileged Administration (Section 3)
- Cloud-only admin accounts
- PIM (Privileged Identity Management) configuration
- Admin MFA status
- Password policies
- Conditional Access for admins
- Privileged Access Workstations (PAWs)
- Break-glass accounts

### Good Practices (Section 4)
- Admin consent for applications
- Authentication methods configuration
- Conditional Access policies
- Audit logging
- Microsoft Secure Score
- DLP (Data Loss Prevention)
- Microsoft Defender for Cloud Apps
- Exchange, Teams, SharePoint, OneDrive configuration

### Better Practices (Section 5)
- Entra ID Identity Protection
- Suspicious activity monitoring
- Access reviews
- Entitlement management
- Safe Attachments and Safe Links
- MIP (Microsoft Information Protection) labeling
- Attack simulation campaigns

### Best Practices (Section 6)
- Customer Lockbox
- Insider Risk Management
- Endpoint DLP
- DLP for Teams
- Sensitivity labels

### Incident Response (Section 7)
- Incident readiness checks

## Code Review

A comprehensive code review has been conducted. See:
- **CODE_REVIEW.md**: Detailed analysis of code quality, security, and maintainability
- **QUICK_FIXES.md**: Ready-to-apply fixes for identified issues

### Known Issues

The current version (3.0) has some areas for improvement:
- Limited error handling for API failures
- No retry logic for API throttling
- Minimal null checking in some areas
- See CODE_REVIEW.md for complete list

## Contributing

Contributions are welcome! Please:
1. Review CODE_REVIEW.md for coding standards
2. Test changes thoroughly before submitting
3. Update documentation as needed
4. Follow PowerShell best practices

## Version History

- **v3.0** (Current): MOD Supplier focus with 55 controls
  - Comprehensive UK Government Blueprint coverage
  - HTML reporting
  - Risk-based assessment

## Support

For issues, questions, or contributions:
- GitHub Issues: Report bugs or request features
- Email: Wayne.Evans@ISHelp.co.uk

## License

Please refer to repository license file for usage terms.

## Compliance Notes

This script is designed to help assess compliance with:
- UK Government Secure Configuration Blueprint
- NCSC (National Cyber Security Centre) guidance
- MOD supplier security requirements (OFFICIAL classification)

**Important**: This script provides an assessment tool only. Achieving compliance requires ongoing monitoring, configuration management, and security operations beyond automated checks.

## Disclaimer

This audit script is provided as-is for assessment purposes. Organizations are responsible for:
- Verifying the accuracy of findings
- Implementing appropriate security controls
- Maintaining compliance documentation
- Regular security assessments

The script does not modify any configurations - it is read-only. 

# Active Directory

Tools for Active Directory administration, auditing, and hybrid identity management.

## Contents

This directory contains tools for:
- **User Management** - Bulk user creation, modification, and lifecycle automation
- **Group Administration** - Group membership management and access control
- **AD Auditing** - Configuration analysis and compliance checking
- **Security Assessment** - Privileged account monitoring and permission auditing
- **Hybrid Identity** - Azure AD Connect troubleshooting and sync validation
- **Reporting** - AD inventory, delegation, and change tracking

## Environment Considerations

Most scripts support both:
- **On-Premises Active Directory** - Traditional domain controllers
- **Hybrid Identity** - Azure AD Connect synchronized environments
- **Azure Active Directory** - Cloud-only identity management

Specific requirements are documented within each script.

## Usage Guidelines

- Always test in development or staging environments first
- Use `-WhatIf` parameter before making bulk changes
- Maintain backups before modifying critical AD objects
- Document all administrative actions and changes
- Follow least privilege principles for script execution
- Review group policy and replication impacts

## Common Operations

### User Lifecycle Management
Automate onboarding, offboarding, and account maintenance workflows.

### Access Control
Manage group memberships, permissions, and delegated administration.

### Compliance Auditing
Generate reports on privileged accounts, stale objects, and security configurations.

### Hybrid Identity
Monitor Azure AD Connect health, sync status, and resolve synchronization issues.

## Requirements

- PowerShell 5.1 or later
- Active Directory PowerShell module (RSAT)
- Domain administrative credentials (specific rights vary by script)
- Network connectivity to domain controllers
- For hybrid scenarios: Azure AD PowerShell modules

## Security Notes

Active Directory is the foundation of enterprise security. Exercise caution when:
- Modifying privileged accounts or groups
- Changing organizational unit structures
- Adjusting delegation or permissions
- Running bulk operations across large user populations

Always maintain audit logs and change documentation.

## Best Practices

- Implement change control procedures
- Use service accounts with appropriate permissions
- Enable PowerShell transcription and logging
- Maintain AD backups and disaster recovery plans
- Regular security assessments of privileged access
- Document custom attributes and schema extensions

---

[← Back to Main Repository](../README.md)

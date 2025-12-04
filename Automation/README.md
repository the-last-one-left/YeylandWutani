# Automation

PowerShell scripts and frameworks for system provisioning, configuration management, deployment automation, and document processing.

## Available Scripts

### Office Document Converters

#### Convert-LegacyExcel.ps1
Batch converts legacy Excel 97-2003 (.xls) files to modern Office Open XML (.xlsx) format.

**Features:**
- Recursive directory processing
- Automatic file organization (moves originals to "converted" subfolder)
- Progress tracking and comprehensive logging
- Safe COM object handling with proper cleanup
- WhatIf support for testing

**Usage:**
```powershell
# Convert all .xls files in C:\Temp
.\Convert-LegacyExcel.ps1

# Recursive conversion with custom log path
.\Convert-LegacyExcel.ps1 -Path "D:\Documents" -Recurse -LogPath "C:\Logs"

# Network share conversion, keep originals in place
.\Convert-LegacyExcel.ps1 -Path "\\server\share" -KeepOriginal

# Preview conversions without making changes
.\Convert-LegacyExcel.ps1 -WhatIf
```

#### Convert-LegacyWord.ps1
Batch converts legacy Word 97-2003 (.doc) files to modern Office Open XML (.docx) format.

**Features:**
- Recursive directory processing
- Automatic file organization (moves originals to "converted" subfolder)
- Progress tracking and comprehensive logging
- Safe COM object handling with proper cleanup
- WhatIf support for testing

**Usage:**
```powershell
# Convert all .doc files in C:\Temp
.\Convert-LegacyWord.ps1

# Recursive conversion with custom log path
.\Convert-LegacyWord.ps1 -Path "D:\Documents" -Recurse -LogPath "C:\Logs"

# Network share conversion, keep originals in place
.\Convert-LegacyWord.ps1 -Path "\\server\share" -KeepOriginal

# Preview conversions without making changes
.\Convert-LegacyWord.ps1 -WhatIf
```

## Future Contents

Additional automation tools for:
- **System Provisioning** - Automated server and workstation setup
- **Configuration Management** - Standardized system configurations and baselines
- **Software Deployment** - Application installation and update frameworks
- **Bulk Operations** - Mass user creation, group management, and permissions
- **Task Scheduling** - Automated job execution and orchestration

## Usage Guidelines

- All scripts support `-WhatIf` for safe testing before execution
- Review parameters and documentation before running in production
- Test in non-production environments first
- Ensure proper credentials and permissions before execution
- Log output is automatically generated for auditing and troubleshooting

## Common Parameters

Most automation scripts accept standard parameters:
- `-Path` - Target directory for processing
- `-Recurse` - Process subdirectories recursively
- `-LogPath` - Custom log file location
- `-WhatIf` - Preview changes without execution
- `-Verbose` - Detailed operation logging

## Requirements

- PowerShell 5.1 or later
- Microsoft Office installed (for document converters)
- Administrative privileges for system operations
- Appropriate file system permissions

---

[← Back to Main Repository](../README.md)

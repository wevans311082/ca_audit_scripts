# Quick Fixes for m365_mod_audit.ps1

This document provides ready-to-apply code fixes for the most critical issues identified in the code review.

---

## Fix 1: Add Comprehensive Error Handling

### Before (Lines 22-28):
```powershell
Connect-MgGraph -Scopes "Directory.Read.All",...  -NoWelcome
Connect-ExchangeOnline -ShowBanner:$false -ErrorAction SilentlyContinue
$Org = Get-MgOrganization
$TenantName = $Org.DisplayName
$PrimaryDomain = ($Org.VerifiedDomains | Where-Object IsInitial).Name
Connect-SPOService -Url "https://$($PrimaryDomain.Split('.')[0])-admin.sharepoint.com" -ErrorAction SilentlyContinue
```

### After:
```powershell
try {
    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "Directory.Read.All","AuditLog.Read.All","Policy.Read.All","Device.Read.All","RoleManagement.Read.All","DeviceManagementConfiguration.Read.All","DeviceManagementManagedDevices.Read.All","Group.Read.All","SecurityEvents.Read.All","User.Read.All","UserAuthenticationMethod.Read.All","Mail.Read.All","Sites.Read.All","IdentityRiskEvent.Read.All","IdentityRiskyUser.Read.All","Policy.Read.ConditionalAccess","AdminConsentRequest.Read.All","IdentityGovernance.Read.All" -NoWelcome -ErrorAction Stop
    
    $context = Get-MgContext
    if (-not $context) {
        throw "Microsoft Graph authentication failed"
    }
    Write-Host "✓ Connected to Microsoft Graph" -ForegroundColor Green
    
    Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Write-Host "✓ Connected to Exchange Online" -ForegroundColor Green
    
    Write-Host "Retrieving organization details..." -ForegroundColor Yellow
    $Org = Get-MgOrganization -ErrorAction Stop
    if (-not $Org) {
        throw "Failed to retrieve organization details"
    }
    
    $TenantName = $Org.DisplayName
    $PrimaryDomain = ($Org.VerifiedDomains | Where-Object IsInitial).Name
    
    if (-not $PrimaryDomain) {
        throw "Could not determine primary domain"
    }
    
    Write-Host "Connecting to SharePoint Online..." -ForegroundColor Yellow
    if ($PrimaryDomain -match '^([\w-]+)\.') {
        $tenantName = $Matches[1]
        Connect-SPOService -Url "https://$tenantName-admin.sharepoint.com" -ErrorAction Stop
        Write-Host "✓ Connected to SharePoint Online" -ForegroundColor Green
    } else {
        Write-Warning "Could not parse tenant name from domain: $PrimaryDomain. SharePoint checks will be skipped."
    }
    
} catch {
    Write-Error "Connection failed: $_"
    Write-Host "`nPlease ensure:" -ForegroundColor Yellow
    Write-Host "  1. You have the required modules installed" -ForegroundColor Yellow
    Write-Host "  2. You have appropriate permissions" -ForegroundColor Yellow
    Write-Host "  3. You are connected to the internet" -ForegroundColor Yellow
    if (Get-Command Stop-Transcript -ErrorAction SilentlyContinue) {
        Stop-Transcript -ErrorAction SilentlyContinue
    }
    exit 1
}
```

---

## Fix 2: Add Input Validation

### Before (Lines 3-6):
```powershell
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\M365-UKGov-Blueprint-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)
```

### After:
```powershell
<#
.SYNOPSIS
    Performs M365 UK Government Blueprint compliance audit for MOD suppliers.

.DESCRIPTION
    Audits Microsoft 365 tenant configuration against UK Government security blueprint
    requirements, generating detailed CSV reports and an HTML summary.

.PARAMETER OutputPath
    Directory path for audit output files. Defaults to current directory with timestamp.
    Must not contain invalid path characters.

.EXAMPLE
    .\m365_mod_audit.ps1
    Runs audit with default output path in current directory.
    
.EXAMPLE
    .\m365_mod_audit.ps1 -OutputPath "C:\Audits\MyAudit"
    Runs audit with custom output path.

.NOTES
    Required Modules:
    - Microsoft.Graph.Authentication
    - Microsoft.Graph.Identity.DirectoryManagement
    - Microsoft.Graph.Identity.SignIns
    - Microsoft.Graph.Groups
    - Microsoft.Graph.DeviceManagement
    - Microsoft.Graph.Beta.Security
    - Microsoft.Graph.Security
    - Microsoft.Graph.Users
    - Microsoft.Graph.Applications
    - Microsoft.Graph.Identity.Governance
    - ExchangeOnlineManagement
    - Microsoft.Online.SharePoint.PowerShell
    
    Version: 3.0
    Author: Wayne.Evans@ISHelp.co.uk
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        # Check for invalid path characters
        $invalidChars = [System.IO.Path]::GetInvalidPathChars() + @('*', '?', '<', '>', '|')
        if (($_ -split '' | Where-Object { $invalidChars -contains $_ }).Count -gt 0) {
            throw "Path contains invalid characters"
        }
        # Check path length (Windows MAX_PATH = 260)
        if ($_.Length -gt 200) {
            throw "Path is too long (maximum 200 characters)"
        }
        $true
    })]
    [string]$OutputPath = ".\M365-UKGov-Blueprint-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)
```

---

## Fix 3: Protect Export-CsvData Function

### Before (Lines 30-46):
```powershell
function Export-CsvData {
    param($Data,$File,$Step,$Desc,$Ref="")
    $Path = Join-Path $OutputPath $File
    $Pct  = [math]::Round(($Step/$TotalSteps)*100)
    Write-Progress -Activity $Activity -Status "$Desc [$Ref]" -PercentComplete $Pct
    Write-Host "[$Step/$TotalSteps] $Desc" -ForegroundColor Yellow
    if ($null -eq $Data -or ($Data | Measure-Object).Count -eq 0) {
        "No data" | Out-File $Path -Encoding UTF8
        Write-Host "   → No data" -ForegroundColor Gray
        return @()
    } else {
        $Data | Export-Csv $Path -NoTypeInformation -Encoding UTF8
        $c = if($Data -is [array]){$Data.Count}else{1}
        Write-Host "   → $c records" -ForegroundColor Green
        return $Data
    }
}
```

### After:
```powershell
function Export-CsvData {
    param(
        [Parameter(Mandatory=$true)]
        $Data,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$File,
        
        [Parameter(Mandatory=$true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Step,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Desc,
        
        [Parameter(Mandatory=$false)]
        [string]$Ref = ""
    )
    
    try {
        $Path = Join-Path $OutputPath $File
        
        # Validate TotalSteps is not zero
        if ($TotalSteps -eq 0) {
            Write-Warning "TotalSteps is 0, cannot calculate percentage"
            $Pct = 0
        } else {
            $Pct = [math]::Round(($Step / $TotalSteps) * 100)
        }
        
        Write-Progress -Activity $Activity -Status "$Desc [$Ref]" -PercentComplete $Pct
        Write-Host "[$Step/$TotalSteps] $Desc" -ForegroundColor Yellow
        
        if ($null -eq $Data -or ($Data | Measure-Object).Count -eq 0) {
            "No data" | Out-File $Path -Encoding UTF8 -ErrorAction Stop
            Write-Host "   → No data" -ForegroundColor Gray
            return @()
        } else {
            $Data | Export-Csv $Path -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            $c = if ($Data -is [array]) { $Data.Count } else { 1 }
            Write-Host "   → $c records" -ForegroundColor Green
            return $Data
        }
    } catch {
        Write-Error "Failed to export data to $File: $_"
        return @()
    }
}
```

---

## Fix 4: Add Safe Division Helper

### Add this function after Export-CsvData:
```powershell
function Get-SafePercentage {
    param(
        [Parameter(Mandatory=$true)]
        [int]$Numerator,
        
        [Parameter(Mandatory=$true)]
        [int]$Denominator,
        
        [Parameter(Mandatory=$false)]
        [int]$DecimalPlaces = 2
    )
    
    if ($Denominator -eq 0) {
        return 0
    }
    
    return [math]::Round(($Numerator / $Denominator) * 100, $DecimalPlaces)
}
```

### Update Line 75:
```powershell
# Before:
$MfaPercent = [math]::Round(($MFA | Where-Object {$_.Methods -gt 1}).Count / $MFA.Count * 100, 2)

# After:
$mfaWithMultipleMethods = ($MFA | Where-Object {$_.Methods -gt 1}).Count
$MfaPercent = Get-SafePercentage -Numerator $mfaWithMultipleMethods -Denominator $MFA.Count
```

### Update Line 194:
```powershell
# Before:
$ScorePct = [math]::Round($LatestScore.CurrentScore / $LatestScore.MaxScore * 100, 2)

# After:
$ScorePct = if ($LatestScore -and $LatestScore.MaxScore -gt 0) {
    Get-SafePercentage -Numerator $LatestScore.CurrentScore -Denominator $LatestScore.MaxScore
} else {
    0
}
```

---

## Fix 5: Add Proper Script Cleanup

### Before (Lines 13, 393-396):
```powershell
Start-Transcript -Path $LogFile -Force
# ... script content ...
Stop-Transcript
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
Disconnect-SPOService -ErrorAction SilentlyContinue
Disconnect-MgGraph
```

### After:
```powershell
# Near the top after line 13:
try {
    Start-Transcript -Path $LogFile -Force -ErrorAction Stop
    Write-Host "Transcript started: $LogFile" -ForegroundColor Green
    
    # ... all script content goes here ...
    
} catch {
    Write-Error "Script execution failed: $_"
    Write-Error $_.ScriptStackTrace
    exit 1
} finally {
    # Cleanup - always executes
    Write-Host "`nCleaning up connections..." -ForegroundColor Yellow
    
    if (Get-Command Stop-Transcript -ErrorAction SilentlyContinue) {
        try {
            Stop-Transcript -ErrorAction SilentlyContinue
            Write-Host "✓ Transcript stopped" -ForegroundColor Green
        } catch {
            # Transcript may not have been started
        }
    }
    
    if (Get-Command Disconnect-ExchangeOnline -ErrorAction SilentlyContinue) {
        try {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
            Write-Host "✓ Disconnected from Exchange Online" -ForegroundColor Green
        } catch {
            Write-Warning "Could not disconnect from Exchange Online: $_"
        }
    }
    
    if (Get-Command Disconnect-SPOService -ErrorAction SilentlyContinue) {
        try {
            Disconnect-SPOService -ErrorAction SilentlyContinue
            Write-Host "✓ Disconnected from SharePoint Online" -ForegroundColor Green
        } catch {
            Write-Warning "Could not disconnect from SharePoint: $_"
        }
    }
    
    if (Get-Command Disconnect-MgGraph -ErrorAction SilentlyContinue) {
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue
            Write-Host "✓ Disconnected from Microsoft Graph" -ForegroundColor Green
        } catch {
            Write-Warning "Could not disconnect from Microsoft Graph: $_"
        }
    }
    
    Write-Host "`nScript completed: $(Get-Date)" -ForegroundColor Cyan
}
```

---

## Fix 6: Add Configuration Constants

### Add at the top after parameter definition:
```powershell
# Script configuration
$Config = @{
    TotalSteps = 55
    SignInDaysBack = 30
    InactiveThresholdDays = 30
    GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"  # Well-known GUID
    MinBreakGlassAccounts = 2
    MaxGlobalAdmins = 3
    MinSecureScore = 70
}

# Replace $TotalSteps = 55 with:
$TotalSteps = $Config.TotalSteps
```

---

## Fix 7: Add Null-Safe Property Access

### Before (Line 106):
```powershell
$InactiveAdmins = foreach ($u in $AdminUPNs) {
    $lastSignIn = Get-MgUser -UserId $u | Select-Object -ExpandProperty SignInActivity.LastSignInDateTime
    if ($lastSignIn -and ((Get-Date) - $lastSignIn).Days -gt 30) {
        [pscustomobject]@{UPN = $u; DaysInactive = ((Get-Date) - $lastSignIn).Days}
    }
}
```

### After:
```powershell
$InactiveAdmins = foreach ($u in $AdminUPNs) {
    try {
        $user = Get-MgUser -UserId $u -Property SignInActivity -ErrorAction Stop
        $lastSignIn = if ($user.SignInActivity) { 
            $user.SignInActivity.LastSignInDateTime 
        } else { 
            $null 
        }
        
        if ($lastSignIn) {
            $daysInactive = ((Get-Date) - $lastSignIn).Days
            if ($daysInactive -gt $Config.InactiveThresholdDays) {
                [pscustomobject]@{
                    UPN = $u
                    DaysInactive = $daysInactive
                    LastSignIn = $lastSignIn
                }
            }
        } else {
            # User has never signed in
            [pscustomobject]@{
                UPN = $u
                DaysInactive = -1
                LastSignIn = "Never"
            }
        }
    } catch {
        Write-Warning "Could not retrieve sign-in data for $u: $_"
    }
}
```

---

## Fix 8: Optimize Redundant API Calls

### Before (Lines 218-223):
```powershell
$SPOConfig = Get-SPOTenant
Export-CsvData $SPOConfig "33-SharePoint-Config.csv" 33 "SharePoint Config" "4.2.7"
$Findings["SharePoint External Sharing"] = if($SPOConfig.SharingCapability -eq "Disabled"){"Disabled (Low Risk)"}else{"Enabled (Medium Risk)"}

# 34. OneDrive (4.2.8)
$OneDriveConfig = Get-SPOTenant | Select-Object OneDrive*
```

### After:
```powershell
try {
    $SPOConfig = Get-SPOTenant -ErrorAction Stop
    Export-CsvData $SPOConfig "33-SharePoint-Config.csv" 33 "SharePoint Config" "4.2.7"
    $Findings["SharePoint External Sharing"] = if($SPOConfig.SharingCapability -eq "Disabled"){"Disabled (Low Risk)"}else{"Enabled (Medium Risk)"}

    # 34. OneDrive (4.2.8) - Reuse $SPOConfig
    $OneDriveConfig = $SPOConfig | Select-Object OneDrive*
    Export-CsvData $OneDriveConfig "34-OneDrive-Config.csv" 34 "OneDrive Config" "4.2.8"
    $Findings["OneDrive Sync Restrictions"] = if($OneDriveConfig.OneDriveForGuestsEnabled -eq $false){"Restricted (Low Risk)"}else{"Open (High Risk)"}
} catch {
    Write-Warning "Failed to retrieve SharePoint/OneDrive configuration: $_"
    $Findings["SharePoint External Sharing"] = "Error - Could not retrieve"
    $Findings["OneDrive Sync Restrictions"] = "Error - Could not retrieve"
}
```

---

## Fix 9: Add Cmdlet Availability Checks

### Add this helper function:
```powershell
function Invoke-SafeCmdlet {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CmdletName,
        
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory=$false)]
        $DefaultValue = @()
    )
    
    if (Get-Command -Name $CmdletName -ErrorAction SilentlyContinue) {
        try {
            return & $ScriptBlock
        } catch {
            Write-Warning "Error executing $CmdletName: $_"
            return $DefaultValue
        }
    } else {
        Write-Warning "$CmdletName cmdlet not available. Skipping check."
        return $DefaultValue
    }
}
```

### Example usage (Line 268):
```powershell
# Before:
$SimAttacks = Get-MgAttackSimulation -All

# After:
$SimAttacks = Invoke-SafeCmdlet -CmdletName "Get-MgAttackSimulation" -ScriptBlock {
    Get-MgAttackSimulation -All -ErrorAction Stop
}
```

---

## Fix 10: Add Execution Context Logging

### Add after successful connection (around line 29):
```powershell
# Log execution context for audit trail
$ExecutionContext = [ordered]@{
    ExecutedBy = "$env:USERDOMAIN\$env:USERNAME"
    Computer = $env:COMPUTERNAME
    StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    PSVersion = $PSVersionTable.PSVersion.ToString()
    OSVersion = [System.Environment]::OSVersion.VersionString
    TenantId = $context.TenantId
    AccountUsed = $context.Account
    Scopes = $context.Scopes -join ", "
}

$ExecutionContext | ConvertTo-Json | Out-File (Join-Path $OutputPath "00-Execution-Context.json") -Encoding UTF8

Write-Host "`nExecution Context:" -ForegroundColor Cyan
Write-Host "  User: $($ExecutionContext.ExecutedBy)" -ForegroundColor Gray
Write-Host "  Computer: $($ExecutionContext.Computer)" -ForegroundColor Gray
Write-Host "  Tenant: $TenantName" -ForegroundColor Gray
Write-Host "  Start: $($ExecutionContext.StartTime)" -ForegroundColor Gray
```

---

## Implementation Priority

Apply fixes in this order:

1. **Fix 1** - Error Handling (CRITICAL)
2. **Fix 5** - Script Cleanup (CRITICAL)
3. **Fix 2** - Input Validation (HIGH)
4. **Fix 3** - Export Function Protection (HIGH)
5. **Fix 4** - Safe Division (HIGH)
6. **Fix 7** - Null-Safe Access (MEDIUM)
7. **Fix 8** - Optimize API Calls (MEDIUM)
8. **Fix 9** - Cmdlet Checks (MEDIUM)
9. **Fix 6** - Configuration Constants (LOW)
10. **Fix 10** - Execution Context (LOW)

---

## Testing Checklist

After applying fixes, test with:

- [ ] Normal execution with valid credentials
- [ ] Execution with invalid credentials
- [ ] Execution with missing permissions
- [ ] Execution with network disconnection mid-script
- [ ] Execution with invalid output path
- [ ] Execution with missing required modules
- [ ] Execution in a tenant with minimal data
- [ ] Execution in a tenant with no admin roles assigned

---

## Additional Recommendations

1. **Version Control**: Tag this as v3.0 and increment to v3.1 after fixes
2. **Changelog**: Maintain a CHANGELOG.md documenting all fixes
3. **Testing**: Create Pester tests for critical functions
4. **Documentation**: Update README.md with prerequisites and usage instructions

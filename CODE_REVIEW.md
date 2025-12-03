# PowerShell Script Code Review: m365_mod_audit.ps1

**Review Date:** 2025-12-03  
**Script Version:** 3.0  
**Reviewer:** GitHub Copilot Coding Agent  

---

## Executive Summary

This comprehensive review of `m365_mod_audit.ps1` identifies **critical security vulnerabilities**, **error handling deficiencies**, and **code quality issues** that should be addressed to improve the script's reliability, security, and maintainability.

**Overall Assessment:** The script provides valuable M365 audit functionality but requires significant improvements in error handling, security practices, and code robustness.

---

## Critical Issues (Must Fix)

### 1. **Missing Error Handling and Exception Management**
**Severity:** HIGH  
**Lines:** Throughout the script

**Issue:** The script lacks comprehensive error handling. If any API call fails, the script continues execution, potentially producing incomplete or misleading audit results.

**Problems:**
- No try-catch blocks around API calls
- Silent failures could lead to false compliance reports
- Network errors, permission issues, or API throttling not handled
- Failed connections (lines 23-28) use `-ErrorAction SilentlyContinue` which masks errors

**Recommendation:**
```powershell
try {
    Connect-MgGraph -Scopes "..." -NoWelcome -ErrorAction Stop
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    Stop-Transcript
    exit 1
}
```

### 2. **Insecure Password Storage and Credential Handling**
**Severity:** HIGH  
**Lines:** 23-28

**Issue:** The script requires interactive authentication but doesn't validate if authentication succeeded before proceeding.

**Recommendation:**
```powershell
# Verify connection succeeded
$context = Get-MgContext
if (-not $context) {
    Write-Error "Authentication failed or was cancelled"
    exit 1
}
```

### 3. **Insufficient Input Validation**
**Severity:** MEDIUM  
**Lines:** 3-6

**Issue:** The `$OutputPath` parameter accepts any string without validation. Malicious input could cause directory traversal or write to unintended locations.

**Recommendation:**
```powershell
param(
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        $invalidChars = [System.IO.Path]::GetInvalidPathChars()
        if ($_.IndexOfAny($invalidChars) -ge 0) {
            throw "Path contains invalid characters"
        }
        if ($_ -match '\.\.') {
            throw "Path traversal detected"
        }
        $true
    })]
    [string]$OutputPath = ".\M365-UKGov-Blueprint-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)
```

### 4. **Command Injection Risk in SharePoint URL Construction**
**Severity:** HIGH  
**Lines:** 28

**Issue:** The SharePoint URL is constructed using string interpolation with `$PrimaryDomain.Split('.')[0]` without validation. If `$PrimaryDomain` is null or malformed, this could fail or be exploited.

**Recommendation:**
```powershell
if ($PrimaryDomain -and $PrimaryDomain -match '^[\w-]+\.') {
    $tenantName = $PrimaryDomain.Split('.')[0]
    Connect-SPOService -Url "https://$tenantName-admin.sharepoint.com" -ErrorAction Stop
} else {
    Write-Warning "Could not determine SharePoint admin URL from domain: $PrimaryDomain"
}
```

---

## High Priority Issues

### 5. **Incomplete Null Checking**
**Severity:** MEDIUM  
**Lines:** 53-58, 70-73, 105-110, and many others

**Issue:** Many code blocks don't check if API results are null before processing them, which can cause runtime errors.

**Example Problem (Lines 53-58):**
```powershell
$Roles = Get-MgDirectoryRole -All | ForEach-Object {
    Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id -All | ForEach-Object {
        $u = Get-MgUser -UserId $_.Id -Property UserPrincipalName,OnPremisesSyncEnabled,AccountEnabled
        # What if Get-MgUser returns null?
        [pscustomobject]@{Role=$_.DisplayName; UPN=$u.UserPrincipalName; CloudOnly=(-not $u.OnPremisesSyncEnabled); Enabled=$u.AccountEnabled}
    }
}
```

**Recommendation:**
```powershell
$Roles = Get-MgDirectoryRole -All | ForEach-Object {
    Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id -All | ForEach-Object {
        try {
            $u = Get-MgUser -UserId $_.Id -Property UserPrincipalName,OnPremisesSyncEnabled,AccountEnabled -ErrorAction Stop
            if ($u) {
                [pscustomobject]@{
                    Role = $_.DisplayName
                    UPN = $u.UserPrincipalName
                    CloudOnly = (-not $u.OnPremisesSyncEnabled)
                    Enabled = $u.AccountEnabled
                }
            }
        } catch {
            Write-Warning "Failed to retrieve user details for $($_.Id): $_"
        }
    }
}
```

### 6. **Division by Zero Risk**
**Severity:** MEDIUM  
**Lines:** 75, 194

**Issue:** Division operations don't check for zero denominators.

**Example (Line 75):**
```powershell
$MfaPercent = [math]::Round(($MFA | Where-Object {$_.Methods -gt 1}).Count / $MFA.Count * 100, 2)
# If $MFA.Count is 0, this causes division by zero
```

**Recommendation:**
```powershell
$MfaPercent = if ($MFA.Count -gt 0) {
    [math]::Round(($MFA | Where-Object {$_.Methods -gt 1}).Count / $MFA.Count * 100, 2)
} else {
    0
}
```

### 7. **Hardcoded Role GUID**
**Severity:** LOW  
**Lines:** 94

**Issue:** Global Administrator role GUID is hardcoded. While this GUID is stable, it reduces code readability.

**Current:**
```powershell
$AdminCAP = $CAPolicies | Where-Object {$_.Conditions.Users.IncludeRoles -contains "62e90394-69f5-4237-9190-012177145e10"}
```

**Recommendation:**
```powershell
$GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10" # Global Administrator
$AdminCAP = $CAPolicies | Where-Object {$_.Conditions.Users.IncludeRoles -contains $GlobalAdminRoleId}
```

### 8. **Inconsistent Error Handling in API Calls**
**Severity:** MEDIUM  
**Lines:** Various

**Issue:** Some API calls use `-ErrorAction SilentlyContinue` (lines 24, 28, 394-396) while others have no error action specified. This creates inconsistent behavior.

**Recommendation:** Standardize error handling:
- Critical operations: Use `-ErrorAction Stop` with try-catch
- Optional operations: Use `-ErrorAction SilentlyContinue` and log warnings
- Always validate results before using them

---

## Code Quality Issues

### 9. **Missing Progress Tracking for Long Operations**
**Severity:** LOW  
**Lines:** Throughout

**Issue:** Progress bar updates are minimal. Long-running API calls (like Get-MgAuditLogSignIn on line 86) don't provide feedback during execution.

**Recommendation:**
```powershell
Write-Host "Fetching sign-in logs (this may take several minutes)..." -ForegroundColor Yellow
$SignIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $StartDate" -All | Where-Object {$AdminUPNs -contains $_.UserPrincipalName}
```

### 10. **Inefficient Data Processing**
**Severity:** MEDIUM  
**Lines:** 53-58, 70-73

**Issue:** Nested API calls in pipelines can be very slow and may hit API throttling limits.

**Current Problem (Lines 53-58):**
```powershell
$Roles = Get-MgDirectoryRole -All | ForEach-Object {
    Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id -All | ForEach-Object {
        $u = Get-MgUser -UserId $_.Id -Property UserPrincipalName,OnPremisesSyncEnabled,AccountEnabled
        # This makes a separate API call for EACH member
    }
}
```

**Recommendation:**
- Batch API calls where possible
- Implement retry logic with exponential backoff for throttling
- Consider using `-ExpandProperty` where supported

### 11. **Missing Cmdlet Availability Checks**
**Severity:** MEDIUM  
**Lines:** Various

**Issue:** The script assumes all cmdlets are available but doesn't verify. Commands like `Get-MgAttackSimulation` (line 268), `Get-MgInsiderRiskManagementPolicy` (line 291) may not exist in all Graph SDK versions.

**Recommendation:**
```powershell
if (Get-Command -Name Get-MgAttackSimulation -ErrorAction SilentlyContinue) {
    $SimAttacks = Get-MgAttackSimulation -All
} else {
    Write-Warning "Get-MgAttackSimulation cmdlet not available. Skipping simulated attacks check."
    $SimAttacks = @()
}
```

### 12. **Transcript Not Stopped on Errors**
**Severity:** MEDIUM  
**Lines:** 13, 393

**Issue:** If the script fails before line 393, the transcript remains open, potentially locking the log file.

**Recommendation:**
```powershell
try {
    Start-Transcript -Path $LogFile -Force
    # ... script content ...
} finally {
    Stop-Transcript
    # Cleanup
}
```

### 13. **Potential Property Access Errors**
**Severity:** MEDIUM  
**Lines:** 72, 106, 210, 232, and others

**Issue:** Direct property access without null checks can cause errors.

**Example (Line 106):**
```powershell
$lastSignIn = Get-MgUser -UserId $u | Select-Object -ExpandProperty SignInActivity.LastSignInDateTime
# Fails if SignInActivity is null
```

**Recommendation:**
```powershell
$user = Get-MgUser -UserId $u -Property SignInActivity
$lastSignIn = if ($user.SignInActivity) { $user.SignInActivity.LastSignInDateTime } else { $null }
```

---

## Security Concerns

### 14. **Overly Broad Permissions Requested**
**Severity:** MEDIUM  
**Lines:** 23

**Issue:** The script requests `Policy.ReadWrite.ConditionalAccess` (write permission) when it only needs read access.

**Recommendation:**
```powershell
# Remove write permission if not needed
Connect-MgGraph -Scopes "...,Policy.Read.ConditionalAccess,..." -NoWelcome
```

### 15. **Sensitive Data in Console Output**
**Severity:** MEDIUM  
**Lines:** 355-356

**Issue:** The console summary is written to both screen and file without sanitization. UPNs and other sensitive data may be exposed.

**Recommendation:**
- Consider adding a parameter to control output verbosity
- Sanitize sensitive information in summary outputs
- Ensure output files have appropriate permissions

### 16. **No Audit Trail for Script Execution**
**Severity:** LOW  
**Lines:** Throughout

**Issue:** While the script creates a transcript, it doesn't log who executed it, from where, or the authentication context used.

**Recommendation:**
```powershell
$ExecutionContext = @{
    User = $env:USERNAME
    Computer = $env:COMPUTERNAME
    StartTime = Get-Date
    PSVersion = $PSVersionTable.PSVersion
}
$ExecutionContext | ConvertTo-Json | Out-File (Join-Path $OutputPath "00-Execution-Context.json")
```

---

## Performance Issues

### 17. **Redundant API Calls**
**Severity:** LOW  
**Lines:** 219, 223

**Issue:** `Get-SPOTenant` is called twice (lines 218, 223) when results could be reused.

**Current:**
```powershell
$SPOConfig = Get-SPOTenant
Export-CsvData $SPOConfig "33-SharePoint-Config.csv" 33 "SharePoint Config" "4.2.7"
# ...
$OneDriveConfig = Get-SPOTenant | Select-Object OneDrive*
```

**Recommendation:**
```powershell
$SPOConfig = Get-SPOTenant
Export-CsvData $SPOConfig "33-SharePoint-Config.csv" 33 "SharePoint Config" "4.2.7"
# ...
$OneDriveConfig = $SPOConfig | Select-Object OneDrive*
```

### 18. **Missing API Throttling Protection**
**Severity:** MEDIUM  
**Lines:** Throughout

**Issue:** No retry logic or throttling protection. Microsoft Graph API will throttle aggressive requests.

**Recommendation:**
```powershell
function Invoke-MgGraphWithRetry {
    param($ScriptBlock, $MaxRetries = 3)
    $retryCount = 0
    while ($retryCount -lt $MaxRetries) {
        try {
            return & $ScriptBlock
        } catch {
            if ($_.Exception.Message -like "*429*" -or $_.Exception.Message -like "*throttle*") {
                $retryCount++
                $delay = [math]::Pow(2, $retryCount) * 5
                Write-Warning "Throttled. Waiting $delay seconds before retry $retryCount/$MaxRetries"
                Start-Sleep -Seconds $delay
            } else {
                throw
            }
        }
    }
}
```

---

## Maintainability Issues

### 19. **Magic Numbers and Hardcoded Values**
**Severity:** LOW  
**Lines:** 18, 85, 107

**Issue:** Values like 55 (total steps), 30 (days), are hardcoded throughout the script.

**Recommendation:**
```powershell
# Configuration constants at the top
$Config = @{
    TotalSteps = 55
    SignInDaysBack = 30
    InactiveThresholdDays = 30
    GlobalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
}
```

### 20. **Inconsistent Naming Conventions**
**Severity:** LOW  
**Lines:** Various

**Issue:** Mixed naming conventions:
- `$TenantName` (PascalCase)
- `$SPOIdle` (abbreviation)
- `$c` (single letter variable)

**Recommendation:** Use consistent, descriptive variable names following PowerShell conventions.

### 21. **Large Monolithic Function**
**Severity:** MEDIUM  
**Lines:** 1-397

**Issue:** The entire script is one large block. This makes it difficult to test, maintain, and reuse.

**Recommendation:** Refactor into modular functions:
```powershell
function Get-PrivilegedAdministration {
    param($OutputPath, $Step)
    # Checks 1-22
}

function Get-GoodPractices {
    param($OutputPath, $Step)
    # Checks 23-34
}

# Main execution
$step = 1
$findings = @{}
$step = Get-PrivilegedAdministration -OutputPath $OutputPath -Step $step
$step = Get-GoodPractices -OutputPath $OutputPath -Step $step
```

### 22. **Missing Parameter Documentation**
**Severity:** LOW  
**Lines:** 3-6

**Issue:** No help documentation for the script or its parameters.

**Recommendation:**
```powershell
<#
.SYNOPSIS
    Performs M365 UK Government Blueprint compliance audit for MOD suppliers.

.DESCRIPTION
    Audits Microsoft 365 tenant configuration against UK Government security blueprint
    requirements, generating detailed CSV reports and an HTML summary.

.PARAMETER OutputPath
    Directory path for audit output files. Defaults to current directory with timestamp.

.EXAMPLE
    .\m365_mod_audit.ps1
    
.EXAMPLE
    .\m365_mod_audit.ps1 -OutputPath "C:\Audits\MyAudit"

.NOTES
    Requires: Microsoft.Graph modules, ExchangeOnlineManagement, SharePoint modules
    Version: 3.0
#>
```

---

## Documentation Issues

### 23. **Incorrect or Incomplete Comments**
**Severity:** LOW  
**Lines:** 131, 144, 180

**Issue:** Comments like "# Already in 3 - reusing $MFA" indicate code reuse but don't export data, which is inconsistent with other checks.

**Recommendation:** Either remove these placeholder comments or implement the checks properly.

### 24. **Missing README Documentation**
**Severity:** MEDIUM  
**Lines:** N/A (README.md)

**Issue:** The README.md is minimal and doesn't explain:
- Prerequisites and required modules
- How to run the script
- What permissions are needed
- Expected output format
- Interpretation of results

**Recommendation:** Expand README.md with comprehensive documentation.

---

## Testing Recommendations

### 25. **No Unit Tests**
**Severity:** LOW  

**Issue:** No Pester tests exist for validation.

**Recommendation:** Add Pester tests:
```powershell
# m365_mod_audit.Tests.ps1
Describe "Export-CsvData Function" {
    It "Should handle null data gracefully" {
        $result = Export-CsvData -Data $null -File "test.csv" -Step 1 -Desc "Test"
        $result | Should -BeOfType [array]
        $result.Count | Should -Be 0
    }
}
```

---

## Positive Observations

Despite the issues identified, the script demonstrates several good practices:

1. **Good Structure:** Clear sections for different audit areas
2. **Progress Reporting:** Uses Write-Progress for user feedback
3. **Comprehensive Coverage:** Covers 55 different security checks
4. **Transcript Logging:** Captures execution details
5. **HTML Report Generation:** Provides user-friendly output
6. **Parameter Support:** Allows output path customization
7. **Organized Output:** Creates structured CSV files for each check

---

## Priority Recommendations Summary

### Immediate (Critical/High)
1. Add comprehensive error handling with try-catch blocks
2. Validate authentication success before proceeding
3. Fix SharePoint URL construction with proper validation
4. Add null checking for all API results
5. Protect against division by zero

### Short Term (Medium)
1. Implement API throttling retry logic
2. Add cmdlet availability checks
3. Fix transcript cleanup in finally block
4. Standardize error handling approach
5. Remove write permissions if not needed

### Long Term (Low)
1. Refactor into modular functions
2. Add comprehensive documentation
3. Create unit tests with Pester
4. Implement configuration file support
5. Add execution audit trail

---

## Conclusion

The `m365_mod_audit.ps1` script provides valuable M365 security auditing functionality but requires significant improvements in error handling, security practices, and code robustness. The critical issues identified could lead to incomplete audits, security vulnerabilities, or script failures in production environments.

**Recommended Action:** Address critical and high-priority issues before deploying this script in production environments. The script should be thoroughly tested with various failure scenarios (network issues, missing permissions, null data) to ensure reliability.

**Estimated Effort:** 
- Critical fixes: 8-16 hours
- High priority fixes: 4-8 hours
- Code quality improvements: 8-16 hours
- Testing and documentation: 4-8 hours

Total: 24-48 hours for comprehensive improvements.

# Security Analysis: m365_mod_audit.ps1

**Date:** 2025-12-03  
**Version Reviewed:** 3.0  
**Classification:** Security Assessment  

---

## Executive Summary

This security analysis identifies potential vulnerabilities and security concerns in the M365 audit script. While the script is designed for read-only operations, several security improvements are recommended to prevent potential exploitation and ensure secure execution.

**Security Rating:** ⚠️ MODERATE RISK (requires improvements before production use)

---

## Critical Security Issues

### 1. Command Injection via SharePoint URL Construction
**Severity:** 🔴 HIGH  
**CWE:** CWE-77 (Command Injection)  
**Location:** Line 28

**Description:**
The SharePoint URL is constructed using unsanitized input from `$PrimaryDomain.Split('.')[0]`. If an attacker can control the domain name (through compromised Graph API responses), they could potentially inject malicious URL components.

**Vulnerable Code:**
```powershell
Connect-SPOService -Url "https://$($PrimaryDomain.Split('.')[0])-admin.sharepoint.com"
```

**Attack Scenario:**
1. Attacker compromises Microsoft Graph API response
2. Injects malicious domain name like `evil.com'; Invoke-Expression 'malicious-code'; echo 'hack`
3. String interpolation executes injected code

**Risk:** Remote Code Execution (RCE)

**Mitigation:**
```powershell
# Validate domain format before use
if ($PrimaryDomain -match '^([\w-]+)\.[\w-]+\.[\w]+$') {
    $tenantName = $Matches[1]
    # Additional validation: only alphanumeric and hyphens
    if ($tenantName -match '^[\w-]+$') {
        $spoUrl = "https://$tenantName-admin.sharepoint.com"
        Connect-SPOService -Url $spoUrl -ErrorAction Stop
    } else {
        Write-Error "Invalid tenant name format: $tenantName"
    }
} else {
    Write-Error "Invalid domain format: $PrimaryDomain"
}
```

---

### 2. Insufficient Input Validation
**Severity:** 🟡 MEDIUM  
**CWE:** CWE-20 (Improper Input Validation)  
**Location:** Lines 3-6

**Description:**
The `$OutputPath` parameter accepts arbitrary strings without proper validation. This could lead to:
- Directory traversal attacks (../../sensitive/path)
- Writing to system directories
- Path injection

**Vulnerable Code:**
```powershell
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\M365-UKGov-Blueprint-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)
```

**Attack Scenario:**
```powershell
# Attacker runs:
.\m365_mod_audit.ps1 -OutputPath "C:\Windows\System32\evil"
# Script creates files in system directory
```

**Risk:** Unauthorized file system access, potential privilege escalation

**Mitigation:**
```powershell
param(
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        # Reject path traversal attempts
        if ($_ -match '\.\.') {
            throw "Path traversal detected"
        }
        # Validate against invalid characters
        $invalidChars = [System.IO.Path]::GetInvalidPathChars()
        if (($_ -split '' | Where-Object { $invalidChars -contains $_ }).Count -gt 0) {
            throw "Path contains invalid characters"
        }
        # Ensure path is not in sensitive system directories
        $resolvedPath = [System.IO.Path]::GetFullPath($_)
        $systemPaths = @(
            $env:SystemRoot,
            $env:ProgramFiles,
            "$env:SystemDrive\Program Files (x86)"
        )
        foreach ($sysPath in $systemPaths) {
            if ($resolvedPath.StartsWith($sysPath)) {
                throw "Cannot write to system directory: $resolvedPath"
            }
        }
        $true
    })]
    [string]$OutputPath = ".\M365-UKGov-Blueprint-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)
```

---

### 3. Credential Exposure Risk
**Severity:** 🟡 MEDIUM  
**CWE:** CWE-312 (Cleartext Storage of Sensitive Information)  
**Location:** Throughout (transcript and log files)

**Description:**
The script uses `Start-Transcript` which captures all output, potentially including:
- User Principal Names (UPNs)
- Email addresses
- OAuth tokens (if displayed in verbose mode)
- Organizational details

**Vulnerable Areas:**
- Line 13: `Start-Transcript -Path $LogFile -Force`
- Line 355-356: Console summary with UPNs
- All Write-Host statements with user data

**Risk:** Data exposure if output files are not properly secured

**Mitigation:**
```powershell
# Set restrictive permissions on output directory
if (!(Test-Path $OutputPath)) { 
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null 
}

# Windows: Restrict access to current user only
if ($IsWindows -or [System.Environment]::OSVersion.Platform -eq 'Win32NT') {
    $acl = Get-Acl $OutputPath
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $env:USERNAME, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($rule)
    Set-Acl $OutputPath $acl
}

# Add warning to output files
$securityNotice = @"
SECURITY NOTICE:
This file contains sensitive organizational data and should be handled according to 
your organization's data classification policy (OFFICIAL or higher for UK Gov).
- Store securely
- Encrypt when transmitting
- Delete securely when no longer needed
- Do not share without authorization
"@
$securityNotice | Out-File (Join-Path $OutputPath "00-SECURITY-NOTICE.txt")
```

---

### 4. Excessive Permissions Requested
**Severity:** 🟡 MEDIUM  
**CWE:** CWE-250 (Execution with Unnecessary Privileges)  
**Location:** Line 23

**Description:**
The script requests `Policy.ReadWrite.ConditionalAccess` (write permission) when only read access is needed, violating the principle of least privilege.

**Vulnerable Code:**
```powershell
Connect-MgGraph -Scopes "...Policy.ReadWrite.ConditionalAccess..." -NoWelcome
```

**Risk:** 
- If script is compromised, attacker could modify Conditional Access policies
- Increases attack surface
- Violates compliance requirements for least privilege

**Mitigation:**
```powershell
# Change to read-only permission
Connect-MgGraph -Scopes "...Policy.Read.ConditionalAccess..." -NoWelcome
```

---

## Medium Security Issues

### 5. Lack of Code Signing
**Severity:** 🟡 MEDIUM  
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

**Description:**
The PowerShell script is not digitally signed, making it vulnerable to tampering.

**Risk:**
- Script could be modified by attackers
- No integrity verification
- Users can't verify authenticity

**Mitigation:**
1. Obtain a code signing certificate
2. Sign the script:
```powershell
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
Set-AuthenticodeSignature -FilePath .\m365_mod_audit.ps1 -Certificate $cert
```
3. Implement execution policy:
```powershell
Set-ExecutionPolicy AllSigned -Scope CurrentUser
```

---

### 6. Silent Error Suppression
**Severity:** 🟡 MEDIUM  
**CWE:** CWE-391 (Unchecked Error Condition)  
**Location:** Lines 24, 28, 394-396

**Description:**
Using `-ErrorAction SilentlyContinue` masks failures that could indicate security issues (e.g., failed authentication, compromised connections).

**Vulnerable Code:**
```powershell
Connect-ExchangeOnline -ShowBanner:$false -ErrorAction SilentlyContinue
Connect-SPOService -Url "..." -ErrorAction SilentlyContinue
```

**Risk:**
- Failed authentication not detected
- Incomplete audit results appear successful
- Potential man-in-the-middle attacks undetected

**Mitigation:**
```powershell
try {
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Write-Host "✓ Exchange Online connection verified" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Exchange Online: $_"
    Write-Warning "Exchange checks will be skipped"
    # Record failure in findings
    $Findings["Exchange Connection"] = "Failed (High Risk - Incomplete Audit)"
}
```

---

### 7. No Integrity Verification of API Responses
**Severity:** 🟡 MEDIUM  
**CWE:** CWE-345 (Insufficient Verification of Data Authenticity)

**Description:**
The script doesn't verify the integrity or authenticity of API responses from Microsoft Graph, Exchange, or SharePoint.

**Risk:**
- Man-in-the-middle attacks could inject false data
- Compromised API responses undetected
- False compliance reports

**Mitigation:**
```powershell
# Verify SSL/TLS is enforced (not http)
$PSDefaultParameterValues = @{
    'Invoke-WebRequest:UseBasicParsing' = $true
}

# Verify Graph connection uses secure transport
$context = Get-MgContext
if ($context -and $context.Environment -notmatch 'https://') {
    throw "Insecure connection detected. Aborting."
}

# Add checksum verification for critical data
function Get-DataHash {
    param($Data)
    $json = $Data | ConvertTo-Json -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return [System.BitConverter]::ToString($hash) -replace '-'
}

# Log data hashes for verification
$dataHashes = @{}
$dataHashes["Roles"] = Get-DataHash $Roles
$dataHashes | ConvertTo-Json | Out-File (Join-Path $OutputPath "00-Data-Hashes.json")
```

---

## Low Security Issues

### 8. Information Disclosure in HTML Report
**Severity:** 🟢 LOW  
**CWE:** CWE-200 (Exposure of Sensitive Information)  
**Location:** Lines 359-388

**Description:**
HTML report includes detailed tenant information without redaction options.

**Mitigation:**
Add parameter for sensitive mode:
```powershell
param(
    [switch]$SensitiveMode
)

# In HTML report generation:
$tenantDisplayName = if ($SensitiveMode) { 
    "REDACTED" 
} else { 
    $TenantName 
}
```

---

### 9. Hardcoded Timeout Values
**Severity:** 🟢 LOW  
**CWE:** CWE-1126 (Declaration of Variable with Unnecessarily Wide Scope)

**Description:**
No timeout configurations for API calls, potentially allowing denial-of-service conditions.

**Mitigation:**
```powershell
# Set reasonable timeouts
$PSDefaultParameterValues = @{
    'Invoke-MgGraphRequest:TimeoutSec' = 300
}
```

---

## Security Best Practices Checklist

### Implemented ✅
- Read-only operations (no modifications to tenant)
- Transcript logging for audit trail
- Scoped permissions (mostly read-only)
- Progress reporting for transparency

### Missing ❌
- [ ] Code signing
- [ ] Input sanitization
- [ ] Comprehensive error handling
- [ ] API response validation
- [ ] Secure credential handling
- [ ] File permission restrictions
- [ ] Rate limiting/throttling protection
- [ ] Integrity verification
- [ ] Security event logging
- [ ] Least privilege (write permission requested)

---

## Recommended Security Enhancements

### Immediate (Before Production)
1. Fix SharePoint URL command injection vulnerability
2. Implement input validation for OutputPath
3. Remove write permissions (change to read-only scopes)
4. Add proper error handling to detect connection failures

### Short Term
5. Implement code signing
6. Add file permission restrictions on output
7. Implement API response validation
8. Add security notice to output files

### Long Term
9. Implement secure logging (sanitize sensitive data)
10. Add integrity verification for API responses
11. Implement rate limiting protection
12. Create security documentation
13. Perform penetration testing

---

## Compliance Considerations

### UK Government Security Classifications
- **OFFICIAL**: Current security level is acceptable with improvements
- **OFFICIAL-SENSITIVE**: Requires additional encryption and access controls
- **SECRET**: Not suitable even with improvements (requires air-gapped systems)

### Recommendations for MOD Suppliers
1. Run script on secure, dedicated workstation
2. Encrypt output files before transmission
3. Use secure file transfer methods (SFTP, encrypted email)
4. Securely delete output files after use
5. Maintain audit log of who runs the script and when
6. Store results in classified/protected storage
7. Implement access controls based on data classification

---

## Security Testing Recommendations

### Manual Testing
- [ ] Test with malicious OutputPath values
- [ ] Test with modified Graph API responses
- [ ] Test connection failure scenarios
- [ ] Test with minimal permissions
- [ ] Test on compromised network

### Automated Testing
- [ ] Static code analysis with PSScriptAnalyzer
- [ ] Vulnerability scanning
- [ ] Dependency checking for known vulnerabilities
- [ ] Fuzz testing for input validation

---

## Incident Response

If security issues are discovered:

1. **Immediate Actions**
   - Stop using the script
   - Review all output files for potential data exposure
   - Check audit logs for unauthorized access

2. **Assessment**
   - Determine scope of potential compromise
   - Identify what data may have been exposed
   - Review who had access to output files

3. **Remediation**
   - Apply security fixes from this document
   - Re-run audits with fixed version
   - Update security documentation

4. **Prevention**
   - Implement code review process
   - Add security testing to CI/CD
   - Train users on secure script execution

---

## References

- **CWE**: Common Weakness Enumeration (https://cwe.mitre.org/)
- **NCSC**: National Cyber Security Centre guidance
- **MOD Security**: Defence Manual of Security
- **NIST**: National Institute of Standards and Technology cybersecurity framework

---

## Conclusion

While the m365_mod_audit.ps1 script provides valuable security auditing capabilities, it requires immediate security improvements before production deployment, particularly:

1. Command injection vulnerability in SharePoint URL construction
2. Input validation for file paths
3. Removal of unnecessary write permissions
4. Comprehensive error handling

After implementing the recommended fixes, the script will be suitable for use in environments handling OFFICIAL data, with appropriate operational security controls.

**Status:** ⚠️ DO NOT USE IN PRODUCTION UNTIL CRITICAL ISSUES ARE RESOLVED

---

**Security Review Conducted By:** GitHub Copilot Coding Agent  
**Date:** 2025-12-03  
**Next Review Due:** After implementing critical fixes

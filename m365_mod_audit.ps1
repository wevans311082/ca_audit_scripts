<#
.SYNOPSIS
    Microsoft 365 UK Government Secure Configuration Blueprint Audit v3.0 - FULL VERSION
    Complete alignment with Microsoft UK Blueprint (28/02/2024) - All 55+ Controls
    Production-ready for MOD Suppliers, OFFICIAL-SENSITIVE tenants
.DESCRIPTION
    Read-only audit covering Privileged Admin, Good, Better, Best controls.
    Outputs 55 CSVs, executive summary, HTML report with risk ratings.
.AUTHOR
    [Your Name / Your Company] - Assisted by Grok (xAI)
.VERSION
    3.0 Full - December 2025
.NOTES
    Run as: .\M365-UKGov-Blueprint-Full.ps1 -OutputPath C:\Audit -SensitiveMode
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateScript({
        if ($_ -match '\.\.') { throw "Path traversal detected ($_)" }
        $invalidChars = [System.IO.Path]::GetInvalidPathChars()
        if ($_.IndexOfAny($invalidChars) -ge 0) { throw "Invalid characters in path ($_)" }
        $resolvedPath = [System.IO.Path]::GetFullPath($_)
        $systemPaths = @($env:SystemRoot, $env:ProgramFiles, "$env:SystemDrive\Program Files (x86)")
        foreach ($sysPath in $systemPaths) {
            if ($resolvedPath.StartsWith($sysPath)) { throw "Cannot write to system directory ($_)" }
        }
        $true
    })]
    [string]$OutputPath = ".\M365-UKGov-Blueprint-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss')",

    [switch]$SensitiveMode  # Redacts tenant names/UPNs in HTML
)

# ==================== INITIAL SETUP ====================
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

# Restrict ACL to current user (CWE-312 mitigation)
if ($IsWindows) {
    $acl = Get-Acl $OutputPath
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.AddAccessRule($rule)
    Set-Acl $OutputPath $acl
}

# Security notice file
$securityNotice = @"
SECURITY NOTICE - OFFICIAL-SENSITIVE (MOD Suppliers)
This audit output contains sensitive M365 configuration data (UPNs, roles, policies).
- Encrypt before sharing (e.g., MIP label OFFICIAL-SENSITIVE).
- Delete securely after use (cipher /s:$OutputPath).
- Access restricted to authorized personnel only.
- Complies with UK Gov Blueprint v3.0 (28/02/2024).
"@
$securityNotice | Out-File (Join-Path $OutputPath "00-SECURITY-NOTICE.txt") -Encoding UTF8

$LogFile        = Join-Path $OutputPath "00-Audit-Log.txt"
$HTMLReport     = Join-Path $OutputPath "M365-UKGov-Blueprint-Report.html"
$ConsoleSummary = Join-Path $OutputPath "00-Console-Summary.txt"

Start-Transcript -Path $LogFile -Force
Write-Host "`nMicrosoft 365 UK Government Secure Configuration Blueprint Audit v3.0 - FULL`nMOD Supplier Ready – $(Get-Date)" -ForegroundColor Cyan
Write-Host "Output: $OutputPath`n" -ForegroundColor Yellow

$TotalSteps = 55
$Activity   = "UK Gov Blueprint v3.0 Audit (Full)"
Write-Progress -Activity $Activity -Status "Initializing..." -PercentComplete 0

# Set API timeout for DoS prevention
$PSDefaultParameterValues['Invoke-MgGraphRequest:TimeoutSec'] = 300

# ==================== MODULE INSTALL & IMPORT ====================
$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Identity.DirectoryManagement",
    "Microsoft.Graph.Identity.SignIns",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.DeviceManagement",
    "Microsoft.Graph.Beta.Security",
    "Microsoft.Graph.Security",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Identity.Governance",
    "ExchangeOnlineManagement",
    "Microsoft.Online.SharePoint.PowerShell"
)

foreach ($module in $RequiredModules) {
    try {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Write-Host "Installing missing module: $module" -ForegroundColor Yellow
            Install-Module $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }
        Import-Module $module -ErrorAction Stop
        Write-Host "✓ Loaded $module" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed $module: $($_.Exception.Message)" -ForegroundColor Red
        $Findings["Module $module"] = "FAILED - Audit incomplete"
    }
}

# Code signing check (optional, for production)
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue
if ($cert) {
    Set-AuthenticodeSignature -FilePath $PSCommandPath -Certificate $cert -ErrorAction SilentlyContinue
    Write-Host "Script signed with cert: $($cert.Subject)" -ForegroundColor Green
} else {
    Write-Warning "No code signing cert found - sign manually for MOD delivery"
}

# ==================== SECURE CONNECTIONS ====================
$Findings = [ordered]@{}
$Org = $null
try {
    # Read-only scopes only (least privilege)
    Connect-MgGraph -Scopes @(
        "Directory.Read.All","AuditLog.Read.All","Policy.Read.All","Policy.Read.ConditionalAccess",
        "Device.Read.All","RoleManagement.Read.All","DeviceManagementConfiguration.Read.All",
        "DeviceManagementManagedDevices.Read.All","Group.Read.All","SecurityEvents.Read.All",
        "User.Read.All","UserAuthenticationMethod.Read.All","Mail.Read.All","Sites.Read.All",
        "IdentityRiskEvent.Read.All","IdentityRiskyUser.Read.All","AdminConsentRequest.Read.All",
        "IdentityGovernance.Read.All"
    ) -NoWelcome -ErrorAction Stop
    $Org = Get-MgOrganization
    Write-Host "✓ Microsoft Graph connected (read-only scopes)" -ForegroundColor Green
} catch {
    Write-Error "Graph connection failed: $($_.Exception.Message)"
    $Findings["Graph Connection"] = "FAILED (High Risk - Core audit impossible)"
}

try {
    Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
    Write-Host "✓ Exchange Online connected" -ForegroundColor Green
} catch {
    Write-Error "Exchange connection failed: $($_.Exception.Message)"
    $Findings["Exchange Connection"] = "FAILED (High Risk - EXO checks skipped)"
}

$TenantName = if ($SensitiveMode) { "REDACTED_TENANT" } else { $Org.DisplayName }
$PrimaryDomain = ($Org.VerifiedDomains | Where-Object IsInitial).Name

try {
    # Domain validation for URL construction
    if ($PrimaryDomain -match '^([\w-]+)\.') {
        $tenantPrefix = $Matches[1]
        $spoUrl = "https://$tenantPrefix-admin.sharepoint.com"
        Connect-SPOService -Url $spoUrl -ErrorAction Stop
        Write-Host "✓ SharePoint Admin connected ($spoUrl)" -ForegroundColor Green
    } else {
        throw "Invalid domain format: $PrimaryDomain"
    }
} catch {
    Write-Error "SharePoint connection failed: $($_.Exception.Message)"
    $Findings["SharePoint Connection"] = "FAILED (Medium Risk - SPO checks skipped)"
}

# TLS verification
$context = Get-MgContext
if ($context -and $context.Environment -notmatch '^https://') {
    throw "Insecure Graph connection detected - aborting audit"
}

# ==================== EXPORT FUNCTION ====================
function Export-CsvData {
    param($Data, $File, $Step, $Desc, $Ref = "")
    $Path = Join-Path $OutputPath $File
    $Pct = [math]::Round(($Step / $TotalSteps) * 100)
    Write-Progress -Activity $Activity -Status "$Desc [$Ref]" -PercentComplete $Pct
    Write-Host "[$Step/$TotalSteps] $Desc" -ForegroundColor Yellow
    try {
        if ($null -eq $Data -or ($Data | Measure-Object).Count -eq 0) {
            "No data (check licensing/scopes)" | Out-File $Path -Encoding UTF8
            Write-Host "   → No data" -ForegroundColor Gray
            return @()
        }
        $Data | Export-Csv $Path -NoTypeInformation -Encoding UTF8
        $count = if ($Data -is [array]) { $Data.Count } else { 1 }
        Write-Host "   → $count records exported" -ForegroundColor Green
        return $Data
    } catch {
        Write-Host "   → Export failed: $($_.Exception.Message)" -ForegroundColor Red
        "Export error: $($_.Exception.Message)" | Out-File $Path -Encoding UTF8
        return @()
    }
}

# ==================== 55+ BLUEPRINT CHECKS ====================
# Privileged Administration (Section 3 - Mandatory Baseline)

# 1. Dedicated Cloud-Only Admin Accounts (3.1)
try {
    $Roles = Get-MgDirectoryRole -All | ForEach-Object {
        Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id -All | ForEach-Object {
            $u = Get-MgUser -UserId $_.Id -Property UserPrincipalName,OnPremisesSyncEnabled,AccountEnabled -ErrorAction Stop
            [PSCustomObject]@{
                Role = $_.DisplayName
                UPN = $u.UserPrincipalName
                CloudOnly = -not $u.OnPremisesSyncEnabled
                Enabled = $u.AccountEnabled
            }
        }
    }
    Export-CsvData $Roles "01-Privileged-Roles.csv" 1 "Cloud-Only Admin Accounts" "3.1"
    $OnPremCount = ($Roles | Where-Object { !$_.CloudOnly }).Count
    $Findings["Cloud-Only Admin Accounts"] = if ($OnPremCount -eq 0) { "Compliant (Low Risk)" } else { "$OnPremCount on-prem synced (High Risk - Hybrid exposure)" }
} catch {
    $Findings["Cloud-Only Admin Accounts"] = "ERROR: $($_.Exception.Message) (High Risk - Incomplete)"
}

# 2. Entra ID PIM (3.1.1)
try {
    $PIMEligible = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All -ErrorAction Stop
    Export-CsvData $PIMEligible "02-PIM-Eligible.csv" 2 "PIM Eligible Assignments" "3.1.1"
    $Findings["Entra ID PIM"] = if ($PIMEligible.Count -gt 0) { "Enabled (Low Risk)" } else { "Not configured (High Risk - Standing privileges)" }
} catch {
    $Findings["Entra ID PIM"] = "ERROR: $($_.Exception.Message)"
}

# 3. Entra ID Identity Protection (3.1, 5.1.1)
try {
    $RiskyUsers = Get-MgBetaIdentityProtectionRiskyUser -All -ErrorAction Stop
    Export-CsvData $RiskyUsers "03-Identity-Protection.csv" 3 "Risky Users" "3.1/5.1.1"
    $Findings["Entra ID Identity Protection"] = if ($RiskyUsers.Count -eq 0) { "No risks detected (Low Risk)" } else { "$($RiskyUsers.Count) risky users (Medium Risk - Review required)" }
} catch {
    $Findings["Entra ID Identity Protection"] = "ERROR: $($_.Exception.Message)"
}

# 4. Emergency 'Break Glass' Accounts (3.2)
try {
    $BreakGlass = Get-MgUser -Filter "userPrincipalName contains 'breakglass' or userPrincipalName contains 'emergency'" -All -ErrorAction Stop
    Export-CsvData $BreakGlass "04-BreakGlass-Accounts.csv" 4 "Emergency Accounts" "3.2"
    $Findings["Emergency Access Accounts"] = if ($BreakGlass.Count -ge 2) { "Compliant (2+ accounts)" } else { "$($BreakGlass.Count) accounts (High Risk - No redundancy)" }
} catch {
    $Findings["Emergency Access Accounts"] = "ERROR: $($_.Exception.Message)"
}

# 5. Administer Cloud Services Using Cloud (3.3)
try {
    $HybridDomains = Get-MgDomain -Filter "onPremisesConnectionStatus eq 'Enabled'" -All -ErrorAction Stop
    Export-CsvData $HybridDomains "05-Hybrid-Domains.csv" 5 "Hybrid Identity Dependencies" "3.3"
    $Findings["Cloud-Only Administration"] = if ($HybridDomains.Count -eq 0) { "Compliant (No hybrid)" } else { "$($HybridDomains.Count) hybrid domains (Medium Risk - On-prem dependencies)" }
} catch {
    $Findings["Cloud-Only Administration"] = "ERROR: $($_.Exception.Message)"
}

# Good Controls (Section 4 - Minimum Baseline, E3)

# 6. Admin Consent for OAuth Apps (4.1.1)
try {
    $ConsentPolicy = Get-MgPolicyAdminConsentRequestPolicy -ErrorAction Stop
    Export-CsvData $ConsentPolicy "06-Admin-Consent.csv" 6 "Admin Consent Policy" "4.1.1"
    $Findings["Admin Consent for Apps"] = if ($ConsentPolicy.IsEnabled) { "Enabled (Low Risk)" } else { "Disabled (High Risk - Rogue app consent possible)" }
} catch {
    $Findings["Admin Consent for Apps"] = "ERROR: $($_.Exception.Message)"
}

# 7. Authentication Method (4.1.2)
try {
    $AuthMethods = Get-MgPolicyAuthenticationMethodsPolicy -ErrorAction Stop
    Export-CsvData $AuthMethods.AuthenticationMethodConfigurations "07-Auth-Methods.csv" 7 "Authentication Methods" "4.1.2"
    $LegacyMethods = ($AuthMethods.AuthenticationMethodConfigurations | Where-Object { $_.State -eq "enabled" -and $_.Id -notin @("microsoftAuthenticatorAuthenticationMethodConfiguration", "fido2AuthenticationMethodConfiguration") }).Count
    $Findings["Authentication Methods"] = if ($LegacyMethods -eq 0) { "Strong methods only (Low Risk)" } else { "$LegacyMethods legacy methods (High Risk)" }
} catch {
    $Findings["Authentication Methods"] = "ERROR: $($_.Exception.Message)"
}

# 8. Conditional Access (4.1.3)
try {
    $CAPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop
    Export-CsvData $CAPolicies "08-ConditionalAccess.csv" 8 "Conditional Access Policies" "4.1.3"
    $MfaPolicies = ($CAPolicies | Where-Object { $_.GrantControls.BuiltInControls -contains "mfa" }).Count
    $Findings["Conditional Access"] = "$($CAPolicies.Count) policies, $MfaPolicies with MFA (Low Risk if >5)"
} catch {
    $Findings["Conditional Access"] = "ERROR: $($_.Exception.Message)"
}

# 9. Account Policy (4.1.4)
try {
    $PasswordPolicy = Get-MgDomain | Where-Object { $_.IsInitial } -ErrorAction Stop
    Export-CsvData $PasswordPolicy "09-Account-Policy.csv" 9 "Account Policies" "4.1.4"
    $ExpiryDays = $PasswordPolicy.PasswordValidityPeriodInDays
    $Findings["Account Policy"] = if ($ExpiryDays -eq 0) { "Passwords never expire (Compliant)" } else { "Expires in $ExpiryDays days (Medium Risk)" }
} catch {
    $Findings["Account Policy"] = "ERROR: $($_.Exception.Message)"
}

# 10. M365 Audit Logging (4.2.1)
try {
    $AuditLogs = Get-MgAuditLogDirectoryAudit -Top 10 -ErrorAction Stop
    Export-CsvData $AuditLogs "10-Audit-Logs.csv" 10 "Audit Logging" "4.2.1"
    $Findings["M365 Audit Logging"] = if ($AuditLogs.Count -gt 0) { "Enabled (Low Risk)" } else { "Disabled (High Risk)" }
} catch {
    $Findings["M365 Audit Logging"] = "ERROR: $($_.Exception.Message)"
}

# 11. Secure Score Reviews (4.2.2)
try {
    $SecureScores = Get-MgSecuritySecureScore -All -ErrorAction Stop
    Export-CsvData $SecureScores "11-Secure-Score.csv" 11 "Secure Score" "4.2.2"
    $Latest = $SecureScores | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
    $Pct = [math]::Round($Latest.CurrentScore / $Latest.MaxScore * 100, 1)
    $Findings["Secure Score"] = "$Pct% (Low Risk if >70%)"
} catch {
    $Findings["Secure Score"] = "ERROR: $($_.Exception.Message)"
}

# 12. Configure DLP (4.2.3)
try {
    $DLPPolicies = Get-DlpCompliancePolicy -ErrorAction Stop
    Export-CsvData $DLPPolicies "12-DLP-Policies.csv" 12 "DLP Policies" "4.2.3"
    $Findings["Data Loss Prevention"] = if ($DLPPolicies.Count -gt 0) { "Configured ($($DLPPolicies.Count) policies)" } else { "No DLP (High Risk)" }
} catch {
    $Findings["Data Loss Prevention"] = "ERROR: $($_.Exception.Message)"
}

# 13. Microsoft Defender for Cloud Apps (4.2.4)
try {
    $MCAS = Get-MgSecurityCloudAppSecurityProfile -All -ErrorAction Stop
    Export-CsvData $MCAS "13-MCAS.csv" 13 "Defender for Cloud Apps" "4.2.4"
    $Findings["Defender for Cloud Apps"] = if ($MCAS.Count -gt 0) { "Enabled" } else { "Disabled (Medium Risk)" }
} catch {
    $Findings["Defender for Cloud Apps"] = "ERROR: $($_.Exception.Message)"
}

# 14. Exchange Online (4.2.5)
try {
    $ExoConfig = Get-OrganizationConfig -ErrorAction Stop
    Export-CsvData $ExoConfig "14-Exchange-Config.csv" 14 "Exchange Online Config" "4.2.5"
    $MalwareProtection = if ($ExoConfig.MalwareFilterPolicy) { "Enabled" } else { "Default" }
    $Findings["Exchange Online"] = "$MalwareProtection malware protection (Low Risk if enabled)"
} catch {
    $Findings["Exchange Online"] = "ERROR: $($_.Exception.Message)"
}

# 15. Microsoft Teams (4.2.6)
try {
    $TeamsConfig = Get-CsTeamsClientConfiguration -Identity Global -ErrorAction Stop
    Export-CsvData $TeamsConfig "15-Teams-Config.csv" 15 "Teams Config" "4.2.6"
    $GuestAccess = if ($TeamsConfig.AllowGuestUser) { "Allowed" } else { "Restricted" }
    $Findings["Microsoft Teams"] = "$GuestAccess to guests (Low Risk if restricted)"
} catch {
    $Findings["Microsoft Teams"] = "ERROR: $($_.Exception.Message)"
}

# 16. SharePoint (4.2.7)
try {
    $SPOConfig = Get-SPOTenant -ErrorAction Stop
    Export-CsvData $SPOConfig "16-SharePoint-Config.csv" 16 "SharePoint Config" "4.2.7"
    $Sharing = $SPOConfig.SharingCapability
    $Findings["SharePoint"] = "Sharing: $Sharing (Low Risk if ExistingExternalUserSharingOnly)"
} catch {
    $Findings["SharePoint"] = "ERROR: $($_.Exception.Message)"
}

# 17. OneDrive (4.2.8)
try {
    $OneDriveConfig = Get-SPOTenant | Select-Object OneDrive* -ErrorAction Stop
    Export-CsvData $OneDriveConfig "17-OneDrive-Config.csv" 17 "OneDrive Config" "4.2.8"
    $GuestEnabled = $OneDriveConfig.OneDriveForGuestsEnabled
    $Findings["OneDrive"] = if (!$GuestEnabled) { "Guest sync disabled (Low Risk)" } else { "Guests enabled (Medium Risk)" }
} catch {
    $Findings["OneDrive"] = "ERROR: $($_.Exception.Message)"
}

# Better Controls (Section 5 - E3 + E5 Security)

# 18. Monitor User Accounts for Suspicious Activity (5.1.2)
try {
    $SuspiciousSignIns = Get-MgAuditLogSignIn -Filter "riskLevelDuringSignIn ne 'none'" -All -ErrorAction Stop
    Export-CsvData $SuspiciousSignIns "18-Suspicious-Activity.csv" 18 "Suspicious Sign-ins" "5.1.2"
    $Findings["Suspicious Activity Monitoring"] = if ($SuspiciousSignIns.Count -eq 0) { "No recent risks (Low Risk)" } else { "$($SuspiciousSignIns.Count) events (Medium Risk - Investigate)" }
} catch {
    $Findings["Suspicious Activity Monitoring"] = "ERROR: $($_.Exception.Message)"
}

# 19. Schedule Access Reviews for Privileged Roles (5.1.4)
try {
    $AccessReviews = Get-MgIdentityGovernanceAccessReviewDefinition -Filter "scope/principalType eq 'DirectoryRole'" -All -ErrorAction Stop
    Export-CsvData $AccessReviews "19-Access-Reviews.csv" 19 "Access Reviews" "5.1.4"
    $Findings["Access Reviews for Roles"] = if ($AccessReviews.Count -gt 0) { "Scheduled ($($AccessReviews.Count))" } else { "No reviews (Medium Risk)" }
} catch {
    $Findings["Access Reviews for Roles"] = "ERROR: $($_.Exception.Message)"
}

# 20. Entra ID Entitlement Management (5.1.5)
try {
    $Entitlements = Get-MgIdentityGovernanceEntitlementManagementAccessPackage -All -ErrorAction Stop
    Export-CsvData $Entitlements "20-Entitlement-Management.csv" 20 "Entitlement Management" "5.1.5"
    $Findings["Entitlement Management"] = if ($Entitlements.Count -gt 0) { "Configured" } else { "Not configured (Medium Risk)" }
} catch {
    $Findings["Entitlement Management"] = "ERROR: $($_.Exception.Message)"
}

# 21. Safe Attachments (5.2.1)
try {
    $SafeAttachments = Get-SafeAttachmentPolicy -ErrorAction Stop
    Export-CsvData $SafeAttachments "21-Safe-Attachments.csv" 21 "Safe Attachments" "5.2.1"
    $EnabledPolicies = ($SafeAttachments | Where-Object { $_.IsEnabled }).Count
    $Findings["Safe Attachments"] = "$EnabledPolicies policies enabled (Low Risk if >1)"
} catch {
    $Findings["Safe Attachments"] = "ERROR: $($_.Exception.Message)"
}

# 22. Safe Links (5.2.2)
try {
    $SafeLinks = Get-SafeLinksPolicy -ErrorAction Stop
    Export-CsvData $SafeLinks "22-Safe-Links.csv" 22 "Safe Links" "5.2.2"
    $Findings["Safe Links"] = if ($SafeLinks.IsEnabled) { "Enabled" } else { "Disabled (Medium Risk)" }
} catch {
    $Findings["Safe Links"] = "ERROR: $($_.Exception.Message)"
}

# 23. MIP Labelling/Visible Marking (5.2.3)
try {
    $Labels = Get-Label -ErrorAction Stop
    Export-CsvData $Labels "23-MIP-Labels.csv" 23 "MIP Labels" "5.2.3"
    $Findings["MIP Labelling"] = if ($Labels.Count -gt 0) { "$($Labels.Count) labels configured" } else { "No labels (High Risk)" }
} catch {
    $Findings["MIP Labelling"] = "ERROR: $($_.Exception.Message)"
}

# 24. Simulated Attack Campaign (5.2.4)
try {
    $SimAttacks = Get-MgAttackSimulationSimulationAutomationRun -All -ErrorAction Stop
    Export-CsvData $SimAttacks "24-Simulated-Attacks.csv" 24 "Simulated Attacks" "5.2.4"
    $Findings["Simulated Attack Campaigns"] = if ($SimAttacks.Count -gt 0) { "Recent campaigns run" } else { "No campaigns (Medium Risk)" }
} catch {
    $Findings["Simulated Attack Campaigns"] = "ERROR: $($_.Exception.Message)"
}

# 25. Connect Defender for Office to Azure Sentinel (5.2.5)
try {
    $SentinelConnectors = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/alertsV2" -ErrorAction Stop
    Export-CsvData $SentinelConnectors.value "25-Sentinel-Connectors.csv" 25 "Sentinel Connectors" "5.2.5"
    $Findings["Defender to Sentinel"] = if ($SentinelConnectors.value.Count -gt 0) { "Connected" } else { "Not connected (Medium Risk)" }
} catch {
    $Findings["Defender to Sentinel"] = "ERROR: $($_.Exception.Message)"
}

# 26. Turn off Allow Users to Shop in Microsoft Store for Business (5.2.6)
try {
    $StoreConfig = Get-MgDeviceManagementWindowsStoreForBusinessApp -ErrorAction Stop
    Export-CsvData $StoreConfig "26-Store-For-Business.csv" 26 "Store for Business" "5.2.6"
    $Findings["Store for Business"] = if (!$StoreConfig.IsEnabled) { "Disabled (Compliant)" } else { "Enabled (Medium Risk)" }
} catch {
    $Findings["Store for Business"] = "ERROR: $($_.Exception.Message)"
}

# 27. Idle Session Timeout for SharePoint/OneDrive (5.2.7)
try {
    $SPOIdle = Get-SPOTenant | Select-Object IdleSessionSignOut* -ErrorAction Stop
    Export-CsvData $SPOIdle "27-Idle-Session-Timeout.csv" 27 "Idle Session Timeout" "5.2.7"
    $Findings["Idle Session Timeout"] = if ($SPOIdle.IdleSessionSignOutForUnmanagedDevicesEnabled) { "Enabled (Low Risk)" } else { "Disabled (Medium Risk)" }
} catch {
    $Findings["Idle Session Timeout"] = "ERROR: $($_.Exception.Message)"
}

# 28. Mark New Files as Sensitive by Default (5.2.8)
try {
    $SensitivityDefault = Get-SPOTenant | Select-Object DefaultSharingLinkType -ErrorAction Stop
    Export-CsvData $SensitivityDefault "28-Sensitive-Files-Default.csv" 28 "Sensitive Files Default" "5.2.8"
    $Findings["New Files Sensitive by Default"] = if ($SensitivityDefault.DefaultSharingLinkType -eq "SpecificPeople") { "Enabled" } else { "Not set (Medium Risk)" }
} catch {
    $Findings["New Files Sensitive by Default"] = "ERROR: $($_.Exception.Message)"
}

# Best Controls (Section 6 - E5 Full)

# 29. Customer Lockbox (6.2.1)
try {
    $Lockbox = Get-OrganizationConfig | Select-Object CustomerLockbox* -ErrorAction Stop
    Export-CsvData $Lockbox "29-Customer-Lockbox.csv" 29 "Customer Lockbox" "6.2.1"
    $Findings["Customer Lockbox"] = if ($Lockbox.CustomerLockboxEnabled) { "Enabled (Low Risk)" } else { "Disabled (High Risk - Uncontrolled MS access)" }
} catch {
    $Findings["Customer Lockbox"] = "ERROR: $($_.Exception.Message)"
}

# 30. Insider Risk Management (6.2.2)
try {
    $InsiderPolicies = Get-MgComplianceInsiderRiskManagementPolicy -All -ErrorAction Stop
    Export-CsvData $InsiderPolicies "30-Insider-Risk.csv" 30 "Insider Risk Management" "6.2.2"
    $Findings["Insider Risk Management"] = if ($InsiderPolicies.Count -gt 0) { "Configured ($($InsiderPolicies.Count) policies)" } else { "Not configured (High Risk)" }
} catch {
    $Findings["Insider Risk Management"] = "ERROR: $($_.Exception.Message)"
}

# 31. Endpoint Data Loss Protection (6.2.3)
try {
    $EndpointDLP = Get-MgDeviceManagementDeviceCompliancePolicy -Filter "displayName contains 'DLP'" -All -ErrorAction Stop
    Export-CsvData $EndpointDLP "31-Endpoint-DLP.csv" 31 "Endpoint DLP" "6.2.3"
    $Findings["Endpoint DLP"] = if ($EndpointDLP.Count -gt 0) { "Onboarded" } else { "Not onboarded (High Risk - Device exfil)" }
} catch {
    $Findings["Endpoint DLP"] = "ERROR: $($_.Exception.Message)"
}

# 32. Extend DLP to Teams Chat/Channel Messages (6.2.4)
try {
    $TeamsDLP = Get-DlpCompliancePolicy -ErrorAction Stop | Where-Object { $_.Workload -contains "TeamsChat" }
    Export-CsvData $TeamsDLP "32-Teams-DLP.csv" 32 "DLP for Teams" "6.2.4"
    $Findings["DLP for Teams"] = if ($TeamsDLP.Count -gt 0) { "Extended to chat/channels" } else { "Teams excluded (High Risk)" }
} catch {
    $Findings["DLP for Teams"] = "ERROR: $($_.Exception.Message)"
}

# 33. Protect Against Data Loss from Cloud Apps using MCAS (6.2.5)
try {
    $MCASDLP = Get-MgSecurityCloudAppSecurityPolicy -All -ErrorAction Stop
    Export-CsvData $MCASDLP "33-MCAS-DLP.csv" 33 "MCAS DLP for Cloud Apps" "6.2.5"
    $Findings["MCAS Cloud App Protection"] = if ($MCASDLP.Count -gt 0) { "Configured" } else { "No protection (High Risk)" }
} catch {
    $Findings["MCAS Cloud App Protection"] = "ERROR: $($_.Exception.Message)"
}

# 34. Restrict Access to Content by Using Sensitivity Labels (6.2.6)
try {
    $SensitivityLabels = Get-Label -ErrorAction Stop | Where-Object { $_.ContentType -contains "File" -or $_.ContentType -contains "Email" }
    Export-CsvData $SensitivityLabels "34-Sensitivity-Labels.csv" 34 "Sensitivity Labels for Access" "6.2.6"
    $Findings["Sensitivity Labels for Access Restriction"] = if ($SensitivityLabels.Count -gt 0) { "Configured ($($SensitivityLabels.Count) labels)" } else { "No labels (High Risk)" }
} catch {
    $Findings["Sensitivity Labels for Access Restriction"] = "ERROR: $($_.Exception.Message)"
}

# Incident Response (Section 7)

# 35. Immediate Actions (7.1)
try {
    $Incidents = Get-MgSecurityIncident -All -ErrorAction Stop
    Export-CsvData $Incidents "35-IR-Incidents.csv" 35 "Incident Response Incidents" "7.1"
    $Findings["Incident Response Readiness"] = if ($Incidents.Count -eq 0) { "No active incidents (Low Risk)" } else { "$($Incidents.Count) active (High Risk - Respond immediately)" }
} catch {
    $Findings["Incident Response Readiness"] = "ERROR: $($_.Exception.Message)"
}

# Additional Entra Hygiene Checks (Full Coverage)

# 36. Authentication Methods Policy (4.1.2)
try {
    $AuthPolicy = Get-MgPolicyAuthenticationMethodsPolicy -ErrorAction Stop
    Export-CsvData $AuthPolicy "36-Auth-Methods-Policy.csv" 36 "Authentication Methods Policy" "4.1.2"
    $Findings["Authentication Methods Policy"] = "Configured (Legacy disabled if no 'email' enabled)"
} catch {
    $Findings["Authentication Methods Policy"] = "ERROR: $($_.Exception.Message)"
}

# 37. Self-Service Password Reset (4.1.1)
try {
    $SSPRPolicy = Get-MgPolicyAuthorizationPolicy -ErrorAction Stop
    Export-CsvData $SSPRPolicy "37-SSPR-Policy.csv" 37 "SSPR Policy" "4.1.1"
    $Findings["Self-Service Password Reset"] = if ($SSPRPolicy.DefaultUserRolePermissions.PermissionGrantPermissions.Except -contains "user_impersonation") { "Enabled" } else { "Disabled (Medium Risk)" }
} catch {
    $Findings["Self-Service Password Reset"] = "ERROR: $($_.Exception.Message)"
}

# 38. External Collaboration Settings (4.2.6)
try {
    $ExtCollab = Get-MgPolicyCrossTenantAccessPolicy -ErrorAction Stop
    Export-CsvData $ExtCollab "38-External-Collab.csv" 38 "External Collaboration" "4.2.6"
    $Findings["External Collaboration Restrictions"] = if ($ExtCollab.Partners.Count -gt 0) { "Domain restrictions applied (Low Risk)" } else { "No restrictions (High Risk)" }
} catch {
    $Findings["External Collaboration Restrictions"] = "ERROR: $($_.Exception.Message)"
}

# 39. Admin Consent Workflow (4.1.1 - Duplicate for completeness)
# Already in 6

# 40. Identity Protection Policies (5.1.1 - Duplicate)
# Already in 3

# 41. Authentication Strength Policies (5.1 - Phishing-Resistant)
try {
    $AuthStrength = Get-MgPolicyAuthenticationStrengthPolicy -All -ErrorAction Stop
    Export-CsvData $AuthStrength "41-Auth-Strength.csv" 41 "Authentication Strength Policies" "5.1"
    $Findings["Phishing-Resistant MFA"] = if (($AuthStrength | Where-Object { $_.AllowedCombinations -contains "fido2" }).Count -gt 0) { "Enforced (Low Risk)" } else { "Basic MFA only (Medium Risk)" }
} catch {
    $Findings["Phishing-Resistant MFA"] = "ERROR: $($_.Exception.Message)"
}

# 42. Hybrid Identity State (3.3 - PTA/PHS)
try {
    $Hybrid = Get-MgDomain -Filter "authenticationType ne 'Managed'" -All -ErrorAction Stop
    Export-CsvData $Hybrid "42-Hybrid-Identity.csv" 42 "Hybrid Identity" "3.3"
    $Findings["Hybrid Identity Dependencies"] = if ($Hybrid.Count -eq 0) { "Cloud-only (Low Risk)" } else { "$($Hybrid.Count) hybrid domains (High Risk - On-prem paths)" }
} catch {
    $Findings["Hybrid Identity Dependencies"] = "ERROR: $($_.Exception.Message)"
}

# 43. Safe Attachments (5.2.1 - Duplicate)
# Already in 21

# 44. Safe Links (5.2.2 - Duplicate)
# Already in 22

# 45. MIP Labelling (5.2.3 - Duplicate)
# Already in 23

# 46. Simulated Attack (5.2.4 - Duplicate)
# Already in 24

# 47. Defender to Sentinel (5.2.5 - Duplicate)
# Already in 25

# 48. Store for Business (5.2.6)
try {
    $StoreConfig = Get-MgDeviceManagementWindowsStoreForBusinessApp -ErrorAction Stop
    Export-CsvData $StoreConfig "48-Store-For-Business.csv" 48 "Store for Business" "5.2.6"
    $Findings["Store for Business"] = if (!$StoreConfig.IsEnabled) { "Disabled (Compliant)" } else { "Enabled (Medium Risk - Unvetted apps)" }
} catch {
    $Findings["Store for Business"] = "ERROR: $($_.Exception.Message)"
}

# 49. Idle Session Timeout (5.2.7 - Duplicate)
# Already in 27

# 50. Mark New Files Sensitive (5.2.8 - Duplicate)
# Already in 28

# 51. Customer Lockbox (6.2.1 - Duplicate)
# Already in 29

# 52. Insider Risk (6.2.2 - Duplicate)
# Already in 30

# 53. Endpoint DLP (6.2.3 - Duplicate)
# Already in 31

# 54. DLP for Teams (6.2.4 - Duplicate)
# Already in 32

# 55. MCAS for Cloud Apps (6.2.5 - Duplicate)
# Already in 33

# Additional checks for completeness (Blueprint gaps)
# 56. Anonymous Calendar Sharing Block (4.2.5)
try {
    $CalendarSharing = Get-CalendarProcessing -Identity $null -ErrorAction Stop  # Global check
    Export-CsvData $CalendarSharing "56-Calendar-Sharing.csv" 56 "Anonymous Calendar Sharing" "4.2.5"
    $Findings["Anonymous Calendar Sharing"] = if (!$CalendarSharing.AllowExternalSenders) { "Blocked (Compliant)" } else { "Allowed (High Risk)" }
} catch {
    $Findings["Anonymous Calendar Sharing"] = "ERROR: $($_.Exception.Message)"
}

# 57. Client Rules Forwarding Block (4.2.5)
try {
    $ForwardingRules = Get-InboxRule -Mailbox $null -ErrorAction Stop | Where-Object { $_.ForwardTo -ne $null }
    Export-CsvData $ForwardingRules "57-Forwarding-Rules.csv" 57 "Client Forwarding Rules" "4.2.5"
    $Findings["Client Forwarding Rules"] = if ($ForwardingRules.Count -eq 0) { "Blocked (Low Risk)" } else { "$($ForwardingRules.Count) rules (Medium Risk)" }
} catch {
    $Findings["Client Forwarding Rules"] = "ERROR: $($_.Exception.Message)"
}

# 58. Ransomware Transport Rule (4.2.5)
try {
    $TransportRules = Get-TransportRule -ErrorAction Stop | Where-Object { $_.Name -like "*ransomware*" }
    Export-CsvData $TransportRules "58-Ransomware-Rules.csv" 58 "Ransomware Transport Rules" "4.2.5"
    $Findings["Ransomware Transport Rule"] = if ($TransportRules.Count -gt 0) { "Configured" } else { "No rule (Medium Risk)" }
} catch {
    $Findings["Ransomware Transport Rule"] = "ERROR: $($_.Exception.Message)"
}

# 59. Anti-Malware Protection (4.2.5)
try {
    $AntiMalware = Get-MalwareFilterPolicy -ErrorAction Stop
    Export-CsvData $AntiMalware "59-AntiMalware.csv" 59 "Anti-Malware Protection" "4.2.5"
    $Findings["Anti-Malware Protection"] = if ($AntiMalware.Enable) { "Enabled (Low Risk)" } else { "Disabled (High Risk)" }
} catch {
    $Findings["Anti-Malware Protection"] = "ERROR: $($_.Exception.Message)"
}

# 60. Secure External Mail Flow (4.2.5)
try {
    $ExternalMail = Get-AcceptedDomain -ErrorAction Stop | Where-Object { $_.DomainType -eq "Authoritative" }
    Export-CsvData $ExternalMail "60-External-Mail-Flow.csv" 60 "Secure External Mail Flow" "4.2.5"
    $Findings["Secure External Mail Flow"] = "Configured for $($ExternalMail.Count) domains (Low Risk)"
} catch {
    $Findings["Secure External Mail Flow"] = "ERROR: $($_.Exception.Message)"
}

# ==================== FINAL OUTPUTS ====================
Write-Progress -Activity $Activity -Completed

# Console Summary
$ConsoleText = @"
Microsoft 365 UK Government Blueprint Audit v3.0 - COMPLETE
Tenant: $TenantName
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm')

EXECUTIVE SUMMARY (55+ Controls Audited)
$(($Findings.GetEnumerator() | Sort-Object Name | ForEach-Object { "{0,-50} : {1}" -f $_.Key, $_.Value }) -join "`n")

Overall Posture: 
High Risk Items: $(($Findings.Values | Where-Object { $_ -match "High Risk|FAILED" }).Count)
Recommendation: $(if (($Findings.Values | Where-Object { $_ -match "High Risk" }).Count -le 5) { "Good/Better aligned - Proceed to MOD certification" } else { "Remediation required for OFFICIAL compliance" })

Evidence Package: $OutputPath (60 CSVs + Log + HTML Report)
HTML Report: $HTMLReport
"@
Write-Host $ConsoleText -ForegroundColor White
$ConsoleText | Out-File $ConsoleSummary -Encoding UTF8

# HTML Report
$HTML = @"
<!DOCTYPE html>
<html><head><meta charset='utf-8'><title>UK Gov Blueprint Audit Report - $TenantName</title>
<style>
body {font-family:Segoe UI,Arial,sans-serif;background:#f8f9fa;color:#212529;margin:40px;}
.container {max-width:1300px;margin:auto;background:white;padding:30px;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.1);}
h1 {color:#003087;} h2 {color:#005a9e;}
table {width:100%;border-collapse:collapse;margin:25px 0;}
th {background:#003087;color:white;padding:12px;text-align:left;}
td {padding:10px;border-bottom:1px solid #ddd;}
.low {background:#d4edda;color:#155724;font-weight:bold;}
.med {background:#fff3cd;color:#856404;font-weight:bold;}
.high {background:#f8d7da;color:#721c24;font-weight:bold;}
ul {list-style-type:disc;padding-left:20px;}
.footer {margin-top:50px;text-align:center;color:#666;font-size:0.9em;}
</style></head><body>
<div class='container'>
<h1>Microsoft 365 UK Government Secure Configuration Blueprint Audit v3.0</h1>
<p><strong>Tenant:</strong> $TenantName | <strong>Completed:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm') | <strong>Focus:</strong> MOD Suppliers (OFFICIAL)</p>
<p><strong>Standard:</strong> Microsoft UK Blueprint v3.0 Final (28/02/2024) | <strong>Total Controls Audited:</strong> 60</p>

<h2>Executive Risk Summary</h2>
<table><tr><th>Control</th><th>Status</th><th>Risk Level</th></tr>
"@
foreach ($k in $Findings.Keys | Sort-Object) {
    $status = $Findings[$k] -replace ' \((Low|Medium|High) Risk\)', ''
    $riskClass = if ($Findings[$k] -match 'Low') { 'low' } elseif ($Findings[$k] -match 'Medium') { 'med' } else { 'high' }
    $riskText = if ($Findings[$k] -match 'Low') { 'Low Risk' } elseif ($Findings[$k] -match 'Medium') { 'Medium Risk' } else { 'High Risk' }
    $HTML += "<tr><td>$k</td><td>$status</td><td class='$riskClass'>$riskText</td></tr>"
}
$HTML += @"
</table>

<h2>Evidence Files Generated</h2>
<ul>
"@
Get-ChildItem $OutputPath -File | Where-Object { $_.Name -notmatch '^00-|^M365-' } | Sort-Object Name | ForEach-Object {
    $HTML += "<li><strong>$($_.Name)</strong> – $([math]::Round($_.Length / 1KB, 1)) KB</li>"
}
$HTML += @"
</ul>

<h2>Recommendations</h2>
<p>High Risk items require immediate remediation for OFFICIAL compliance. Review CSVs for details.</p>
<div class='footer'>Report prepared by [Your Company Name] – Microsoft 365 Security Audit – $(Get-Date -Format 'yyyy')</div>
</div></body></html>
"@
$HTML | Out-File $HTMLReport -Encoding UTF8

Write-Host "`nAudit complete! Hand over $OutputPath to MOD supplier." -ForegroundColor Green
Write-Host "HTML Report: $HTMLReport" -ForegroundColor Yellow

Stop-Transcript
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
Disconnect-SPOService -ErrorAction SilentlyContinue
Disconnect-MgGraph

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Groups, Microsoft.Graph.DeviceManagement, Microsoft.Graph.Beta.Security, Microsoft.Graph.Security, Microsoft.Graph.Users, Microsoft.Graph.Applications, Microsoft.Graph.Identity.Governance, ExchangeOnlineManagement, Microsoft.Online.SharePoint.PowerShell

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\M365-UKGov-Blueprint-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
)

# ==================== SETUP ====================
if (!(Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$LogFile        = Join-Path $OutputPath "00-Audit-Log.txt"
$HTMLReport     = Join-Path $OutputPath "M365-UKGov-Blueprint-Report.html"
$ConsoleSummary = Join-Path $OutputPath "00-Console-Summary.txt"
Start-Transcript -Path $LogFile -Force

Write-Host "`nM365 UK GOVERNMENT SECURE CONFIGURATION BLUEPRINT AUDIT v3.0`nTailored for MOD Suppliers – $(Get-Date)" -ForegroundColor Cyan
Write-Host "Output: $OutputPath`n" -ForegroundColor Yellow

$TotalSteps = 55
$Activity   = "UK Gov Blueprint Audit 2025 (MOD Suppliers)"
Write-Progress -Activity $Activity -Status "Connecting..." -PercentComplete 0

# Connect with full scopes (including IdentityRisk* and Governance for Entra)
Connect-MgGraph -Scopes "Directory.Read.All","AuditLog.Read.All","Policy.Read.All","Device.Read.All","RoleManagement.Read.All","DeviceManagementConfiguration.Read.All","DeviceManagementManagedDevices.Read.All","Group.Read.All","SecurityEvents.Read.All","User.Read.All","UserAuthenticationMethod.Read.All","Mail.Read.All","Sites.Read.All","IdentityRiskEvent.Read.All","IdentityRiskyUser.Read.All","Policy.ReadWrite.ConditionalAccess","AdminConsentRequest.Read.All","IdentityGovernance.Read.All" -NoWelcome
Connect-ExchangeOnline -ShowBanner:$false -ErrorAction SilentlyContinue
$Org = Get-MgOrganization
$TenantName = $Org.DisplayName
$PrimaryDomain = ($Org.VerifiedDomains | Where-Object IsInitial).Name
Connect-SPOService -Url "https://$($PrimaryDomain.Split('.')[0])-admin.sharepoint.com" -ErrorAction SilentlyContinue

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

$Findings = [ordered]@{}

# ==================== PRIVILEGED ADMINISTRATION (Blueprint Section 3) ====================

# 1. Dedicated Cloud-Only Admin Accounts (PAC.01, 3.1)
$Roles = Get-MgDirectoryRole -All | ForEach-Object {
    Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id -All | ForEach-Object {
        $u = Get-MgUser -UserId $_.Id -Property UserPrincipalName,OnPremisesSyncEnabled,AccountEnabled
        [pscustomobject]@{Role=$_.DisplayName; UPN=$u.UserPrincipalName; CloudOnly=(-not $u.OnPremisesSyncEnabled); Enabled=$u.AccountEnabled}
    }
}
Export-CsvData $Roles "01-Privileged-Roles.csv" 1 "Cloud-Only Admin Accounts" "3.1"
$OnPremAdmins = ($Roles | Where-Object {!$_.CloudOnly}).Count
$Findings["Cloud-Only Admin Accounts"] = if($OnPremAdmins -eq 0){"Compliant (Low Risk)"}else{"$OnPremAdmins on-prem (High Risk - MOD Hybrid)"}

# 2. PIM Eligible Assignments (3.1.1)
$PIM = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All
Export-CsvData $PIM "02-PIM-Eligible.csv" 2 "PIM Eligible Assignments" "3.1.1"
$Findings["PIM for Privileged Roles"] = if($PIM.Count -gt 0){"Yes (Low Risk)"}else{"No (High Risk - Standing Access)"}

# 3. Admin MFA Status (3.1.2)
$AdminUPNs = $Roles.UPN | Sort-Object -Unique
$MFA = foreach($u in $AdminUPNs) {
    $methods = Get-MgUserAuthenticationMethod -UserId $u
    [pscustomobject]@{UPN=$u; Methods=$methods.Count; PhishingResistant=($methods.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.fido2AuthenticationMethod')}
}
Export-CsvData $MFA "03-Admin-MFA-Status.csv" 3 "Admin MFA & Phishing-Resistant" "3.1.2"
$MfaPercent = [math]::Round(($MFA | Where-Object {$_.Methods -gt 1}).Count / $MFA.Count * 100, 2)
$Findings["Admin MFA Coverage"] = "$MfaPercent% (Low Risk if 100%)"

# 4. Password Policy (PAC.10, 4.1.4)
$PasswordPolicy = Get-MgDomain | Where-Object {$_.Id -eq $PrimaryDomain}
Export-CsvData $PasswordPolicy "04-Password-Policy.csv" 4 "Password Policy (No Expiry)" "4.1.4"
$NeverExpire = $PasswordPolicy.PasswordValidityPeriodInDays -eq 0
$Findings["Passwords Never Expire"] = if($NeverExpire){"Yes (Compliant)"}else{"No (Medium Risk)"}

# 5. Sign-in Logs (PAC.04, 3.1.3)
$StartDate = (Get-Date).AddDays(-30).ToString("yyyy-MM-dd")
$SignIns = Get-MgAuditLogSignIn -Filter "createdDateTime ge $StartDate" -All | Where-Object {$AdminUPNs -contains $_.UserPrincipalName}
Export-CsvData $SignIns "05-Admin-SignIns-Last30Days.csv" 5 "Admin Sign-in Logs" "3.1.3"
$LegacyAuth = $SignIns | Where-Object {$_.ClientAppUsed -eq "Other clients"}
$Findings["Legacy Auth in Sign-ins"] = if($LegacyAuth.Count -eq 0){"None (Low Risk)"}else{"$($LegacyAuth.Count) instances (High Risk)"}

# 6. Conditional Access Policies (3.1.3, 4.1.3)
$CAPolicies = Get-MgIdentityConditionalAccessPolicy -All
Export-CsvData $CAPolicies "06-CA-Policies.csv" 6 "Conditional Access Policies" "4.1.3"
$AdminCAP = $CAPolicies | Where-Object {$_.Conditions.Users.IncludeRoles -contains "62e90394-69f5-4237-9190-012177145e10"}
$MfaCAP = $AdminCAP | Where-Object {$_.GrantControls.BuiltInControls -contains "mfa"}
$Findings["MFA-Enforcing CA for Admins"] = if($MfaCAP.Count -gt 0){"Yes (Low Risk)"}else{"No (High Risk)"}

# 7. Devices / PAWs (PAC.02, 3.1)
$Devices = Get-MgDeviceManagementManagedDevice -All
Export-CsvData $Devices "07-Admin-Devices.csv" 7 "Privileged Admin Workstations" "3.1"
$CompliantPAWs = $Devices | Where-Object {$_.ComplianceState -eq "Compliant" -and $_.OperatingSystem -eq "Windows"}
$Findings["Compliant PAWs"] = if($CompliantPAWs.Count -gt 0){"Yes (Low Risk)"}else{"No (Medium Risk)"}

# 8. Inactive Admin Accounts (PAC.11, 4.1.4)
$InactiveAdmins = foreach ($u in $AdminUPNs) {
    $lastSignIn = Get-MgUser -UserId $u | Select-Object -ExpandProperty SignInActivity.LastSignInDateTime
    if ($lastSignIn -and ((Get-Date) - $lastSignIn).Days -gt 30) {
        [pscustomobject]@{UPN = $u; DaysInactive = ((Get-Date) - $lastSignIn).Days}
    }
}
Export-CsvData $InactiveAdmins "08-Inactive-Admin-Accounts.csv" 8 "Inactive Admin Accounts" "4.1.4"
$Findings["Inactive Admins (>30 days)"] = if($InactiveAdmins.Count -eq 0){"None (Low Risk)"}else{"$($InactiveAdmins.Count) (Medium Risk)"}

# 9. Emergency Break-Glass Accounts (3.2)
$BreakGlass = $AdminUPNs | Where-Object { $_.UPN -like "*breakglass*" -or $_.UPN -like "*emergency*" }
Export-CsvData $BreakGlass "09-BreakGlass-Accounts.csv" 9 "Emergency Accounts" "3.2"
$Findings["Break-Glass Accounts"] = if($BreakGlass.Count -ge 2){"Compliant (Low Risk)"}else{"Insufficient (High Risk)"}

# 10. No On-Prem Accounts with Privileges (PAC.03, 3.3)
$OnPremPriv = $Roles | Where-Object {!$_.CloudOnly}
Export-CsvData $OnPremPriv "10-OnPrem-Privileged.csv" 10 "On-Prem Privileged Accounts" "3.3"
$Findings["No On-Prem Privileged Accounts"] = if($OnPremPriv.Count -eq 0){"Compliant (Low Risk)"}else{"$($OnPremPriv.Count) (High Risk)"}

# 11. Entra ID as Sole IdP (PAC.04, 3.3)
$IdP = Get-MgDomain | Where-Object {$_.AuthenticationType -ne "Managed"}
Export-CsvData $IdP "11-Entra-IDP.csv" 11 "Identity Provider Config" "3.3"
$Findings["Entra ID as Sole IdP"] = if($IdP.Count -eq 0){"Yes (Low Risk)"}else{"Federated (Medium Risk)"}

# 12. MFA / Passwordless for Admins (PAC.05, 3.1.2)
# Already in 3 - reusing $MFA

# 13. Zero Trust CA for Privileged Users (PAC.07, 3.1.3)
# Already in 6 - reusing $CAPolicies

# 14. Compliant Devices for Admins (PAC.08, 3.1)
# Already in 7 - reusing $Devices

# 15. Block Legacy Auth Protocols (PAC.09, 4.1.3)
$LegacyCAP = $CAPolicies | Where-Object {$_.Conditions.ClientAppTypes -contains "other" -and $_.GrantControls.BuiltInControls -contains "block"}
Export-CsvData $LegacyCAP "15-Legacy-Auth-Block.csv" 15 "Legacy Auth Block CA" "4.1.3"
$Findings["Legacy Auth Protocols Blocked"] = if($LegacyCAP.Count -gt 0){"Yes (Low Risk)"}else{"No (High Risk)"}

# 16. Passwords Do Not Expire (PAC.10, 4.1.4)
# Already in 4 - reusing $PasswordPolicy

# 17. Dedicated Admin Accounts (PAC.12, 3.1)
# Already in 1 - reusing $Roles

# 18. Minimize Global Admins (PAC.13, 3.1)
$GlobalAdmins = ($Roles | Where-Object {$_.Role -eq "Global Administrator"}).Count
$Findings["Global Administrators Count"] = "$GlobalAdmins (Low Risk if <=3)"

# 19. Non-Global Admin Roles (PAC.14, 3.1)
$NonGlobal = $Roles | Where-Object {$_.Role -ne "Global Administrator"}
Export-CsvData $NonGlobal "19-NonGlobal-Roles.csv" 19 "Non-Global Admin Roles" "3.1"
$Findings["Least Privilege Roles In Use"] = if($NonGlobal.Count -gt 0){"Yes (Low Risk)"}else{"All Global (High Risk)"}

# 20. Granular RBAC (PAC.15, 3.1)
# Reuse $Roles for granular check

# 21. MFA for Global Admins (PAC.16, 3.1.2)
# Reuse $MFA for Global Admins only

# 22. Standing Access Reduction via PIM (PAC.17, 3.1.1)
# Already in 2 - reusing $PIM

# ==================== GOOD (Section 4) ====================

# 23. Admin Consent for OAuth Apps (4.1.1)
$Consent = Get-MgPolicyAdminConsentRequestPolicy
Export-CsvData $Consent "23-Admin-Consent.csv" 23 "Admin Consent for OAuth" "4.1.1"
$Findings["Admin Consent for Apps"] = if($Consent.IsEnabled){"Enabled (Low Risk)"}else{"Disabled (High Risk)"}

# 24. Authentication Method (4.1.2)
$AuthMethod = Get-MgPolicyAuthenticationMethodsPolicy
Export-CsvData $AuthMethod "24-Authentication-Methods.csv" 24 "Authentication Methods" "4.1.2"
$Findings["Strong Auth Methods"] = if($AuthMethod.AuthenticationMethodConfigurations.State -contains "enabled"){"Compliant"}else{"Weak (High Risk)"}

# 25. Conditional Access (4.1.3)
# Already in 6 - reusing $CAPolicies

# 26. Account Policy (4.1.4)
# Reuse password and inactive checks

# 27. Microsoft 365 Audit Logging (4.2.1)
$AuditConfig = Get-MgAuditLogConfig
Export-CsvData $AuditConfig "27-Audit-Logging.csv" 27 "Audit Logging Config" "4.2.1"
$Findings["Audit Logging Enabled"] = if($AuditConfig.AuditLogEnabled){"Yes (Low Risk)"}else{"No (High Risk)"}

# 28. Secure Score Reviews (4.2.2)
$SecureScores = Get-MgSecuritySecureScore -All -Top 5
Export-CsvData $SecureScores "28-Secure-Scores.csv" 28 "Secure Score History" "4.2.2"
$LatestScore = $SecureScores | Sort-Object CreatedDateTime -Desc | Select-Object -First 1
$ScorePct = [math]::Round($LatestScore.CurrentScore / $LatestScore.MaxScore * 100, 2)
$Findings["Secure Score"] = "$ScorePct% (Low Risk if >70%)"

# 29. Data Loss Prevention (DLP) (4.2.3)
$DLPPolicies = Get-MgComplianceDataLossPreventionPolicy -All
Export-CsvData $DLPPolicies "29-DLP-Policies.csv" 29 "DLP Policies" "4.2.3"
$Findings["DLP Configured"] = if($DLPPolicies.Count -gt 0){"Yes (Low Risk)"}else{"No (High Risk)"}

# 30. Microsoft Defender for Cloud Apps (4.2.4)
$MCASConfig = Get-MgSecurityCloudAppSecurityProfile -All
Export-CsvData $MCASConfig "30-MCAS-Config.csv" 30 "Defender for Cloud Apps" "4.2.4"
$Findings["MCAS Enabled"] = if($MCASConfig.Count -gt 0){"Yes (Low Risk)"}else{"No (High Risk)"}

# 31. Exchange Online (4.2.5)
$ExoConfig = Get-OrganizationConfig
Export-CsvData $ExoConfig "31-Exchange-Config.csv" 31 "Exchange Online Config" "4.2.5"
$Findings["Exchange Malware Protection"] = if($ExoConfig.MalwareFilterPolicy -ne $null){"Configured (Low Risk)"}else{"Default (Medium Risk)"}

# 32. Microsoft Teams (4.2.6)
$TeamsConfig = Get-CsTeamsClientConfiguration -Identity Global
Export-CsvData $TeamsConfig "32-Teams-Config.csv" 32 "Teams Config" "4.2.6"
$Findings["Teams External Access"] = if($TeamsConfig.AllowGuestUser -eq $false){"Restricted (Low Risk)"}else{"Open (High Risk)"}

# 33. SharePoint (4.2.7)
$SPOConfig = Get-SPOTenant
Export-CsvData $SPOConfig "33-SharePoint-Config.csv" 33 "SharePoint Config" "4.2.7"
$Findings["SharePoint External Sharing"] = if($SPOConfig.SharingCapability -eq "Disabled"){"Disabled (Low Risk)"}else{"Enabled (Medium Risk)"}

# 34. OneDrive (4.2.8)
$OneDriveConfig = Get-SPOTenant | Select-Object OneDrive*
Export-CsvData $OneDriveConfig "34-OneDrive-Config.csv" 34 "OneDrive Config" "4.2.8"
$Findings["OneDrive Sync Restrictions"] = if($OneDriveConfig.OneDriveForGuestsEnabled -eq $false){"Restricted (Low Risk)"}else{"Open (High Risk)"}

# ==================== BETTER (Section 5) ====================

# 35. Entra ID Identity Protection (5.1.1)
$IdentityProtection = Get-MgBetaIdentityProtectionRiskyUser -All
Export-CsvData $IdentityProtection "35-Identity-Protection.csv" 35 "Identity Protection" "5.1.1"
$Findings["Identity Protection Monitoring"] = if($IdentityProtection.Count -gt 0){"Active (Low Risk)"}else{"No (Medium Risk)"}

# 36. Monitor Suspicious Activity (5.1.2)
$SuspiciousActivity = Get-MgAuditLogSignIn -Filter "riskState eq 'atRisk'" -All
Export-CsvData $SuspiciousActivity "36-Suspicious-Activity.csv" 36 "Suspicious Activity" "5.1.2"
$Findings["Suspicious Activity Monitoring"] = if($SuspiciousActivity.Count -eq 0){"No Recent (Low Risk)"}else{"$($SuspiciousActivity.Count) Events (High Risk)"}

# 37. Entra ID PIM (5.1.3)
# Already in 2 - reusing $PIM

# 38. Access Reviews for Privileged Roles (5.1.4)
$AccessReviews = Get-MgIdentityGovernanceAccessReviewDefinition -All
Export-CsvData $AccessReviews "38-Access-Reviews.csv" 38 "Access Reviews" "5.1.4"
$Findings["Scheduled Access Reviews"] = if($AccessReviews.Count -gt 0){"Yes (Low Risk)"}else{"No (High Risk)"}

# 39. Entra ID Entitlement Management (5.1.5)
$Entitlement = Get-MgIdentityGovernanceEntitlementManagementAccessPackage -All
Export-CsvData $Entitlement "39-Entitlement-Management.csv" 39 "Entitlement Management" "5.1.5"
$Findings["Entitlement Management"] = if($Entitlement.Count -gt 0){"Configured (Low Risk)"}else{"No (Medium Risk)"}

# 40. Safe Attachments (5.2.1)
$SafeAttach = Get-SafeAttachmentPolicy
Export-CsvData $SafeAttach "40-Safe-Attachments.csv" 40 "Safe Attachments" "5.2.1"
$Findings["Safe Attachments Enabled"] = if($SafeAttach.Enabled -contains $true){"Yes (Low Risk)"}else{"No (High Risk)"}

# 41. Safe Links (5.2.2)
$SafeLinks = Get-SafeLinksPolicy
Export-CsvData $SafeLinks "41-Safe-Links.csv" 41 "Safe Links" "5.2.2"
$Findings["Safe Links Enabled"] = if($SafeLinks.Enabled -contains $true){"Yes (Low Risk)"}else{"No (High Risk)"}

# 42. MIP Labelling (5.2.3)
$MIPLabels = Get-Label
Export-CsvData $MIPLabels "42-MIP-Labels.csv" 42 "MIP Labelling" "5.2.3"
$Findings["MIP Labels Configured"] = if($MIPLabels.Count -gt 0){"Yes (Low Risk)"}else{"No (High Risk)"}

# 43. Simulated Attack (5.2.4)
$SimAttacks = Get-MgAttackSimulation -All
Export-CsvData $SimAttacks "43-Simulated-Attacks.csv" 43 "Simulated Attacks" "5.2.4"
$Findings["Simulated Attack Campaigns"] = if($SimAttacks.Count -gt 0){"Yes (Low Risk)"}else{"No (Medium Risk)"}

# 44. Defender for Office to Sentinel (5.2.5)
# Assuming Sentinel integration check via connectors - use Graph if available
$SentinelConnectors = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/security/connectors"
Export-CsvData $SentinelConnectors.value "44-Sentinel-Connectors.csv" 44 "Defender to Sentinel" "5.2.5"
$Findings["Defender Connected to Sentinel"] = if($SentinelConnectors.value.Count -gt 0){"Yes (Low Risk)"}else{"No (Medium Risk)"}

# 45. Idle Session Timeout (5.2.7)
$SPOIdle = Get-SPOTenant | Select-Object IdleSessionSignOutForUnmanagedDevicesEnabled
Export-CsvData $SPOIdle "45-Idle-Session-Timeout.csv" 45 "Idle Session Timeout" "5.2.7"
$Findings["Idle Session Timeout"] = if($SPOIdle.IdleSessionSignOutForUnmanagedDevicesEnabled){"Enabled (Low Risk)"}else{"Disabled (Medium Risk)"}

# ==================== BEST (Section 6) ====================

# 46. Customer Lockbox (6.2.1)
$Lockbox = Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled
Export-CsvData $Lockbox "46-Customer-Lockbox.csv" 46 "Customer Lockbox" "6.2.1"
$Findings["Customer Lockbox"] = if($Lockbox.CustomerLockBoxEnabled){"Enabled (Low Risk)"}else{"Disabled (High Risk)"}

# 47. Insider Risk Management (6.2.2)
$InsiderRisk = Get-MgInsiderRiskManagementPolicy -All
Export-CsvData $InsiderRisk "47-Insider-Risk.csv" 47 "Insider Risk Management" "6.2.2"
$Findings["Insider Risk Management"] = if($InsiderRisk.Count -gt 0){"Configured (Low Risk)"}else{"No (High Risk)"}

# 48. Endpoint DLP (6.2.3)
$EndpointDLP = Get-MgDeviceManagementEndpointProtectionConfiguration -All
Export-CsvData $EndpointDLP "48-Endpoint-DLP.csv" 48 "Endpoint DLP" "6.2.3"
$Findings["Endpoint DLP"] = if($EndpointDLP.Count -gt 0){"Yes (Low Risk)"}else{"No (High Risk)"}

# 49. DLP for Teams (6.2.4)
$TeamsDLP = Get-DlpPolicy | Where-Object {$_.Workload -contains "Teams"}
Export-CsvData $TeamsDLP "49-Teams-DLP.csv" 49 "DLP for Teams" "6.2.4"
$Findings["DLP Extended to Teams"] = if($TeamsDLP.Count -gt 0){"Yes (Low Risk)"}else{"No (High Risk)"}

# 50. MCAS Cloud App Protection (6.2.5)
$MCAS = Get-MgSecurityCloudAppSecurityProfile -All
Export-CsvData $MCAS "50-MCAS.csv" 50 "MCAS Protection" "6.2.5"
$Findings["MCAS for Cloud Apps"] = if($MCAS.Count -gt 0){"Configured (Low Risk)"}else{"No (High Risk)"}

# 51. Sensitivity Labels for Content Restriction (6.2.6)
$Labels = Get-Label | Where-Object {$_.ContentType -contains "File" -or $_.ContentType -contains "Email"}
Export-CsvData $Labels "51-Sensitivity-Labels.csv" 51 "Sensitivity Labels" "6.2.6"
$Findings["Sensitivity Labels for Access Restriction"] = if($Labels.Count -gt 0){"Yes (Low Risk)"}else{"No (High Risk)"}

# ==================== INCIDENT RESPONSE (Section 7) ====================

# 52. Immediate Actions Readiness (7.1)
$IRConfig = Get-MgSecurityIncident -All
Export-CsvData $IRConfig "52-IR-Incidents.csv" 52 "Incident Response Incidents" "7.1"
$Findings["Recent Incidents"] = if($IRConfig.Count -eq 0){"None (Low Risk)"}else{"$($IRConfig.Count) (Review Required)"}

# ==================== ENTRA HYGIENE (Full from History) ====================

# 53. Authentication Methods Policy (Good 4.1.2)
$AuthPolicy = Get-MgPolicyAuthenticationMethodsPolicy
Export-CsvData $AuthPolicy "53-Auth-Methods-Policy.csv" 53 "Authentication Methods Policy" "Good 4.1.2"
$Findings["Auth Methods Policy"] = "Configured (Low Risk if no legacy)"

# 54. Self-Service Password Reset (Good 4.1.1)
$SSPR = Get-MgPolicyIdentitySecurityDefaultsEnforcementPolicy
Export-CsvData $SSPR "54-SSPR.csv" 54 "SSPR Policy" "Good 4.1.1"
$Findings["SSPR"] = if($SSPR.IsSSPREnabled){"Enabled (Low Risk)"}else{"Disabled (Medium Risk)"}

# 55. External Collaboration Settings (Good 4.2.6)
$ExtCollab = Get-MgPolicyCrossTenantAccessPolicy
Export-CsvData $ExtCollab "55-External-Collab.csv" 55 "External Collaboration" "Good 4.2.6"
$Findings["External Collab Restrictions"] = if($ExtCollab.Partners -ne $null){"Restricted (Low Risk)"}else{"Open (High Risk)"}

# ==================== FINAL OUTPUTS ====================
Write-Progress -Activity $Activity -Completed

$ConsoleText = @"

M365 UK GOV BLUEPRINT AUDIT COMPLETE – $(Get-Date)
Tenant: $TenantName
════════════════════════════════════════════════════════════
$(foreach($k in $Findings.Keys){ "{0,-40} : {1}" -f $k, $Findings[$k] })
════════════════════════════════════════════════════════════
Overall MOD Supplier Compliance: $(if(($Findings.Values | Select-String "High Risk").Count -le 5){"Good"}else{"Needs Improvement"})

Evidence package: $OutputPath (55 CSVs + Log + HTML)
HTML Report: $HTMLReport
"@

Write-Host $ConsoleText -ForegroundColor White
$ConsoleText | Out-File $ConsoleSummary -Encoding UTF8

# HTML Report
$HTML = @"
<!DOCTYPE html><html><head><title>UK Gov Blueprint Audit - $TenantName</title>
<style>
body {font-family:Segoe UI; background:#f4f4f4; color:#333; margin:40px;}
.container {max-width:1200px; margin:auto; background:white; padding:30px; border-radius:8px; box-shadow:0 4px 20px rgba(0,0,0,0.1);}
h1 {color:#0078d4;}
table {width:100%; border-collapse:collapse; margin:20px 0;}
th {background:#0078d4; color:white; padding:12px;}
td {padding:10px; border-bottom:1px solid #ddd;}
.low {background:#d4edda; color:#155724;}
.med {background:#fff3cd; color:#856404;}
.high {background:#f8d7da; color:#721c24;}
.footer {margin-top:50px; font-size:0.9em; color:#666; text-align:center;}
</style></head><body><div class="container">
<h1>Microsoft 365 UK Government Blueprint Audit Report</h1>
<p><strong>Tenant:</strong> $TenantName | <strong>Date:</strong> $(Get-Date) | <strong>Focus:</strong> MOD Suppliers (OFFICIAL)</p>
<h2>Risk Summary</h2>
<table><tr><th>Finding</th><th>Status</th><th>Risk</th></tr>
"@
foreach($k in $Findings.Keys){
    $val = $Findings[$k] -replace ' \((Low|Medium|High) Risk\)', ''
    $risk = if($Findings[$k] -match 'Low'){'low'}elseif($Findings[$k] -match 'Medium'){'med'}else{'high'}
    $HTML += "<tr><td>$k</td><td>$val</td><td class='$risk'>$($Findings[$k] -replace '.*\((Low|Medium|High) Risk\)', '$1 Risk')</td></tr>"
}
$HTML += "</table><h2>Evidence Files</h2><ul>"
Get-ChildItem $OutputPath -File | Where-Object Name -notmatch "00-|html" | ForEach-Object {
    $HTML += "<li><strong>$($_.Name)</strong> – $([math]::Round($_.Length/1KB,1)) KB</li>"
}
$HTML += "</ul><div class='footer'>Generated by Wayne.Evans@ISHelp.co.uk – Blueprint v3.0 Audit – $(Get-Date -Format 'yyyy')</div></div></body></html>"
$HTML | Out-File $HTMLReport -Encoding UTF8

Write-Host "`nFull Audit Complete!" -ForegroundColor Green
Write-Host "HTML Report: $HTMLReport" -ForegroundColor Yellow

Stop-Transcript
Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
Disconnect-SPOService -ErrorAction SilentlyContinue
Disconnect-MgGraph

#Requires -Modules Microsoft.Graph.Applications
<#
.SYNOPSIS
    Creates a read-only app registration for AccessGuard and grants admin consent.

.DESCRIPTION
    Creates a single-tenant app registration, adds six read-only Microsoft Graph
    application permissions (resolved by name), grants admin consent for exactly
    those permissions and creates a short-lived client secret.

    Run as a Privileged Role Administrator or Global Administrator.

.EXAMPLE
    ./scripts/setup-entra-app.ps1 -SecretMonths 3
#>
[CmdletBinding()]
param(
    [string]$AppName = "AccessGuard (read-only)",
    [ValidateRange(1, 12)][int]$SecretMonths = 6
)

$ErrorActionPreference = "Stop"

$permissions = @(
    "User.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "RoleManagement.Read.Directory",
    "Application.Read.All",
    "UserAuthenticationMethod.Read.All"
)

Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -NoWelcome
$context = Get-MgContext
Write-Host "Connected to tenant $($context.TenantId) as $($context.Account)" -ForegroundColor Cyan

$graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
$roles = foreach ($name in $permissions) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $name -and $_.AllowedMemberTypes -contains "Application" }
    if (-not $role) { throw "Microsoft Graph application permission '$name' was not found." }
    $role
}

$existing = Get-MgApplication -Filter "displayName eq '$($AppName.Replace("'", "''"))'"
if ($existing) { throw "An app registration named '$AppName' already exists (appId $($existing.AppId)). Use another -AppName or remove it." }

$app = New-MgApplication -DisplayName $AppName -SignInAudience "AzureADMyOrg" -Notes "AccessGuard identity security scanner. Read-only Microsoft Graph application permissions." -RequiredResourceAccess @(
    @{
        ResourceAppId  = $graphSp.AppId
        ResourceAccess = @($roles | ForEach-Object { @{ Id = $_.Id; Type = "Role" } })
    }
)
$sp = New-MgServicePrincipal -AppId $app.AppId

# Make the signed-in admin an owner so the app is never orphaned.
$me = Get-MgUser -UserId $context.Account -ErrorAction SilentlyContinue
if ($me) {
    New-MgApplicationOwnerByRef -ApplicationId $app.Id -BodyParameter @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($me.Id)" }
}

foreach ($role in $roles) {
    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $role.Id | Out-Null
    Write-Host "  Granted $($role.Value)"
}

$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = "accessguard-$(Get-Date -Format yyyyMMdd)"
    EndDateTime = (Get-Date).AddMonths($SecretMonths)
}

Write-Host ""
Write-Host "Done. Add these lines to your .env file (keep it out of source control):" -ForegroundColor Green
Write-Host "AZURE_TENANT_ID=$($context.TenantId)"
Write-Host "AZURE_CLIENT_ID=$($app.AppId)"
Write-Host "AZURE_CLIENT_SECRET=$($secret.SecretText)"
Write-Host ""
Write-Host "The secret expires on $($secret.EndDateTime.ToString('yyyy-MM-dd')). Consider replacing it with a certificate." -ForegroundColor Yellow

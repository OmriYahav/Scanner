param(
    [Parameter(Mandatory = $true)][string]$ModuleName
)

$ErrorActionPreference = 'Stop'

if (-not (Get-PackageProvider -Name NuGet -ListAvailable)) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
}

Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
"OK"

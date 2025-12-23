param(
    [Parameter(Mandatory = $true)][string]$ModuleName
)

$ErrorActionPreference = 'Stop'

# Ensure modern TLS is enabled for PowerShell Gallery downloads. Older
# environments may default to TLS 1.0/1.1 which are rejected by the
# gallery endpoints and produce trust errors during module installation.
try {
    $currentProtocols = [System.Net.ServicePointManager]::SecurityProtocol
    $desiredProtocols = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
    [System.Net.ServicePointManager]::SecurityProtocol = $currentProtocols -bor $desiredProtocols
}
catch {
    Write-Warning "Unable to force TLS 1.2/1.3 for module installation: $($_.Exception.Message)"
}

function Ensure-NuGetProvider {
    $nuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
    if ($nuget) {
        return $true
    }

    try {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -ForceBootstrap -Scope CurrentUser -ErrorAction Stop | Out-Null
        $nuget = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
        return [bool]$nuget
    }
    catch {
        Write-Warning "NuGet provider installation failed: $($_.Exception.Message)"
        return $false
    }
}

if (-not (Ensure-NuGetProvider)) {
    Write-Error "Unable to install NuGet package provider required for module installation"
    exit 1
}

Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber
"OK"

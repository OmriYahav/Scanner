param(
    [string]$ModuleName = 'PSDiscoveryProtocol'
)

$module = Get-Module -ListAvailable $ModuleName
if ($module) {
    Write-Output "True"
    exit 0
}

Write-Output "False"
exit 1

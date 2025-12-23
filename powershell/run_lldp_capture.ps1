param(
    [Parameter(Mandatory = $true)][int]$DurationSeconds,
    [string]$InterfaceNameOrAlias
)

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$duration = $DurationSeconds
$result = [ordered]@{
    module_imported = $false
    cmdlet_available = $false
    cmdlet_used = 'Invoke-DiscoveryProtocolCapture'
    neighbors = @()
    error_type = $null
    error_message = $null
    failed_stage = $null
}

try {
    Import-Module PSDiscoveryProtocol -ErrorAction Stop
    $result.module_imported = $true
} catch {
    $result.error_type = 'ModuleError'
    $result.error_message = "PSDiscoveryProtocol module missing: $($_.Exception.Message)"
    $result.failed_stage = 'ImportModule'
    $result | ConvertTo-Json -Depth 8
    exit 1
}

try {
    $null = Get-Command Invoke-DiscoveryProtocolCapture -ErrorAction Stop
    $result.cmdlet_available = $true
} catch {
    $result.error_type = 'ModuleError'
    $result.error_message = "Invoke-DiscoveryProtocolCapture unavailable: $($_.Exception.Message)"
    $result.failed_stage = 'ValidateCmdlet'
    $result | ConvertTo-Json -Depth 8
    exit 1
}

try {
    if ([string]::IsNullOrWhiteSpace($InterfaceNameOrAlias)) {
        $capture = Invoke-DiscoveryProtocolCapture -Type LLDP -Force -Duration $duration
    } else {
        $capture = Invoke-DiscoveryProtocolCapture -Type LLDP -Force -Duration $duration -InterfaceAlias $InterfaceNameOrAlias
    }
    $data = $capture | Get-DiscoveryProtocolData
} catch {
    $result.error_type = 'ParameterError'
    $result.error_message = $_.Exception.Message
    $result.failed_stage = 'Capture'
}

if ($result.error_type) {
    $result | ConvertTo-Json -Depth 8
    exit 1
}

if ($null -eq $data) { $data = @() }
$result.neighbors = $data | ForEach-Object {
    [pscustomobject]@{
        ChassisId = $_.ChassisId
        PortId = $_.PortId
        SystemName = $_.SystemName
        PortDescription = $_.PortDescription
        ManagementAddress = $_.ManagementAddress
        Vlans = $_.Vlans
        VlanIds = $_.VlanIds
        Interface = $_.Interface
        InterfaceAlias = $_.InterfaceAlias
    }
}
$result | ConvertTo-Json -Depth 8

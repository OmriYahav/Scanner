param (
    [int]$DurationSeconds = 30
)

function Write-Log {
    param([string]$Message)
    [Console]::Error.WriteLine($Message)
}

$payload = @{
    module_imported = $false
    cmdlet_available = $false
    cmdlet_used = $null
    error_type = $null
    failed_stage = $null
    error_message = $null
    neighbors = @()
}

try {
    Import-Module PSDiscoveryProtocol -ErrorAction Stop
    $payload.module_imported = $true
}
catch {
    Write-Log "LLDP module import failed: $($_.Exception.Message)"
    $payload.error_type = "ModuleError"
    $payload.failed_stage = "ImportModule"
    $payload.error_message = $_.Exception.Message
    $payload | ConvertTo-Json -Depth 6
    exit 0
}

$cmdlet = Get-Command Invoke-DiscoveryProtocolCapture -ErrorAction SilentlyContinue
$payload.cmdlet_available = [bool]$cmdlet
if (-not $payload.cmdlet_available) {
    Write-Log "Invoke-DiscoveryProtocolCapture not available"
    $payload.error_type = "ModuleError"
    $payload.failed_stage = "GetCommand"
    $payload.error_message = "Invoke-DiscoveryProtocolCapture not available"
    $payload | ConvertTo-Json -Depth 6
    exit 0
}

$captureParams = @{
    Type = 'LLDP'
    Force = $true
    Duration = $DurationSeconds
}

$payload.cmdlet_used = "Invoke-DiscoveryProtocolCapture"

try {
    $data = Invoke-DiscoveryProtocolCapture @captureParams |
        Get-DiscoveryProtocolData
}
catch {
    $exception = $_.Exception
    $payload.failed_stage = "Capture"
    $payload.error_message = $exception.Message

    if ($exception -is [System.Management.Automation.ParameterBindingException]) {
        Write-Log "LLDP capture failed due to parameter error: $($exception.Message)"
        $payload.error_type = "ParameterError"
    }
    else {
        Write-Log "LLDP capture failed: $($exception.Message)"
        $payload.error_type = "CaptureError"
    }

    $payload | ConvertTo-Json -Depth 6
    exit 0
}

if (-not $data) {
    Write-Log "LLDP capture completed with no neighbors detected"
    $payload.error_type = "NoNeighbors"
    $payload.error_message = "No LLDP neighbors detected"
    $payload.neighbors = @()
    $payload | ConvertTo-Json -Depth 6
    exit 0
}

$neighbors = @()

foreach ($item in $data) {
    $ipAddresses = @()
    if ($item.IPAddresses) {
        $ipAddresses = @($item.IPAddresses)
    }

    $managementAddress = $null
    if ($ipAddresses.Count -gt 0) {
        $managementAddress = $ipAddresses[0]
    }
    elseif ($item.ManagementAddress) {
        $managementAddress = $item.ManagementAddress
    }

    $portId = $item.Port
    if (-not $portId -and $item.PortId) {
        $portId = $item.PortId
    }

    $systemName = $item.ComputerName
    if (-not $systemName -and $item.SystemName) {
        $systemName = $item.SystemName
    }

    $neighbors += [pscustomobject]@{
        chassis_id         = $item.ChassisId
        port_id            = $portId
        system_name        = $systemName
        port_description   = $item.PortDescription
        system_description = $item.SystemDescription
        management_address = $managementAddress
        ttl                = $item.TimeToLive
        connection         = $item.Connection
        interface          = $item.Interface
    }
}

$payload.neighbors = $neighbors
$payload | ConvertTo-Json -Depth 6

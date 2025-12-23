param (
    [int]$DurationSeconds = 30
)

Import-Module PSDiscoveryProtocol -ErrorAction Stop

if (-not (Get-Command Invoke-DiscoveryProtocolCapture -ErrorAction SilentlyContinue)) {
    throw "Invoke-DiscoveryProtocolCapture not available"
}

$result = Invoke-DiscoveryProtocolCapture `
            -Type LLDP `
            -Force `
            -Duration $DurationSeconds

$data = $result | Get-DiscoveryProtocolData

if (-not $data) {
    Write-Output (@{
        status = "NoNeighbors"
    } | ConvertTo-Json)
    exit 0
}

$data | ForEach-Object {
    [pscustomobject]@{
        ChassisId         = $_.ChassisId
        PortId            = $_.PortId
        SystemName        = $_.SystemName
        PortDescription   = $_.PortDescription
        ManagementAddress = $_.ManagementAddress
        Vlans             = $_.Vlans
    }
} | ConvertTo-Json -Depth 6

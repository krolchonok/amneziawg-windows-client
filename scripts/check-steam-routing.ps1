param(
    [int]$Seconds = 10
)

$ErrorActionPreference = "Stop"

function Get-SteamPids {
    $names = @("steam", "steamwebhelper")
    $procs = Get-Process -Name $names -ErrorAction SilentlyContinue
    if (-not $procs) {
        return @()
    }
    return @($procs | Select-Object -ExpandProperty Id)
}

function Get-InterfaceDelta {
    param(
        [string[]]$Names,
        [int]$DelaySeconds
    )

    $before = Get-NetAdapterStatistics -Name $Names
    Start-Sleep -Seconds $DelaySeconds
    $after = Get-NetAdapterStatistics -Name $Names

    return $before | ForEach-Object {
        $name = $_.Name
        $a = $after | Where-Object Name -eq $name
        [pscustomobject]@{
            Name           = $name
            RxDeltaMB      = [math]::Round(($a.ReceivedBytes - $_.ReceivedBytes) / 1MB, 2)
            TxDeltaMB      = [math]::Round(($a.SentBytes - $_.SentBytes) / 1MB, 2)
            RxPacketsDelta = $a.ReceivedUnicastPackets - $_.ReceivedUnicastPackets
            TxPacketsDelta = $a.SentUnicastPackets - $_.SentUnicastPackets
        }
    }
}

function Get-SteamConnections {
    param(
        [int[]]$Pids
    )

    if (-not $Pids -or $Pids.Count -eq 0) {
        return @()
    }

    return Get-NetTCPConnection -State Established |
        Where-Object { $_.OwningProcess -in $Pids } |
        Sort-Object OwningProcess, RemoteAddress |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
}

Write-Host "Sampling interface traffic for $Seconds seconds..." -ForegroundColor Cyan
$delta = Get-InterfaceDelta -Names @("Ethernet", "all") -DelaySeconds $Seconds

$steamPids = Get-SteamPids
$connections = Get-SteamConnections -Pids $steamPids

Write-Host ""
Write-Host "Interface delta:" -ForegroundColor Green
$delta | Format-Table -AutoSize

Write-Host ""
Write-Host "Steam PIDs:" -ForegroundColor Green
if ($steamPids.Count -eq 0) {
    Write-Host "No running steam processes found."
} else {
    $steamPids | ForEach-Object { Write-Host $_ }
}

Write-Host ""
Write-Host "Steam established TCP connections:" -ForegroundColor Green
if (-not $connections -or $connections.Count -eq 0) {
    Write-Host "No established Steam TCP connections found."
} else {
    $connections | Format-Table -AutoSize
}

Write-Host ""
Write-Host "Current routes on interface 'all':" -ForegroundColor Green
Get-NetRoute -AddressFamily IPv4 |
    Where-Object { $_.InterfaceAlias -eq "all" } |
    Sort-Object DestinationPrefix |
    Format-Table ifIndex, InterfaceAlias, DestinationPrefix, NextHop, RouteMetric -AutoSize

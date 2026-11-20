# Real localhost TCP SYN-style port scan demo.
# Run with the SIEM-l network collector active.
param(
    [string]$Target = "127.0.0.1",
    [int[]]$Ports = @(22, 80, 135, 443, 445, 3389, 8080, 8081, 8082)
)

Write-Host "Scanning $Target across $($Ports.Count) ports"
foreach ($port in $Ports) {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $task = $client.ConnectAsync($Target, $port)
        if (-not $task.Wait(150)) {
            Write-Host "[$port] timed out"
        } elseif ($client.Connected) {
            Write-Host "[$port] open"
        } else {
            Write-Host "[$port] closed"
        }
    } catch {
        Write-Host "[$port] closed"
    } finally {
        $client.Dispose()
    }
    Start-Sleep -Milliseconds 100
}

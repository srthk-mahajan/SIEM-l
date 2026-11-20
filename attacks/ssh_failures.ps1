# Real SSH failure demo. Requires a reachable Windows/Linux SSH service.
param(
    [string]$Target = "127.0.0.1",
    [string]$Account = "siem_demo_invalid",
    [int]$Attempts = 6
)

if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
    throw "OpenSSH client is not installed or ssh.exe is not on PATH."
}

for ($i = 1; $i -le $Attempts; $i++) {
    Write-Host "Failed SSH attempt $i"
    & ssh.exe `
        -o ConnectTimeout=2 `
        -o PreferredAuthentications=password `
        -o PubkeyAuthentication=no `
        -o StrictHostKeyChecking=no `
        "$Account@$Target" "exit" 2>$null
    Start-Sleep -Milliseconds 500
}

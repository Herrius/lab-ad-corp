# join-domain.ps1
# Une WS01 al dominio corp.local y aplica hardening de workstation
# Ejecutar manualmente después de que el DC esté completamente configurado:
#   vagrant provision ws01 --provision-with join-domain

# Configurar DNS al DC
Write-Host "[*] Configurando DNS hacia el DC (192.168.56.100)..."
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } |
    Where-Object { $_.Name -notlike "*Loopback*" } |
    Select-Object -Last 1
Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses "192.168.56.100"

# Verificar conectividad con el DC
Write-Host "[*] Verificando conectividad con el DC..."
$ping = Test-Connection -ComputerName "192.168.56.100" -Count 2 -Quiet
if (-not $ping) {
    Write-Error "No se puede alcanzar el DC en 192.168.56.100. ¿Está levantado?"
    exit 1
}

# Verificar resolución DNS de corp.local
$resolve = Resolve-DnsName -Name "corp.local" -ErrorAction SilentlyContinue
if (-not $resolve) {
    Write-Error "No se puede resolver corp.local. Verificar DNS."
    exit 1
}

Write-Host "[*] Uniendo WS01 al dominio corp.local..."
$credential = New-Object System.Management.Automation.PSCredential(
    "CORP\vagrant",
    (ConvertTo-SecureString "vagrant" -AsPlainText -Force)
)
Add-Computer -DomainName "corp.local" -Credential $credential -Force

# =============================================================================
# HARDENING DE WORKSTATION
# Consistente con el hardening del DC
# =============================================================================

Write-Host "[*] Aplicando hardening de workstation..."

# LLMNR deshabilitado
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWORD

# NetBIOS deshabilitado
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($a in $adapters) {
    $a.SetTcpipNetbios(2) | Out-Null
}

# SMB signing requerido en cliente
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force

# WDigest deshabilitado
$wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $wdigestPath)) { New-Item -Path $wdigestPath -Force | Out-Null }
Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 0 -Type DWORD

Write-Host "[+] WS01 configurado y unido a corp.local. Reiniciando..."
Restart-Computer -Force

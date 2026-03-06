# install-ad.ps1
# Instala AD DS y promueve la máquina a Domain Controller
# Idempotente: verifica si ya es DC antes de instalar

# Verificar si ya es DC (DomainRole >= 4 significa DC)
if ((Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4) {
    Write-Host "[*] Ya es Domain Controller. Saltando instalación."
    exit 0
}

Write-Host "[*] Configurando DNS del adaptador privado..."
$adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } |
    Where-Object { $_.Name -notlike "*Loopback*" } |
    Select-Object -Last 1
if ($adapter) {
    Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses "127.0.0.1"
}

Write-Host "[*] Instalando rol AD-Domain-Services..."
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Write-Host "[*] Promoviendo a Domain Controller (corp.local)..."
Import-Module ADDSDeployment
Install-ADDSForest `
    -DomainName "corp.local" `
    -DomainNetbiosName "CORP" `
    -SafeModeAdministratorPassword (ConvertTo-SecureString "Admin123!" -AsPlainText -Force) `
    -InstallDns:$true `
    -NoRebootOnCompletion:$true `
    -Force:$true

Write-Host "[*] Instalación completada. El sistema reiniciará para aplicar cambios."

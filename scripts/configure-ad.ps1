#Requires -RunAsAdministrator

# ====================================================================
# configure-ad.ps1 - Configura el dominio corp.local para el lab AD
# Attack chain: LDAP anonimo -> j.smith:Welcome1 -> Kerberoast svc_backup -> Password1 -> Domain Admin
# ====================================================================

$dc = $env:COMPUTERNAME

# --- Fix IP duplicada en Ethernet 2 (VirtualBox ARP race condition) ---
$adapter2 = Get-NetAdapter | Where-Object { $_.Name -eq "Ethernet 2" } | Select-Object -First 1
if ($adapter2) {
    $ipInfo = Get-NetIPAddress -InterfaceIndex $adapter2.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -eq "192.168.56.100" }
    if ($ipInfo -and $ipInfo.AddressState -eq "Duplicate") {
        Write-Host "[*] Corrigiendo IP duplicada en Ethernet 2..."
        $ipInfo | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        New-NetIPAddress -InterfaceIndex $adapter2.InterfaceIndex `
            -IPAddress "192.168.56.100" -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Seconds 3
        Write-Host "[*] IP restaurada: 192.168.56.100"
    }
}

# --- Esperar NTDS + ADWS ---
Write-Host "[*] Esperando servicios de AD (NTDS + ADWS)..."
$timeout = 600; $elapsed = 0
while ($elapsed -lt $timeout) {
    $ntds = (Get-Service -Name "NTDS"  -ErrorAction SilentlyContinue).Status
    $adws = (Get-Service -Name "ADWS"  -ErrorAction SilentlyContinue).Status
    Write-Host "    [$elapsed s] NTDS=$ntds ADWS=$adws"
    if ($ntds -eq "Running" -and $adws -eq "Running") { break }
    Start-Sleep -Seconds 15; $elapsed += 15
}
if ($elapsed -ge $timeout) { Write-Host "[-] TIMEOUT esperando AD"; exit 1 }

Write-Host "[*] Servicios Running. Esperando inicializacion interna de ADWS (60s)..."
Start-Sleep -Seconds 60

# --- Verificar que AD responde ---
Write-Host "[*] Verificando Get-ADDomain -Server $dc..."
$retries = 0
while ($retries -lt 12) {
    try {
        $null = Get-ADDomain -Server $dc -ErrorAction Stop
        Write-Host "[*] AD disponible. Servidor: $dc"
        break
    } catch { $retries++; Start-Sleep -Seconds 15 }
}
if ($retries -ge 12) { Write-Host "[-] AD no disponible tras espera"; exit 1 }

# --- Crear usuarios de dominio ---
Write-Host "[*] Creando usuarios de dominio..."

# j.smith: punto de entrada via LDAP anonimo (password en descripcion)
New-ADUser `
    -Name "John Smith" `
    -SamAccountName "j.smith" `
    -UserPrincipalName "j.smith@corp.local" `
    -Description "Temp password: Welcome1" `
    -AccountPassword (ConvertTo-SecureString "Welcome1" -AsPlainText -Force) `
    -Enabled $true `
    -Server $dc `
    -ErrorAction SilentlyContinue

# svc_backup: Domain Admin + SPN (Kerberoastable) -> objetivo del ataque
New-ADUser `
    -Name "Backup Service" `
    -SamAccountName "svc_backup" `
    -UserPrincipalName "svc_backup@corp.local" `
    -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) `
    -Enabled $true `
    -Server $dc `
    -ErrorAction SilentlyContinue

Add-ADGroupMember -Identity "Domain Admins" -Members "svc_backup" `
    -Server $dc -ErrorAction SilentlyContinue
Set-ADUser -Identity "svc_backup" `
    -Add @{servicePrincipalName = "backup/dc.corp.local"} `
    -Server $dc -ErrorAction SilentlyContinue

# m.jones: usuario regular
New-ADUser `
    -Name "Mark Jones" `
    -SamAccountName "m.jones" `
    -UserPrincipalName "m.jones@corp.local" `
    -AccountPassword (ConvertTo-SecureString "Summer2023!" -AsPlainText -Force) `
    -Enabled $true `
    -Server $dc `
    -ErrorAction SilentlyContinue

# l.garcia: usuario regular
New-ADUser `
    -Name "Laura Garcia" `
    -SamAccountName "l.garcia" `
    -UserPrincipalName "l.garcia@corp.local" `
    -AccountPassword (ConvertTo-SecureString "Autumn2023!" -AsPlainText -Force) `
    -Enabled $true `
    -Server $dc `
    -ErrorAction SilentlyContinue

# --- Habilitar LDAP anonimo via dsHeuristics (scheduled task como SYSTEM) ---
Write-Host "[*] Habilitando LDAP anonimo..."
$configNC = (Get-ADRootDSE -Server $dc).configurationNamingContext
$dshScript = "Import-Module ActiveDirectory; " +
    "Set-ADObject -Identity 'CN=Directory Service,CN=Windows NT,CN=Services,$configNC' " +
    "-Replace @{dsHeuristics='0000002'} -Server $dc"
$action   = New-ScheduledTaskAction -Execute "powershell.exe" `
              -Argument "-NonInteractive -Command `"$dshScript`""
$trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName "SetDsHeuristics" -Action $action `
    -Trigger $trigger -Settings $settings -RunLevel Highest -User "SYSTEM" -Force | Out-Null
Start-Sleep -Seconds 25
Unregister-ScheduledTask -TaskName "SetDsHeuristics" -Confirm:$false -ErrorAction SilentlyContinue

# ACL: permitir lectura anonima en DC=corp,DC=local
$domain   = [ADSI]"LDAP://localhost/DC=corp,DC=local"
$everyone = [System.Security.Principal.SecurityIdentifier]"S-1-1-0"
$adRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead
$aType    = [System.Security.AccessControl.AccessControlType]::Allow
$inherit  = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
$rule     = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $everyone, $adRights, $aType, $inherit)
$domain.psbase.ObjectSecurity.AddAccessRule($rule)
$domain.psbase.CommitChanges()

# --- Aplicar hardening (10 medidas) ---
Write-Host "[*] Aplicando hardening (10 medidas)..."

# 1+2. Password policy + lockout (parametros correctos)
Set-ADDefaultDomainPasswordPolicy -Identity "corp.local" `
    -MinPasswordLength 12 `
    -MaxPasswordAge (New-TimeSpan -Days 90) `
    -MinPasswordAge (New-TimeSpan -Days 1) `
    -PasswordHistoryCount 24 `
    -ComplexityEnabled $true `
    -Server $dc -ErrorAction SilentlyContinue

Set-ADDefaultDomainPasswordPolicy -Identity "corp.local" `
    -LockoutThreshold 5 `
    -LockoutDuration (New-TimeSpan -Minutes 30) `
    -LockoutObservationWindow (New-TimeSpan -Minutes 30) `
    -Server $dc -ErrorAction SilentlyContinue

# 3. Deshabilitar AS-REP roasting en todas las cuentas
Get-ADUser -Filter * -Server $dc -ErrorAction SilentlyContinue | ForEach-Object {
    Set-ADAccountControl -Identity $_ -DoesNotRequirePreAuth $false `
        -Server $dc -ErrorAction SilentlyContinue
}
Get-ADComputer -Filter * -Server $dc -ErrorAction SilentlyContinue | ForEach-Object {
    Set-ADAccountControl -Identity $_ -DoesNotRequirePreAuth $false `
        -Server $dc -ErrorAction SilentlyContinue
}

# 4. Deshabilitar LLMNR
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f 2>&1 | Out-Null

# 5. Deshabilitar NetBIOS sobre TCP/IP
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object {
    $_.SetTcpipNetbios(2) | Out-Null
}

# 6. Deshabilitar WPAD
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" /v WpadOverride /t REG_DWORD /d 1 /f 2>&1 | Out-Null

# 7. Habilitar SMB signing (previene relay attacks)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
    -Name RequireSecuritySignature -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
    -Name EnableSecuritySignature -Value 1 -ErrorAction SilentlyContinue

# 8. Restringir acceso anonimo a SAM/shares (excepto LDAP que va por dsHeuristics)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name RestrictAnonymous -Value 1 -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name RestrictAnonymousSAM -Value 1 -ErrorAction SilentlyContinue

# 9. No almacenar hash LM
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name NoLmHash -Value 1 -ErrorAction SilentlyContinue

# 10. Auditorias de logon y gestion de cuentas
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable 2>&1 | Out-Null
auditpol /set /category:"Account Management" /success:enable /failure:enable 2>&1 | Out-Null

# --- Crear share y flags ---
Write-Host "[*] Creando flags..."

New-Item -ItemType Directory -Path "C:\Shares\Internal" -Force -ErrorAction SilentlyContinue | Out-Null
New-SmbShare -Name "Internal" -Path "C:\Shares\Internal" `
    -ChangeAccess "Domain Users" -ReadAccess "Everyone" -ErrorAction SilentlyContinue | Out-Null
Set-Content -Path "C:\Shares\Internal\flag_user.txt" `
    -Value "FLAG{ldap_anon_enum_j_smith_Welcome1}" -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Path "C:\Users\Administrator\Desktop" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Content -Path "C:\Users\Administrator\Desktop\flag.txt" `
    -Value "FLAG{domain_admin_via_kerberoast_svc_backup}" -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[+] Configuracion completada."
Write-Host "[+] Attack chain: ldapsearch anonimo -> j.smith:Welcome1 -> kerberoast svc_backup -> Password1 -> Domain Admin"

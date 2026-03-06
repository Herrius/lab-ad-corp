# configure-ad.ps1
# Configura usuarios, LDAP anónimo, hardening y flags del laboratorio
#
# Attack chain intencionado:
#   LDAP anónimo -> j.smith:Welcome1 (campo Description)
#   -> Kerberoasting svc_backup -> hash TGS
#   -> hashcat rockyou.txt -> Password1
#   -> psexec como Domain Admin -> flags

Import-Module ActiveDirectory
Start-Sleep -Seconds 10  # Esperar a que AD esté completamente disponible

# =============================================================================
# USUARIOS
# =============================================================================

Write-Host "[*] Creando usuarios de dominio..."

# j.smith: usuario regular. Password en Description para LDAP anónimo (breadcrumb intencional)
New-ADUser `
    -Name "John Smith" `
    -SamAccountName "j.smith" `
    -UserPrincipalName "j.smith@corp.local" `
    -AccountPassword (ConvertTo-SecureString "Welcome1" -AsPlainText -Force) `
    -Description "Temp password: Welcome1" `
    -Enabled $true `
    -PasswordNeverExpires $true

# svc_backup: cuenta de servicio, Domain Admin, SPN registrado (objetivo del Kerberoasting)
New-ADUser `
    -Name "Backup Service" `
    -SamAccountName "svc_backup" `
    -UserPrincipalName "svc_backup@corp.local" `
    -AccountPassword (ConvertTo-SecureString "Password1" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true

Add-ADGroupMember -Identity "Domain Admins" -Members "svc_backup"
Set-ADUser -Identity "svc_backup" -Add @{servicePrincipalName = "backup/dc01.corp.local"}

# m.jones y l.garcia: usuarios con passwords fuertes, no atacables en este lab
New-ADUser `
    -Name "Mark Jones" `
    -SamAccountName "m.jones" `
    -UserPrincipalName "m.jones@corp.local" `
    -AccountPassword (ConvertTo-SecureString "K#9mP@2xLq5!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true

New-ADUser `
    -Name "Laura Garcia" `
    -SamAccountName "l.garcia" `
    -UserPrincipalName "l.garcia@corp.local" `
    -AccountPassword (ConvertTo-SecureString "X`$7nR@4wYt8!" -AsPlainText -Force) `
    -Enabled $true `
    -PasswordNeverExpires $true

# =============================================================================
# LDAP ANÓNIMO (vulnerabilidad intencionada)
# LDAP (389) es independiente de SMB (445): SMB signing no bloquea esto
# =============================================================================

Write-Host "[*] Habilitando LDAP anónimo..."

# dsHeuristics = "0000002" habilita operaciones LDAP anónimas
$dse = [ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local"
$dse.dsHeuristics = "0000002"
$dse.CommitChanges()

# ACL: ANONYMOUS LOGON con GenericRead en la raíz del dominio
$domain = [ADSI]"LDAP://DC=corp,DC=local"
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    [System.Security.Principal.NTAccount]"ANONYMOUS LOGON",
    [System.DirectoryServices.ActiveDirectoryRights]"GenericRead",
    [System.Security.AccessControl.AccessControlType]"Allow"
)
$domain.ObjectSecurity.AddAccessRule($rule)
$domain.CommitChanges()

# =============================================================================
# HARDENING (10 vectores bloqueados deliberadamente)
# Solo existe UNA ruta de explotación: LDAP anónimo -> Kerberoasting
# =============================================================================

Write-Host "[*] Aplicando hardening (10 medidas)..."

# 1. Kerberos pre-auth obligatorio para todos (bloquea AS-REP Roasting)
Get-ADUser -Filter * | Set-ADAccountControl -DoesNotRequirePreAuth $false

# 2. Account lockout: 5 intentos / 30 min (impide brute force)
Set-ADDefaultDomainPasswordPolicy -Identity "corp.local" `
    -LockoutBadCount 5 `
    -LockoutDuration "00:30:00" `
    -LockoutObservationWindow "00:30:00"

# 3. SMB signing requerido (bloquea NTLM Relay)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# 4. LLMNR deshabilitado (bloquea LLMNR Poisoning)
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWORD

# 5. NBT-NS deshabilitado (bloquea NBT-NS Poisoning)
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS over TCP/IP
}

# 6. SMBv1 deshabilitado (bloquea EternalBlue)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# 7. Print Spooler deshabilitado (bloquea PrintNightmare)
Stop-Service -Name "Spooler" -Force -ErrorAction SilentlyContinue
Set-Service -Name "Spooler" -StartupType Disabled

# 8. WDigest deshabilitado (sin creds en texto plano en LSASS)
$wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $wdigestPath)) { New-Item -Path $wdigestPath -Force | Out-Null }
Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 0 -Type DWORD

# 9. LSA Protection - RunAsPPL (dificulta credential dumping)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWORD

# 10. Delegation deshabilitada en todas las cuentas (bloquea delegation abuse)
Get-ADUser -Filter * | Set-ADAccountControl -AccountNotDelegated $true
Get-ADComputer -Filter * | Set-ADAccountControl -AccountNotDelegated $true

# =============================================================================
# FLAGS
# =============================================================================

Write-Host "[*] Creando flags..."

# User flag: accesible por cualquier Domain User (se llega con j.smith)
New-Item -ItemType Directory -Path "C:\Shares\Internal" -Force | Out-Null
Set-Content -Path "C:\Shares\Internal\user_flag.txt" -Value "FLAG{ldap_anon_kerberoast_success}"
New-SmbShare -Name "Internal" -Path "C:\Shares\Internal" -FullAccess "Domain Users" -ErrorAction SilentlyContinue

# Root flag: requiere acceso como Administrator (se llega via psexec con svc_backup)
Set-Content -Path "C:\Users\Administrator\Desktop\flag.txt" -Value "FLAG{ad_lab_domain_admin}"

Write-Host ""
Write-Host "[+] Configuración completada."
Write-Host "[+] Attack chain: ldapsearch anonimo -> j.smith:Welcome1 -> kerberoast svc_backup -> Password1 -> Domain Admin"

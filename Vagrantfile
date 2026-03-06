# Proyecto 4.1: Dominio Windows Básico (Single Attack Path)
# Dominio: corp.local
# Attack chain: LDAP anónimo → Kerberoasting → Domain Admin
#
# Requisito: vagrant plugin install vagrant-reload
#
# Despliegue:
#   vagrant up dc                                          # Instala AD + configura
#   vagrant up ws01                                        # Arranca Windows 10
#   vagrant provision ws01 --provision-with join-domain     # Une al dominio

Vagrant.configure("2") do |config|

  # === ATACANTE: Kali (opcional, arrancar con: vagrant up kali) ===
  config.vm.define "kali", autostart: false do |kali|
    kali.vm.box = "kalilinux/rolling"
    kali.vm.hostname = "kali"
    kali.vm.network "private_network", ip: "192.168.56.10"
    kali.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
      vb.cpus = 2
      vb.name = "AD-Lab-Kali"
    end
  end

  # === DC: Windows Server 2019 ===
  config.vm.define "dc" do |dc|
    dc.vm.box = "gusztavvargadr/windows-server-2019-standard"
    dc.vm.network "private_network", ip: "192.168.56.100"
    dc.vm.communicator = "winrm"
    dc.vm.guest = :windows
    dc.vm.boot_timeout = 900
    dc.winrm.transport = :plaintext
    dc.winrm.basic_auth_only = true
    dc.winrm.retry_limit = 60
    dc.winrm.retry_delay = 10

    dc.vm.provider "virtualbox" do |vb|
      vb.memory = "4096"
      vb.cpus = 2
      vb.name = "AD-Lab-DC01"
    end

    # Fase 1: Instalar AD y promover a DC
    dc.vm.provision "install-ad", type: "shell", path: "scripts/install-ad.ps1"

    # Reboot automático post-promoción (requiere vagrant-reload plugin)
    dc.vm.provision :reload

    # Fase 2: Crear usuarios, hardening, flags
    dc.vm.provision "configure-ad", type: "shell", path: "scripts/configure-ad.ps1"
  end

  # === WS01: Windows 10 Workstation ===
  config.vm.define "ws01" do |ws|
    ws.vm.box = "gusztavvargadr/windows-10"
    ws.vm.network "private_network", ip: "192.168.56.101"
    ws.vm.communicator = "winrm"
    ws.vm.guest = :windows
    ws.vm.boot_timeout = 900
    ws.winrm.transport = :negotiate
    ws.winrm.retry_limit = 60
    ws.winrm.retry_delay = 10

    ws.vm.provider "virtualbox" do |vb|
      vb.memory = "2048"
      vb.cpus = 2
      vb.name = "AD-Lab-WS01"
    end

    # Unir al dominio (ejecutar manualmente después de que DC esté listo)
    ws.vm.provision "join-domain", type: "shell", path: "scripts/join-domain.ps1", run: "never"
  end

end

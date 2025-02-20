# Multi-Hysteria-Installer para Ubuntu 20.04 y superiores

Este script instala Hysteria en sistemas Ubuntu AMD64. Actualmente, no soporta otras distribuciones ni arquitecturas.

## Requisitos

Antes de ejecutar el script, asegúrate de tener los siguientes paquetes instalados:

```bash
sudo apt -y -q install curl wget openssl  iptables-persistent
```

## Instalación de Hysteria

Clona el repositorio y cambia al directorio del proyecto:

```bash
git clone https://github.com/staffnetDev/Multi-Hysteria-Installer.git
cd Multi-Hysteria-Installer-
```

Otorga permisos de ejecución al script de instalación y ejecútalo:

```bash
chmod +x install.sh
bash install_final
```

Este script instalará y configurará Hysteria, incluyendo la persistencia de las reglas de `iptables`.


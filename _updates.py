# -*- coding: utf-8 -*-
"""
PANTER JBOSS - Update Manager
Analyst : Apo1o13
Build   : 2026-04-30 - Custom Edition
"""

RED = '\x1b[91m'
RED1 = '\033[31m'
BLUE = '\033[94m'
GREEN = '\033[32m'
BOLD = '\033[1m'
NORMAL = '\033[0m'
ENDC = '\033[0m'

import panterjboss as panter
from sys import version_info
import os
import shutil
from zipfile import ZipFile
import traceback
import logging, datetime
logging.captureWarnings(True)
FORMAT = "%(asctime)s (%(levelname)s): %(message)s"
logging.basicConfig(filename='panterjboss_'+str(datetime.datetime.today().date())+'.log', format=FORMAT, level=logging.INFO)


global gl_http_pool


def set_http_pool(pool):
    global gl_http_pool
    gl_http_pool = pool


def auto_update():
    """
    Update functionality disabled in custom build.
    :return: False
    """
    panter.print_and_flush(RED + "\n [!] PANTER JBOSS: auto-update deshabilitado en esta build personalizada.\n" + ENDC)
    return False


def check_updates():
    """
    Update check disabled in custom build.
    :return: False
    """
    return False

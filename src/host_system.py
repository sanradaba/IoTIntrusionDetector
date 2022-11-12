import utils
import subprocess
import sys
import logging
import os
import ctypes


def is_admin() -> bool:
    """Permite comprobar si el proceso se está ejecutando como
    root/Administrador en el sistema operativo

    Returns:
        bool: true si el proceso se esta ejecutando como root/Administrador,
        false en caso contrario
    """
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


def is_npcap_installed() -> bool:
    """Comprueba si está instalada la librería Npcap en SO Windows

    Returns:
        bool: true si está instalado Npcap, false en caso contrario
    """
    if utils.get_os() == 'windows':
        npcap_path = os.path.join(
            os.environ['WINDIR'], 'System32', 'Npcap'
        )
        return os.path.exists(npcap_path)


def enable_ip_forwarding():

    os_platform = utils.get_os()

    if os_platform == 'mac':
        cmd = ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=1']
    elif os_platform == 'linux':
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=1']
    elif os_platform == 'windows':
        cmd = ['powershell', 'Set-NetIPInterface', '-Forwarding', 'Enabled']

    assert subprocess.call(cmd) == 0


def disable_ip_forwarding():

    os_platform = utils.get_os()

    if os_platform == 'mac':
        cmd = ['/usr/sbin/sysctl', '-w', 'net.inet.ip.forwarding=0']
    elif os_platform == 'linux':
        cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=0']
    elif os_platform == 'windows':
        cmd = ['powershell', 'Set-NetIPInterface', '-Forwarding', 'Disabled']

    assert subprocess.call(cmd) == 0

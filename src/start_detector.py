import ctypes
import os
import signal
import sys
import time

import scapy.all as sc

import detector
import host_system
import utils
from naming import ConstantsNamespace


def main():
    sc.load_layer("http")
    # Tiene que ejecutarse con permisos de root
    if not host_system.is_admin():
        sys.stderr.write('Por favor, ejecutame con root/Administrador.\n')
        sys.exit(1)

    if not host_system.is_npcap_installed():
        constants = ConstantsNamespace()
        sys.stderr.write("IoT Intrusion detector no puede funcionar"
                         + "sin Npcap.\n")
        sys.stderr.write("Por favor, visita para instalarlo "
                         + constants.NPCAP_DOWNLOAD_URL)
        sys.exit(1)

    # chequeo de interfaces de red conectadas
    # if len(utils.get_network_ip_range()) == 0:
    if not utils.check_ethernet_network():
        sys.stderr.write("IoT  Intrusion detector no puede funcionar con "
                         + "múltiples interfaces de red conectadas"
                         + "de manera simultanea.\n")
        sys.stderr.write("Por favor revise si tiene una VPN funcionando "
                         + "o si su computadora está conectada "
                         + "a la red cableada e inalámbrica simultáneamente.")
        sys.exit(1)

    utils.log('[Main] Finalizando procesos anteriores.')
    if not kill_existing_inspector():
        utils.log('[Main] No se han podido finalizar los procesos.')
        return

    utils.log('[Main] Arrancando detector')
    detector.enable_ip_forwarding()

    # We don't wrap the function below in safe_run because, well, 
    # if it crashes, it crashes.
    host_state = detector.start()

    # Waiting for termination
    while True:
        with host_state.lock:
            if host_state.quit:
                break
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print('')
            break

    utils.log('[Main] Restaurando ARP...')

    with host_state.lock:
        host_state.spoof_arp = False

    for t in range(10):
        print('Limpiando ({})...'.format(10 - t))
        time.sleep(1)

    detector.disable_ip_forwarding()

    utils.log('[Main] Quit.')

    print('\n' * 100)
    print("""
        IoT Detector de intrusiones finalizado.

        Ya puede cerrar la ventana.

    """)

    # Remove PID file
    try:
        os.remove(get_pid_file())
    except Exception:
        pass


def get_pid_file():

    pid_file = os.path.join(
        os.path.expanduser('~'),
        utils.DEFAULT_HOME_DIR_NAME,
        'iot_inspector_pid.txt'
    )

    return pid_file


def kill_existing_inspector():

    pid_file = get_pid_file()

    try:
        with open(pid_file) as fp:
            pid = int(fp.read().strip())
    except Exception:
        pass
    else:
        # Kill existing process
        killed = False
        for _ in range(60):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                killed = True
                break
            else:
                time.sleep(1)
                utils.log('[Main] esperando por la finalización de procesos.')
        if not killed:
            return False

    with open(pid_file, 'w') as fp:
        fp.write(str(os.getpid()))

    return True


if __name__ == '__main__':
    main()

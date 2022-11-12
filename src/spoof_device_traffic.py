import utils
from host_state import HostState
from packet_processor import PacketProcessor
from packet_capture import PacketCapture
import host_system
import sys
import naming
from arp_spoof import ArpSpoof
import time
from arp_scan import ArpScan


def main():

    if not host_system.is_admin():
        sys.stderr.write('Por favor, ejecutame con root/Administrador.\n')
        sys.exit(1)

    if not host_system.is_npcap_installed():
        sys.stderr.write("IoT Intrusion detector no puede funcionar"
                         + "sin Npcap.\n")
        sys.stderr.write("Por favor, visita para instalarlo "
                         + naming.NPCAP_DOWNLOAD_URL)
        sys.exit(1)

    if len(utils.get_network_ip_range()) == 0:
        sys.stderr.write("IoT  Intrusion detector no puede funcionar con "
                         + "múltiples interfaces de red conectadas"
                         + "de manera simultanea.\n")
        sys.stderr.write("Por favor revise si tiene una VPN funcionando "
                         + "o si su computadora está conectada "
                         + "a la red cableada e inalámbrica simultáneamente.")
        sys.exit(1)

    host_system.enable_ip_forwarding()

    state = HostState()
    state.host_mac = utils.get_my_mac()
    state.gateway_ip, _, state.host_ip = utils.get_default_route()
    assert utils.is_ipv4_addr(state.gateway_ip)
    assert utils.is_ipv4_addr(state.host_ip)
    utils.log('[Main] Inicio de prueba de detección de dispositivos de red.')
    state.packet_processor = PacketProcessor(state)

    arp_scan_thread = ArpScan(state)
    arp_scan_thread.start()
    
    utils.log('Initialized:', state.__dict__)
    # Continuously capture packets
    packet_capture_thread = PacketCapture(state)
    packet_capture_thread.start()

    arp_spoof_thread = ArpSpoof(state)
    arp_spoof_thread.start()

    # Waiting for termination
    while True:
        with state.lock:
            victim_device_id = utils.get_oui('78:bd:bc:f0:4c:ad')
            if victim_device_id is not None:
                if victim_device_id not in state.device_whitelist:
                    state.device_whitelist.append(victim_device_id)
            if state.quit:
                break
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print('')
            break

    utils.log('[Main] Restoring ARP...')

    with state.lock:
        state.spoof_arp = False

    for t in range(10):
        print('Cleaning up ({})...'.format(10 - t))
        time.sleep(1)

    host_system.disable_ip_forwarding()

    utils.log('[Main] Quit.')


if __name__ == '__main__':
    main()

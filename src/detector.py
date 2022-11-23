"""
Entry point for Inspector UI.

"""
import utils
from host_state import HostState
from packet_processor import PacketProcessor
from arp_scan import ArpScan
from syn_scan import SynScan
from packet_capture import PacketCapture
from arp_spoof import ArpSpoof
# from data_upload import DataUploader
from netdisco_wrapper import NetdiscoWrapper
from naming import ConstantsNamespace
from device_identification import DeviceRegistry
import subprocess
import sys
import logging
# import server_config
import webserver


def start():
    """
    Initializes inspector by spawning a number of background threads.

    Returns the host state once all background threats are started.

    """
    # Read from home directory the user_key. If non-existent, get one from
    # cloud.
    config_dict = utils.get_user_config()

    utils.log('[MAIN] Starting.')

    # Set up environment
    state = HostState()
    # state.user_key = config_dict['user_key'].replace('-', '')
    state.secret_salt = config_dict['secret_salt']
    state.host_mac = utils.get_my_mac()
    state.gateway_ip, _, state.host_ip = utils.get_default_route()
    state.net, state.mask = utils.get_net_and_mask()

    deviceRegistry = DeviceRegistry()
    deviceRegistry.loadFromCsv("src/oui.csv")

    assert utils.is_ipv4_addr(state.gateway_ip)
    assert utils.is_ipv4_addr(state.host_ip)

    state.packet_processor = PacketProcessor(state)

    utils.log('Initialized:', state.__dict__)

    # Start web API
    webserver.start_thread(state, deviceRegistry)

    # Continously discover devices
    arp_scan_thread = ArpScan(state)
    arp_scan_thread.start()

    # Continously discover ports via SYN scans
    syn_scan_thread = SynScan(state)
    syn_scan_thread.start()

    # # Continuously gather SSDP data
    netdisco_thread = NetdiscoWrapper(state)
    netdisco_thread.start()

    # Continuously capture packets
    packet_capture_thread = PacketCapture(state)
    packet_capture_thread.start()

    # Continously spoof ARP
    if '--no_spoofing' not in sys.argv:
        arp_spoof_thread = ArpSpoof(state)
        arp_spoof_thread.start()

    # Suppress scapy warnings
    try:
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    except Exception:
        pass

    # Suppress flask messages
    try:
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
    except Exception:
        pass

    console_message = "Ready. To test if the API works, visit http://127.0.0.1:{:}/get_device_list"
    print(console_message.format(ConstantsNamespace().PORT))

    return state


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



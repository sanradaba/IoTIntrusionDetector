"""
Misc functions.

"""
# import server_config
import os
import scapy.all as sc
import time
import threading
import traceback
import datetime
import sys
import re
import json
import uuid
import hashlib
import netaddr
import netifaces
import ipaddress
import subprocess


IPv4_REGEX = re.compile(r'[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}\.[0-9]{0,3}')

sc.conf.verb = 0

# If non empty, then only devices with the following MAC addresses with be
# inspected. Do not populate this list in production. For internal testing.
TEST_OUI_LIST = [
    # 'd83134',  
    # '74f61c',  
]

DEFAULT_HOME_DIR_NAME = 'iot-intrusion-detector'

# directorio de logs
home_dir = os.path.join(os.path.expanduser('~'), DEFAULT_HOME_DIR_NAME)
if not os.path.isdir(home_dir):
    os.mkdir(home_dir)


def is_ipv4_addr(value):

    return IPv4_REGEX.match(value)


def get_user_config():
    """Returns the user_config dict."""

    user_config_file = os.path.join(
        os.path.expanduser('~'),
        DEFAULT_HOME_DIR_NAME,
        'iot_detector_config.json'
    )

    try:
        with open(user_config_file) as fp:
            return json.load(fp)

    except Exception:
        pass

    secret_salt = str(uuid.uuid4())
    # actualizar configuración
    with open(user_config_file, 'w') as fp:
        config_dict = {
            'secret_salt': secret_salt
        }
        json.dump(config_dict, fp)

    return config_dict


class TimeoutError(Exception):
    pass


_lock = threading.Lock()


def log(*args):

    log_str = '[%s] ' % datetime.datetime.today()
    log_str += ' '.join([str(v) for v in args])

    log_file_path = os.path.join(
        os.path.expanduser('~'),
        DEFAULT_HOME_DIR_NAME,
        'iot_detector_logs.txt'
    )

    with open(log_file_path, 'a') as fp:
        fp.write(log_str + '\n')


def get_gateway_ip(timeout=10):
    """Returns the IP address of the gateway."""

    return get_default_route(timeout)[0]


def get_host_ip(timeout=10):
    """Returns the host's local IP (where IoT Inspector client runs)."""

    return get_default_route(timeout)[2]


def _get_routes():

    while True:

        sc.conf.route.resync()
        routes = sc.conf.route.routes
        if routes:
            return routes

        time.sleep(1)


def get_default_route():
    """Returns (gateway_ip, iface, host_ip)."""
    # Discover the active/preferred network interface 
    # by connecting to Google's public DNS server
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect(("8.8.8.8", 80))
            iface_ip = s.getsockname()[0]
    except socket.error:
        sys.stderr.write('Detector de intrusiones IoT no puede funcionar'
                         + 'sin conectividad de red.\n')
        sys.exit(1)

    while True:
        routes = _get_routes()
        default_route = None
        for route in routes:
            if route[4] == iface_ip:
                # Reassign scapy's default interface to the one we selected
                sc.conf.iface = route[3]
                default_route = route[2:5]
                break
        if default_route:
            break

        log('get_default_route: retrying')
        time.sleep(1)  

    # If we are using windows, conf.route.routes table doesn't update.
    # We have to update routing table manually for packets
    # to pick the correct route. 
    if sys.platform.startswith('win'):
        for i, route in enumerate(routes):
            # if we see our selected iface, update the metrics to 0
            if route[3] == default_route[1]:
                routes[i] = (*route[:-1], 0)

    return default_route


def get_net_and_mask():
    iface = get_default_route()[1]
    routes = _get_routes()
    net = mask = None
    for route in routes:
        if route[3] == iface:
            net = ipaddress.IPv4Address(route[0])
            mask = ipaddress.IPv4Address(route[1])
            break
    return net, mask


def check_pkt_in_network(ip, net, mask):
    full_net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
    return full_net.network_address == net


def get_network_ip_range_windows():
    default_iface = get_default_route()
    iface_filter = default_iface[1]
    print(default_iface)
    ip_set = set()
    iface_ip = iface_filter.ip
    iface_guid = iface_filter.guid
    for k, v in netifaces.ifaddresses(iface_guid).items():
        if v[0]['addr'] == iface_ip:
            netmask = v[0]['netmask']
            break

    network = netaddr.IPAddress(iface_ip)
    cidr = netaddr.IPAddress(netmask).netmask_bits()
    subnet = netaddr.IPNetwork('{}/{}'.format(network, cidr))

    return ip_set


def get_network_ip_range():
    """
        Gets network IP range for the default interface specified
        by scapy.conf.iface
    """
    ip_set = set()
    default_route = get_default_route()

    iface_str = ''
    if sys.platform.startswith('win'):
        iface_info = sc.conf.iface
        iface_str = iface_info.guid
    else:
        iface_str = sc.conf.iface

    netmask = None
    for k, v in netifaces.ifaddresses(iface_str).items():
        if v[0]['addr'] == default_route[2]:
            netmask = v[0]['netmask']
            break

    # Netmask is None when user runs VPN.
    if netmask is None:
        return set()

    gateway_ip = netaddr.IPAddress(default_route[0])
    cidr = netaddr.IPAddress(netmask).netmask_bits()
    subnet = netaddr.IPNetwork('{}/{}'.format(gateway_ip, cidr))

    for ip in subnet:
        ip_set.add(str(ip))

    return ip_set


def check_ethernet_network():
    """
        Check presence of non-Ethernet network adapters (e.g., VPN).
        VPNs use TUN interfaces which don't have a hardware address.
    """
    default_iface = get_default_route()

    assert default_iface[1] == sc.conf.iface, "incorrect sc.conf.iface"
    iface_str = ''
    if sys.platform.startswith('win'):
        iface_info = sc.conf.iface
        iface_str = iface_info.guid
    else:
        iface_str = sc.conf.iface

    ifaddresses = netifaces.ifaddresses(str(iface_str))
    try:
        iface_mac = ifaddresses[netifaces.AF_LINK][0]['addr']
    except KeyError:
        return False
    return iface_mac != ''


def get_my_mac():
    """Returns the MAC addr of the default route interface."""

    mac_set = get_my_mac_set(iface_filter=get_default_route()[1])
    return mac_set.pop()


def get_my_mac_set(iface_filter=None):
    """Returns a set of MAC addresses of the current host."""

    out_set = set()
    if sys.platform.startswith("win"):
        from scapy.arch.windows import NetworkInterface
        if type(iface_filter) == NetworkInterface:
            out_set.add(iface_filter.mac)

    for iface in sc.get_if_list():
        if iface_filter is not None and iface != iface_filter:
            continue
        try:
            mac = sc.get_if_hwaddr(iface)
        except Exception as e:
            continue
        else:
            out_set.add(mac)

    return out_set


class _SafeRunError(object):
    """Used privately to denote error state in safe_run()."""

    def __init__(self):
        pass


def restart_upon_crash(func, args=[], kwargs={}):
    """Restarts func upon unexpected exception and logs stack trace."""

    while True:

        result = safe_run(func, args, kwargs)

        if isinstance(result, _SafeRunError):
            time.sleep(1)
            continue

        return result


def safe_run(func, args=[], kwargs={}):
    """Returns _SafeRunError() upon failure and logs stack trace."""

    try:
        return func(*args, **kwargs)

    except Exception as e:

        err_msg = '=' * 80 + '\n'
        err_msg += 'Time: %s\n' % datetime.datetime.today()
        err_msg += 'Function: %s %s %s\n' % (func, args, kwargs)
        err_msg += 'Exception: %s\n' % e
        err_msg += str(traceback.format_exc()) + '\n\n\n'

        with _lock:
            sys.stderr.write(err_msg + '\n')
            log(err_msg)

        return _SafeRunError()


def get_device_id(device_mac, host_state):

    device_mac = str(device_mac).lower().replace(':', '')
    s = device_mac + str(host_state.secret_salt)

    return 's' + hashlib.sha256(s.encode('utf-8')).hexdigest()[0:10]


def smart_max(v1, v2):
    """
        Returns max value even if one value is None.

        Python cannot compare None and int, so build a wrapper
        around it.
    """
    if v1 is None:
        return v2

    if v2 is None:
        return v1

    return max(v1, v2)


def smart_min(v1, v2):
    """
    Returns min value even if one of the value is None.

    By default min(None, x) == None per Python default behavior.

    """

    if v1 is None:
        return v2

    if v2 is None:
        return v1

    return min(v1, v2)


def get_min_max_tuple(min_max_tuple, value):
    """
    Returns a new min_max_tuple with value considered.

    For example:

        min_max_tuple = (2, 3)
        print get_min_max_tuple(min_max_tuple, 4)

    We get back (2, 4).

    """
    min_v, max_v = min_max_tuple

    min_v = smart_min(min_v, value)
    max_v = smart_max(max_v, value)

    return (min_v, max_v)


def get_oui(mac):

    return mac.replace(':', '').lower()[0:6]


def get_os():
    """Returns 'mac', 'linux', or 'windows'. Raises RuntimeError otherwise."""

    os_platform = sys.platform

    if os_platform.startswith('darwin'):
        return 'mac'

    if os_platform.startswith('linux'):
        return 'linux'

    if os_platform.startswith('win'):
        return 'windows'

    raise RuntimeError('Unsupported operating system.')


def open_browser_on_windows(url):

    try:
        subprocess.call(['start', '', url], shell=True)
    except Exception:
        pass


def jsonify_dict(input_dict):
    """
    Returns a new dict where all the keys are jsonified as string, and all the
    values are turned into lists if they are sets.

    """
    output_dict = {}

    for (k, v) in input_dict.items():
        if isinstance(k, tuple):
            k = json.dumps(k)
        if isinstance(v, set):
            v = list(v)
        output_dict[k] = v

    return json.dumps(output_dict)


def test():
    # check_ethernet_network()
    print(get_default_route())


if __name__ == '__main__':
    test()

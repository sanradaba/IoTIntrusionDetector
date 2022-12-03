"""
Analizador de tráfico

"""
import threading
import time
import utils

from host_state import HostState

ANALYSIS_INTERVAL = 10


class TrafficAnalyzer(object):

    def __init__(self, host_state):

        assert isinstance(host_state, HostState)
        self._host_state = host_state

        self._lock = threading.Lock()
        self._active = True

        self._thread = threading.Thread(target=self._analyzer_thread)
        self._thread.daemon = True

        self._last_analysis_ts = time.time()

    def _analyzer_thread(self):
        while True:
            time.sleep(ANALYSIS_INTERVAL)
            with self._lock:
                if not self._active:
                    return
            utils.safe_run(self._analyze_traffic)

    def start(self):

        with self._lock:
            self._active = True

        self._thread.start()

        utils.log('[Analyzer] Start traffic analyzer')

    def stop(self):

        utils.log('[Analyzer] Stopping.')

        with self._lock:
            self._active = False

        self._thread.join()

        utils.log('[Analyzer] Stopped.')

    def _clear_host_state_pending_data(self):
        self._host_state.pending_dhcp_dict = {}
        self._host_state.pending_resolver_dict = {}
        self._host_state.pending_dns_dict = {}
        self._host_state.pending_flow_dict = {}
        self._host_state.pending_ua_dict = {}
        self._host_state.pending_tls_dict_list = []
        self._host_state.pending_netdisco_dict = {}
        self._host_state.pending_syn_scan_dict = {}

    def _prepare_analysis_data(self):
        """Returns (window_duration, a dictionary of data to post).
        """

        window_duration = time.time() - self._last_analysis_ts

        # Remove all pending tasks
        with self._host_state.lock:
            flow_dict = self._host_state.pending_flow_dict
            ip_mac_dict = self._host_state.ip_mac_dict
            self._clear_host_state_pending_data()
            self._last_analysis_ts = time.time()

        device_dict = {}
        for (ip, mac) in ip_mac_dict.items():
            # Never include the gateway
            if ip == self._host_state.gateway_ip:
                continue
            device_id = utils.get_device_id(mac, self._host_state)
            oui = utils.get_oui(mac)
            device_dict[device_id] = (ip, oui)
        return (window_duration, device_id)

    def _analyze_traffic(self):
        devices = []
        with self._host_state.lock:
            if not self._host_state.device_whitelist:
                return devices
        window_duration, device_id = self._prepare_analysis_data()

        attack_detected = {self._last_analysis_ts: window_duration}
        with self._host_state.lock:
            if device_id not in self._host_state.detected_attacks_dict:
                self._host_state.detected_attacks_dict[device_id] = []
            self._host_state.detected_attacks_dict[device_id].append(
                attack_detected)
        devices.append(device_id)
        utils.log('[Analyzer] analysis result:', False)
        return devices

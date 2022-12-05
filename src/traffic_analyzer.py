"""
Analizador de tráfico

"""
import threading
import time
import utils
import itertools
import pandas as pd

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

    def _prepare_analysis_data(self, devices_to_analyze):
        """Returns (window_duration, a dictionary of data to post).
        """

        window_duration = time.time() - self._last_analysis_ts

        # Remove all pending tasks
        with self._host_state.lock:
            features_dict = self._host_state.flow_features_dict
            ip_mac_dict = self._host_state.ip_mac_dict
            self._host_state.flow_features_dict = {}
            self._clear_host_state_pending_data()
            self._last_analysis_ts = time.time()

        device_dict = {}
        for (ip, mac) in ip_mac_dict.items():
            # Never include the gateway
            if ip == self._host_state.gateway_ip:
                continue
            device_id = utils.get_device_id(mac, self._host_state)
            if device_id in devices_to_analyze:
                oui = utils.get_oui(mac)
                device_dict[device_id] = (ip, oui)

        flows_by_device_id_dict = {}
        for device_id in devices_to_analyze:
            key_to_extract = {
                "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean",
                "flow_iat_mean", "flow_iat_max", "fwd_iat_mean", "fwd_iat_max",
                "fwd_header_len", "fwd_pkts_s", "pkt_len_min", "pkt_len_max",
                "pkt_len_std", "ack_flag_cnt", "init_fwd_win_byts"
                              }
            if device_id in features_dict:
                features_list = []
                for flowId in features_dict[device_id]:
                    flow_features = features_dict[device_id][flowId].get_data()
                    extracted_dict = dict((key, flow_features[key])
                                          for key in key_to_extract
                                          if key in flow_features)
                    features_list.append(extracted_dict)
            # groups = itertools.groupby(device_traffic,
            #                           key=lambda element: element[0])
            # df = pd.DataFrame(device_traffic)
            # df["local"] = pd.to_datetime(df['time_stamp'], unit='s', utc=True)
            # flows = df.groupby(["flow_id"])
            # df["IAT"] = flows["time_stamp"].diff(1)
            # for packet in device_traffic:
            #    print(packet)

                print(features_list)
                flows_by_device_id_dict[device_id] = extracted_dict

        return (window_duration, flows_by_device_id_dict)

    def _analyze_traffic(self):
        victim_devices = []
        devices_to_analyze = []
        with self._host_state.lock:
            devices_to_analyze = self._host_state.device_whitelist

        if not devices_to_analyze:
            return victim_devices

        window_duration, flows_by_device_id_dict = self._prepare_analysis_data(
            devices_to_analyze)

        attack_detected = {self._last_analysis_ts: window_duration}
#        with self._host_state.lock:
#            if device_id not in self._host_state.detected_attacks_dict:
#                self._host_state.detected_attacks_dict[device_id] = []
#            self._host_state.detected_attacks_dict[device_id].append(
#                attack_detected)
       # victim_devices.append(device_id)
        utils.log('[Analyzer] analysis result:', False)
        return victim_devices

"""
Analizador de tráfico

"""
import threading
import time
import utils
import pandas as pd
import datetime
from os import path
from neural_network import DDoSDetector

from host_state import HostState

"""equivalencias

    Returns: equi
        _type_: _description_
"""


ANALYSIS_INTERVAL = 30

CICDDos2019_cicflowmeter_equivalences = {
    "Source IP": "src_ip",
    "Source Port": "src_port",
    "Destination IP": "dst_ip",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Flow Duration": "flow_duration",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Max": "flow_iat_max",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd Header Length": "fwd_header_len",
    "Fwd Packets/s": "fwd_pkts_s",
    "Min Packet Length": "pkt_len_min",
    "Max Packet Length": "pkt_len_max",
    "Packet Length Std": "pkt_len_std",
    "ACK Flag Count": "ack_flag_cnt",
    "Init_Win_bytes_forward": "init_fwd_win_byts",
    "Init_Win_bytes_backward": "init_bwd_win_byts",
    "min_seg_size_forward": "fwd_seg_size_min",
    "Subflow Fwd Bytes": "subflow_fwd_byts",
    "Subflow Bwd Bytes": "subflow_bwd_byts",
    "Total Length of Bwd Packets": "totlen_bwd_pkts",
    "Packet Length Variance": "pkt_len_var",
    "Bwd Packets/s": "bwd_pkts_s",
    "Flow Bytes/s": "flow_byts_s",
    "Bwd Header Length": "bwd_header_len",
}


class TrafficAnalyzer(object):

    def __init__(self, host_state):

        assert isinstance(host_state, HostState)
        self._host_state = host_state

        self._lock = threading.Lock()
        self._active = True

        self._thread = threading.Thread(target=self._analyzer_thread,
                                        name='analyzer')
        self._thread.daemon = True

        self._last_analysis_ts = time.time()
        self.DDoSDetector = DDoSDetector()

    def _analyzer_thread(self):
        while True:
            time.sleep(ANALYSIS_INTERVAL)
            with self._lock:
                if not self._active:
                    return
            victim_devices = self._analyze_traffic()
            if victim_devices:
                with self._host_state.lock:
                    detected_attacks_dict = \
                        self._host_state.detected_attacks_dict
                    for device_id in victim_devices.keys():
                        if device_id not in detected_attacks_dict:
                            detected_attacks_dict[device_id
                                                  ] = [victim_devices[
                                                      device_id]]
                        else:
                            detected_attacks_dict[
                                device_id].append(victim_devices[device_id])

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
            key_to_extract = CICDDos2019_cicflowmeter_equivalences.values()

            if device_id in features_dict:
                features_list = []
                flows_list = []
                for flowId in features_dict[device_id]:
                    flow_features = features_dict[device_id][flowId].get_data()
                    extracted_dict = dict((key, flow_features[key])
                                          for key in key_to_extract
                                          if key in flow_features)
                    flows_list.append(flowId)
                    features_list.append(
                        rename_from_cicflowmeter_to_CICDDos2019(
                            self.DDoSDetector.get_features(), extracted_dict))

                filename = device_id + "_"
                filename += datetime.datetime.fromtimestamp(
                    self._last_analysis_ts).replace(
                    microsecond=0).isoformat().replace(":", "")
                filename += ".csv"
                filename = path.join(utils.home_dir, "captures", filename)
                pd.DataFrame(features_list).to_csv(filename, index=False)
                # print(features_list)
                flows_by_device_id_dict[device_id] = (features_list,
                                                      flows_list)

        return (window_duration, flows_by_device_id_dict)

    def _analyze_traffic(self):
        victim_devices = {}
        devices_to_analyze = []
        with self._host_state.lock:
            devices_to_analyze = self._host_state.device_whitelist

        if not devices_to_analyze:
            return victim_devices

        window_duration, flows_by_device_id_dict = self._prepare_analysis_data(
            devices_to_analyze)
        iso_timestamp = datetime.datetime.fromtimestamp(
                    self._last_analysis_ts).replace(
                    microsecond=0).isoformat()
        for device_id in flows_by_device_id_dict:
            features_list, flows_keys = flows_by_device_id_dict[device_id]
            flows_evaluation = self.DDoSDetector.evaluate(
                features_list)
            victim_devices[device_id] = {"time_stamp": iso_timestamp,
                                         "flow_keys": []}
            for flow_key, evaluation in zip(flows_keys, flows_evaluation):
                if 1 == evaluation:
                    victim_devices[device_id]["flow_keys"].append(flow_key)
                    utils.log('[Analyzer] device (id={}) {}: supected flow [{}]'
                              .format(device_id, iso_timestamp, flow_key))
            if not victim_devices[device_id]["flow_keys"]:
                victim_devices = {}
        return victim_devices





def rename_from_cicflowmeter_to_CICDDos2019(features: list, cicflowmeter: dict) -> dict:
    """Permite generar un dicionario con nombrado
    de cararcterísticas de la colección CICDDos2019
    partiendo de un diccionario de extracción
    de la versión python de cicflowmeter

    Args:
        features (list): Lista de características a extraer
        cicflowmeter (dict): diccionario resultado de la captura
        de tráfico realizada por cicflowmeter

    Returns:
        dict: Diccionario con carácterísticas evaluable por
        algoritmos ML entrenados con CICDDos2019
    """
    CICDDoS2019 = {}
    for key in features:
        CICDDoS2019[key] = cicflowmeter[
            CICDDos2019_cicflowmeter_equivalences[key]]
    return CICDDoS2019


if __name__ == "__main__":
    ta = TrafficAnalyzer()

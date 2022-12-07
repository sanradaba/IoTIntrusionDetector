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

ANALYSIS_INTERVAL = 60


class TrafficAnalyzer(object):

    def __init__(self, host_state):

        assert isinstance(host_state, HostState)
        self._host_state = host_state

        self._lock = threading.Lock()
        self._active = True

        self._thread = threading.Thread(target=self._analyzer_thread)
        self._thread.daemon = True

        self._last_analysis_ts = time.time()
        self.DDoSDetector = DDoSDetector()

    def _analyzer_thread(self):
        while True:
            time.sleep(ANALYSIS_INTERVAL)
            with self._lock:
                if not self._active:
                    return
            victim_devices = utils.safe_run(self._analyze_traffic)
            if victim_devices:
                with self._host_state.lock:
                    detected_attacks_dict = \
                        self._host_state.detected_attacks_dict
                    for device_id in victim_devices:
                        if device_id not in detected_attacks_dict:
                            detected_attacks_dict[device_id] = []
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
            key_to_extract = {
                "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_std",
                "flow_iat_mean", "flow_iat_max", "fwd_iat_mean", "fwd_iat_max",
                "fwd_header_len", "fwd_pkts_s", "pkt_len_min", "pkt_len_max",
                "pkt_len_std", "ack_flag_cnt", "init_fwd_win_byts",
                "fwd_seg_size_min"
                              }
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
                        rename_from_cicflowmeter_to_CICDDos2019(extracted_dict))
            # groups = itertools.groupby(device_traffic,
            #                           key=lambda element: element[0])
            # df = pd.DataFrame(device_traffic)
            # df["local"] = pd.to_datetime(df['time_stamp'], unit='s', utc=True)
            # flows = df.groupby(["flow_id"])
            # df["IAT"] = flows["time_stamp"].diff(1)
            # for packet in device_traffic:
            #    print(packet)

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
            for flow_key, evaluation in zip(flows_keys, flows_evaluation):
                if 1 == evaluation:
                    victim_devices[device_id] = iso_timestamp
                    utils.log('[Analyzer] device (id={}) {}: supected flow [{}]'
                              .format(device_id, iso_timestamp, flow_key))
                    break
        return victim_devices


def rename_from_cicflowmeter_to_CICDDos2019(cicflowmeter: dict) -> dict:
    """Permite generar un dicionario con nombrado
    de cararcterísticas de la colección CICDDos2019
    partiendo de un diccionario de extracción
    de la versión python de cicflowmeter

    Args:
        cicflowmeter (dict): diccionario resultado de la captura
        de tráfico realizada por cicflowmeter

    Returns:
        dict: Diccionario con carácterísticas evaluable por
        algoritmos ML entrenados con CICDDos2019
    """
    CICDDoS2019 = {}
    CICDDoS2019["Fwd Packet Length Max"] = cicflowmeter["fwd_pkt_len_max"]
    CICDDoS2019["Fwd Packet Length Min"] = cicflowmeter["fwd_pkt_len_min"]
    CICDDoS2019["Fwd Packet Length Std"] = cicflowmeter["fwd_pkt_len_std"]
    CICDDoS2019["Flow IAT Mean"] = cicflowmeter["flow_iat_mean"]
    CICDDoS2019["Flow IAT Max"] = cicflowmeter["flow_iat_max"]
    CICDDoS2019["Fwd IAT Mean"] = cicflowmeter["fwd_iat_mean"]
    CICDDoS2019["Fwd IAT Max"] = cicflowmeter["fwd_iat_max"]
    CICDDoS2019["Fwd Header Length"] = cicflowmeter["fwd_header_len"]
    CICDDoS2019["Fwd Packets/s"] = cicflowmeter["fwd_pkts_s"]
    CICDDoS2019["Min Packet Length"] = cicflowmeter["pkt_len_min"]
    CICDDoS2019["Max Packet Length"] = cicflowmeter["pkt_len_max"]
    CICDDoS2019["Packet Length Std"] = cicflowmeter["pkt_len_std"]
    CICDDoS2019["ACK Flag Count"] = cicflowmeter["ack_flag_cnt"]
    CICDDoS2019["Init_Win_bytes_forward"] = cicflowmeter["init_fwd_win_byts"]
    CICDDoS2019["min_seg_size_forward"] = cicflowmeter["fwd_seg_size_min"]
    return CICDDoS2019


if __name__ == "__main__":
    ta = TrafficAnalyzer()

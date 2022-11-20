"""
Implements the device-identification algorithm

"""

from csv import DictReader
import utils


MAC_TO_NAME_MAPPING = {
    '10bef5032d6a': ('D-Link', 'NAS'),
    '78bdbcf04cad': ('Philips', 'Philips Light Bulb'),
    '2caa8e9a64b7': ('Wyze', 'Wyze Camera'),
    '4cefc00b91b3': ('Amazon', 'Amazon Echo'),
    '18b4308a9fb2': ('Nest', 'Nest Camera'),
    '24fd5b01b2f8': ('SmartThings', 'SmartThings Dishwasher'),
    '50c7bf09f34c': ('TP-Link', 'TP-Link Smart Plug'),
    '50f14a65371c': ('Bose', 'Bose Speaker'),
    '54e0193c7c14': ('Amazon', 'Ring Camera'),
    '702c1f39256e': ('Wisol', 'Wisol Fridge'),
    'a477332fe06e': ('Google', 'Google Home'),
    'c0972769bd52': ('Samsung', 'Samsung Stove'),
    'd828c9061c69': ('GE', 'GE Dryer'),
    'd828c9061517': ('GE', 'GE Washer'),
    '28395e4d2914': ('Samsung', 'Samsung Smart TV'),
    'f0f0a4f8e5fc': ('Amazon', 'Amazon Fire Stick TV')
}


class DeviceRegistry(object):
    """Base de datos de dispositivos por MAC.
    """
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(DeviceRegistry, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        self.file_name = None
        # http://standards-oui.ieee.org/oui/oui.csv
        self.MAC_Address_Block_Large_dict = {}
        # http://standards-oui.ieee.org/oui28/mam.csv
        self.MAC_Address_Block_Medium = {}

    def loadFromCsv(self, file_name: str):
        """Carga de csv el registro de asignaciones IEEE 
        - MAC Address Block Large (MA-L)
        https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries

        Args:
            file_name (str): ruta de fichero csv MA-L
        """
        self.file_name = file_name
        utils.log("Cargando registro de asignaciones largas (MA-L)..")
        with open(self.file_name, 'r', encoding='utf8') as f:
            dict_reader = DictReader(f)
            self.MAC_Address_Block_Large_dict = list(dict_reader)
        utils.log("Asignaciones MA-L..")

    def get_device_vendor(self, mac_address: str):
        mac_address = mac_address.replace(':', '').upper()[:6]
        finded = list(filter(
            lambda vendor: vendor['Assignment'] == mac_address,
            self.MAC_Address_Block_Large_dict))
        if(finded):
            return finded[0]['Organization Name']
        else:
            return ''


def get_device_name(mac_address):

    mac_address = mac_address.replace(':', '').lower()

    try:
        return MAC_TO_NAME_MAPPING[mac_address][1]
    except KeyError:
        return ''


def get_device_vendor(mac_address):

    mac_address = mac_address.replace(':', '').lower()

    try:
        return MAC_TO_NAME_MAPPING[mac_address][0]
    except KeyError:
        return ''


if __name__ == "__main__":
    singleton_devices_registry = DeviceRegistry()
    singleton_devices_registry.loadFromCsv("src/oui.csv")
    print(singleton_devices_registry.get_device_vendor("4c:ab:4f:c4:93:e0"))

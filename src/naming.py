from dataclasses import dataclass


@dataclass(frozen=True)
class ConstantsNamespace:
    """Objeto singleton de constantes
    """
    VERSION = "0.1.0"
    NPCAP_DOWNLOAD_URL = 'https://npcap.com/#download'
    PORT = 18380

import socket

class DeepRiver_Client:
    def __init__(self):
        self.is_connected = False
        self.server_info = {
            'host': None,
            'port': None
        }
        self.nickname = None
        self._s = None

    def connect(self, host: str, password = None):
        pass
    
    def disconnect(self):
        pass
    
    def _create_key_pair(self, name):
        pass

    def _load_server_public_key(self):
        pass

    def _get_server_banner(self):
        pass
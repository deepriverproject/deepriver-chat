import os

# ===========[ ERRORS ]===========

class PublicKeyNotFound(Exception):
    pass

class PrivateKeyNotFound(Exception):
    pass


# ===========[ ENUMS ]===========
class ServerType:
    PUBLIC = 0
    SEMIPUBLIC = 1
    SEMIPRIVATE = 2
    PRIVATE = 3

# ===========[ DeepRiver_Server ]===========
class DeepRiver_Server:
    def __init__(self, config=None):
        pass
    def _set_default_config(self):
        self._host = "localhost"
        self._port = 10101
        self._type = ServerType.PUBLIC
        self._server_password = None
        if not os.path.isfile('./keys/public_key.pub'):
            raise PublicKeyNotFound(f"Public key could not not found: ./keys/public_key.pub")
        with open('./keys/public_key.pub') as f:
            self._public_key = f.read()
        if not os.path.isfile('./keys/private_key.priv'):
            raise PrivateKeyNotFound(f"Private key could not found: ./keys/private_key.priv")
        with open('./keys/private_key.priv') as f:
            self._private_key = f.read()
        self._connection_init_timeout = 5
        self._idle_timeout = 0
        if not os.path.isfile('banned.txt'):
            open('banned.txt').close()
        self._ban_list = 'banned.txt'    
        self._send_banner_file = False
        self._verbosity = 0
        if not os.path.isfile('banner.txt'):
            open('banner.txt').close()
        self._banner_file = 'banner.txt'
        self._enable_admin = False
        self._admins = {
            'admin': 'admin',
            'testing': 'password'
        }

        
    
        
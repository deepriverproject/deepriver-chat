import os
import configparser
import socket
import threading
from base64 import b64encode, b64decode
import platform

# ===========[ ERRORS ]===========

class PublicKeyNotFound(Exception):
    pass
class PrivateKeyNotFound(Exception):
    pass
class ConfigNotFound(Exception):
    pass
class InvalidConfig(Exception):
    pass

# ===========[ ENUMS ]===========
class ServerType:
    PUBLIC = "public"
    SEMIPUBLIC = "semipublic"
    SEMIPRIVATE = "semiprivate"
    PRIVATE = "private"

class PacketHeader:
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"
    BANNER = "BANNER"
    PUBLIC_KEY = "PUBLIC_KEY"
    CONNPASS = "CONNPASS"
    CHAL = "CHAL"
    MSG_NORMAL = "MSG_NORMAL"
    MSG_CLIENT = "MSG_CLIENT"
    MSG_SRV_SUCCESS = "MSG_SRV_SUCCESS"
    MSG_SRV_DISCONNECT = "MSG_SRV_FAIL"
    DISCONNECT = "DISCONNECT"

# ===========[ DeepRiver_Server ]===========
class DeepRiver_Server:
    __version__ = "0.0.1"

    def __init__(self, config=None):
        self._set_default_config()
        if config:
            self._parse_config(config)
        
        self._clients = {}
    
    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.bind((self._host, self._port))
        self._server.listen(5)

        print("Starting")
        while True:
            client, addr = self._server.accept()
            addr = addr[0]
            print("Conn: " + addr)
            #TODO: Create ban check

            threading.Thread(target=self._connection_init, args=(client,addr,)).start()
    
    def _connection_init(self, client: socket.socket, addr):
        print("Got connection: " + addr)
        client.settimeout(self._connection_init_timeout if self._connection_init_timeout != 0 else None)
        packet = PacketHeader.BANNER + ' '
        if self._verbosity == 0:
            packet += b64encode((f"DeepRiver {self.__version__}").encode()).decode()
        else:
            packet += b64encode(f"DeepRiver {self.__version__} {platform.platform()}".encode()).decode()
        if self._type == ServerType.PUBLIC or self._type == ServerType.SEMIPRIVATE:
            packet += ' '
            packet += b64encode(self._public_key).decode()
        client.send(packet.encode())
        client.close()
        print("Closed connection: " + addr)

    
    def _client_loop(self, client, addr):
        pass
    
    def _disconnect_client(self, client):
        pass

    def _disconnect_all_clients(self):
        pass

    def _parse_config(self, config):
        if not os.path.isfile(config):
            raise ConfigNotFound("Configuration file has not been found: " + str(config))
        cfg = configparser.ConfigParser()
        
        if len(cfg.read(config)) == 0:
            raise InvalidConfig("Provided configuration could not be read.")
        
        if 'Server' in cfg:
            scfg = cfg['Server']

            if 'Host' in scfg:
                self._host = scfg['Host']
            if 'Port' in scfg:
                try:
                    self._port = int(scfg['Port'])
                    if not 1 <= self._port <= 65535:
                        raise InvalidConfig("Port must be an integer (1 - 65535)")
                except ValueError:
                    raise InvalidConfig("Port must be an integer (1 - 65535)")

            if 'Type' in scfg:
                if scfg['Type'] == 'public':
                    self._type = ServerType.PUBLIC
                elif scfg['Type'] == 'semipublic':
                    self._type = ServerType.SEMIPUBLIC
                elif scfg['Type'] == 'semiprivate':
                    self._type = ServerType.SEMIPRIVATE
                elif scfg['Type'] == 'private':
                    self._type = ServerType.PRIVATE
                else:
                    raise InvalidConfig("invalid server type: " + str(scfg['Type']))
            
            if 'ServerPassword' in scfg:
                self._server_password = scfg['ServerPassword']
            
            if 'PublicKeyPath' in scfg:
                if not os.path.isfile(scfg['PublicKeyPath']):
                    raise InvalidConfig("Invalid public key path: " + str(scfg['PublicKeyPath']))
                with open(scfg['PublicKeyPath'], 'rb') as f:
                    self._public_key = f.read()
            
            if 'PrivateKeyPath' in scfg:
                if not os.path.isfile(scfg['PrivateKeyPath']):
                    raise InvalidConfig("Invalid private key path: " + str(scfg['PrivateKeyPath']))
                with open(scfg['PrivateKeyPath'], 'rb') as f:
                    self._private_key = f.read()
            
            if 'ConnectionInitTimeout' in scfg:
                try:
                    self._connection_init_timeout = int(scfg['ConnectionInitTimeout'])
                except ValueError:
                    raise InvalidConfig('ConnectionInitTimeout must be an integer.')
            
            if 'IdleTimeOut' in scfg:
                try:
                    self._idle_timeout = int(scfg['IdleTimeOut'])
                except ValueError:
                    raise InvalidConfig('IdleTimeOut must be an integer.')
            
            if 'BanListPath' in scfg:
                if not os.path.isfile(scfg['BanListPath']):
                    raise InvalidConfig("Invalid ban list path: " + str(scfg['BanListPath']))
                self._ban_list_file = scfg['BanListPath']
                with open(scfg['BanListPath'], 'r') as f:
                    self._ban_list = f.read().split('\n')
        if 'Banner' in cfg:
            bcfg = cfg['Banner']

            if 'SendBannerFile' in bcfg:
                self._send_banner_file = True if bcfg['SendBannerFile'] == 'yes' else False
            
            if 'Verbosity' in bcfg:
                try:
                    self._verbosity = int(bcfg['Verbosity'])
                    if self._verbosity != 0 and self._verbosity != 1:
                        raise InvalidConfig("Invalid verbosity value")
                except ValueError:
                    raise InvalidConfig("Verbosity must be an integer")
            
            if 'BannerFile' in bcfg:
                if not os.path.isfile(bcfg['BannerFile']):
                    raise InvalidConfig("Invalid banner file path")
                with open(bcfg['BannerFile']) as f:
                    self._banner_file = f.read()
        
        if 'Admin' in cfg:
            acfg = cfg['Admin']

            if 'EnableAdministrators' in acfg:
                self._enable_administrators = True if acfg['EnableAdministrators'] == 'yes' else False
            
            if 'Usernames' in acfg:
                if not 'Passwords' in acfg:
                    raise InvalidConfig("Usernames property cannot be present without Passwords one.")
                
                if len(acfg['Usernames'].split(',')) != len(acfg['Passwords'].split(',')):
                    raise InvalidConfig("Usernames must be the same amount as Passwords")
                
                self._admins = {}
                i = 0
                for uid in acfg['Usernames'].split(','):
                    self._admins.update({uid: acfg['Passwords'].split(',')[i]})
                    i += 1

    def _set_default_config(self):
        self._host = "localhost"
        self._port = 10101
        self._type = ServerType.PUBLIC
        self._server_password = None
        if not os.path.isfile('./keys/public_key.pub'):
            raise PublicKeyNotFound(f"Public key could not not found: ./keys/public_key.pub")
        with open('./keys/public_key.pub', 'rb') as f:
            self._public_key = f.read()
        if not os.path.isfile('./keys/private_key.priv'):
            raise PrivateKeyNotFound(f"Private key could not found: ./keys/private_key.priv")
        with open('./keys/private_key.priv', 'rb') as f:
            self._private_key = f.read()
        self._connection_init_timeout = 5
        self._idle_timeout = 0
        if not os.path.isfile('banned.txt'):
            open('banned.txt', 'w').close()
        self._ban_list_file = 'banned.txt'
        with open('banned.txt', 'r') as f:
            self._ban_list = f.read().split('\n')    
        self._send_banner_file = False
        self._verbosity = 0
        if not os.path.isfile('banner.txt'):
            open('banner.txt', 'w').close()
        with open('banner.txt', 'r') as f:
            self._banner_file = f.read()
        self._enable_admin = False
        self._admins = {}
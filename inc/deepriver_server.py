import base64
import os
import configparser
import re
import socket
from struct import pack
import threading
from base64 import b64encode, b64decode
import platform
import random
from crypto import Cryptography
crypt = Cryptography()

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
from enums import *

# ===========[ DeepRiver_Server ]===========
class DeepRiver_Server:
    __version__ = "0.0.1"

    def __init__(self, config=None):
        self._set_default_config()
        if config:
            self._parse_config(config)
        
        self._clients = []
    
    def start(self):
        self._log("MAIN", f"DeepRiver Server {self.__version__}")
        self._log("MAIN", f"Starting server...")
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.bind((self._host, self._port))
        self._server.listen(5)
        self._log("MAIN", f"Server started, listener active on {self._host}:{self._port}")
        while True:
            client, addr = self._server.accept()
            addr = addr[0]
            port = addr[1]
            self._log("MAIN", f"Connection recieved from {addr}")

            #TODO: Create ban check

            threading.Thread(target=self._connection_init, args=(client,addr,port)).start()
            self._log("MAIN", f"Pre-connection thread spawned for {addr}")

    
    def _connection_init(self, client: socket.socket, addr, port):
        ident = threading.get_ident()
        self._log(f"PRECONNECTION:{ident}", f"Pre-connection thread {ident} started ({addr}:{port})")
        client.settimeout(self._connection_init_timeout if self._connection_init_timeout != 0 else None)

        #FIXME: Shorten this
        if self._verbosity == 0:
            payload = f"DeepRiver {self.__version__}"
        else:
            payload = f"DeepRiver {self.__version__} {platform.platform()}"
        
        payload = b64encode(payload.encode())

        if self._type == ServerType.PUBLIC or self._type == ServerType.SEMIPRIVATE:
            payload += b' '
            payload += b64encode(self._public_key)
        client.send(self._build_packet(PacketHeader.BANNER, payload))
        try:
            data = self._parse_packet(client.recv(4096))
        except Exception as e:
            self._disconnect_client(client)
            self._log(f"PRECONNECTION:{ident}", f"Client timed out. Closing thread...")
            return

        if data['header'] != PacketHeader.PUBLIC_KEY:
            client.send(self._build_packet(PacketHeader.ERROR, ServerErrors.INVALID_PACKET_HEADER))
            self._disconnect_client(client)
            self._log(f"PRECONNECTION:{ident}", f"Recieved a wrong header. Closing thread...")
            return

        client_public_key = data['payload']

        chal_int = random.randint(10000, 99999)
        try:
            chal_enc = crypt.rsa_encrypt(client_public_key, str(chal_int))
        except:
            client.send(self._build_packet(PacketHeader.ERROR, ServerErrors.INVALID_PUBLIC_KEY))
            self._disconnect_client(client)
            self._log(f"PRECONNECTION:{ident}", f"Recieved invalid client public key. Closing thread...")
            return
        client.send(self._build_packet(PacketHeader.CHAL, chal_enc))

        try:
            data = self._parse_packet(client.recv(4096))
        except socket.error:
            self._disconnect_client(client)
            self._log(f"PRECONNECTION:{ident}", f"Client timed out. Closing thread...")
            return
        except Exception as e:
            self._disconnect_client(client)
            self._log(f"PRECONNECTION:{ident}", f"Urecognized error: {e}")
            return
        
        if data['header'] != PacketHeader.CHAL:
            client.send(self._build_packet(PacketHeader.ERROR, ServerErrors.INVALID_PACKET_HEADER))
            self._disconnect_client(client)
            self._log(f"PRECONNECTION:{ident}", f"Recieved a wrong header. Closing thread...")
            return
        try:
            client_chal_int = int(crypt.rsa_decrypt(self._private_key, data['payload']))
            if client_chal_int != chal_int+1:
                client.send(self._build_packet(PacketHeader.ERROR, ServerErrors.CHALLENGE_FAILED))
                self._disconnect_client(client)
                self._log(f"PRECONNECTION:{ident}", f"Client failed the challenge. Closing thread...")
                return
        except:
            client.send(self._build_packet(PacketHeader.ERROR, ServerErrors.CHALLENGE_FAILED))
            self._disconnect_client(client)
            self._log(f"PRECONNECTION:{ident}", f"Client failed the challenge. Closing thread...")
            return
        
        client_connpass = crypt.generate_aes_key()
        client.send(self._build_packet(PacketHeader.CONNPASS, crypt.rsa_encrypt(client_public_key, b64encode(client_connpass))))

        chal_int = random.randint(10000, 99999)

        client.send(self._build_packet_secure(client_connpass, PacketHeader.CHAL, str(chal_int)))

        try:
            data = self._parse_packet_secure(client_connpass, client.recv(4096))
            if data['header'] != PacketHeader.CHAL:
                client.send(self._build_packet(PacketHeader.ERROR, ServerErrors.INVALID_PACKET_HEADER))
                self._disconnect_client(client)
                self._log(f"PRECONNECTION:{ident}", f"Recieved a wrong header. Closing thread...")
                return
        except:
            self._disconnect_client(client)
            self._log(f"PRECONNECTION:{ident}", f"Client sent malformed challenge. Closing thread...")
            return
        
        try:
            client_chal_int = data['payload']
            if int(client_chal_int) != chal_int+1:
                client.send(self._build_packet(PacketHeader.ERROR, ServerErrors.CHALLENGE_FAILED))
                self._disconnect_client(client)
                self._log(f"PRECONNECTION:{ident}", f"Client failed the challenge. Closing thread...")
                return
        except:
            client.send(self._build_packet(PacketHeader.ERROR, ServerErrors.CHALLENGE_FAILED))
            self._disconnect_client(client)
            self._log(f"PRECONNECTION:{ident}", f"Client failed the challenge. Closing thread...")

        client.send(self._build_packet_secure(client_connpass, PacketHeader.SUCCESS, "DONE"))
        
        self._disconnect_client(client)
        self._log(f"PRECONNECTION:{ident}", f"Client connected! Closing thread...")
        return
        
        client.send(self._build_packet_secure(client_connpass, PacketHeader.NICKNAME, b64encode(b"NICKNAME")))
        try:
            data = self._parse_packet_secure(client_connpass, client.recv(4096))
            if data['header'] != PacketHeader.NICKNAME:
                client.send(self._build_packet(PacketHeader.ERROR, b64encode(ServerErrors.INVALID_PACKET_HEADER)))
                self._disconnect_client(client)
                self._log(f"PRECONNECTION:{ident}", f"Recieved a wrong header. Closing thread...")
                return
        except:
            self._disconnect_client(client)
            self._log(f"PRECONNECTION:{ident}", f"Client sent malformed challenge. Closing thread...")
            return



        #self._disconnect_client(client)
        #self._log(f"PRECONNECTION:{ident}", f"Client connected! Closing thread...")
        return

    def _connection_handler(self, client: socket.socket, host: tuple, nick: str):
        pass

    def _log(self, name, message, mtype="info"):
        print(f"[*] ({name}) >> {message}")

    def _client_loop(self, client, addr):
        pass
    
    def _disconnect_client(self, client: socket.socket):
        client.close()

    def _disconnect_all_clients(self):
        pass
    
    def _build_packet(self, header: PacketHeader, payload) -> bytes:
        return header.encode() + b' ' + b64encode(payload.encode() if type(payload) != bytes else payload)
    
    def _build_packet_secure(self, conpass, header: PacketHeader, payload):
        enc = crypt.aes_encrypt(conpass, self._build_packet(header, payload))
        return b64encode(enc['ciphertext'] + b' ' + enc['nonce'])

    def _parse_packet(self, packet: bytes):
        p = packet.decode().split(' ')
        return {
            'header': p[0],
            'payload': b64decode(p[1])
        }
    
    def _parse_packet_secure(self, connpass, packet: bytes):
        p_enc = b64decode(packet).decode().split(' ')
        p_dec = crypt.aes_decrypt(connpass,b64decode(p_enc[0]),b64decode(p_enc[1])).decode().split()
        return {
            'header': p_dec[0],
            'payload': b64decode(p_dec[1]).decode()
        }

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
        #FIXME: Create so that existing config goes first and then gets set a default value IF not present in config.

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

l = DeepRiver_Server()
l.start()
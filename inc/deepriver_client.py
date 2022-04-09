import socket
from enums import *
from base64 import b64encode as b64e, b64decode as b64d
import os
from crypto import Cryptography
crypt = Cryptography()

class DeepRiver_Client:
    def __init__(self, config=None):
        self.is_connected = False
        self.server_info = {
            'host': None,
            'port': None,
            'public_key': None
        }

        self.client_info = {
            "public_key": None,
            "private_key": None,
            "connpass": None,
            "nickname": None
        }
        self._s = None

        self.set_log_callback(self._default_log)

    def connect(self, host: str, port: int, nickname: str, password = None):
        self.client_info['nickname'] = nickname

        self._s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._s.connect((host, port))

        if (banner := self._get_server_banner()) == False:
            self._log("Connection terminated")
            self._s.close()
            return False
        
        if self.server_info['public_key'] == None:
            if not os.path.isfile(f"servers/{host}.{self.server_info[port]}.server.pub"):
                self._log("Public key not found")
                self._s.close()
                return False
        else:
            if not os.path.isdir("servers"):
                os.mkdir("servers")
            with open(f"servers/{host}.{port}.server.pub", 'wb') as f:
                f.write(self.server_info['public_key'].encode())

        if not os.path.isfile(f"servers/{host}.{port}.client.pub"):
            keys = crypt.generate_key_pair()
            with open(f"servers/{host}.{port}.client.pub", 'wb') as f:
                self.client_info['public_key'] = keys[0]
                f.write(keys[0])
            with open(f"servers/{host}.{port}.client.priv", 'wb') as f:
                self.client_info['private_key'] = keys[1]
                f.write(keys[1])
        else:
            with open(f"servers/{host}.{port}.client.pub", 'rb') as f:
                self.client_info['public_key'] = f.read()
            with open(f"servers/{host}.{port}.client.priv", 'rb') as f:
                self.client_info['private_key'] = f.read()
        
        self._s.send(self._build_packet(PacketHeader.PUBLIC_KEY, self.client_info['public_key']))

        data = self._parse_packet(self._s.recv(4096))
        if data['header'] != PacketHeader.CHAL:
            if data['header'] == PacketHeader.ERROR:
                self._log(f"Error: {data['payload']}")
            else:
                self._log(f"Unknown packet: {data['header']}")
            self._s.close()
            return False
        
        chal_decrypted = int(crypt.rsa_decrypt(self.client_info['private_key'], data['payload']).decode())
        chal_response = crypt.rsa_encrypt(self.server_info['public_key'], str(chal_decrypted+1))
        self._s.send(self._build_packet(PacketHeader.CHAL, chal_response))

        data = self._parse_packet(self._s.recv(4096))
        if data['header'] != PacketHeader.CONNPASS:
            if data['header'] == PacketHeader.ERROR:
                self._log(f"Error: {data['payload']}")
            else:
                self._log(f"Unknown packet: {data['header']}")
            self._s.close()
            return False

        self.client_info['connpass'] = b64d(crypt.rsa_decrypt(self.client_info['private_key'], data['payload']))
        
        data = self._parse_packet_secure(self.client_info['connpass'], self._s.recv(4096))
        if data['header'] != PacketHeader.CHAL:
            if data['header'] == PacketHeader.ERROR:
                self._log(f"Error: {data['payload']}")
            else:
                self._log(f"Unknown packet: {data['header']}")
            self._s.close()
            return False

        chal_decrypted = int(data['payload'])
        self._s.send(self._build_packet_secure(self.client_info['connpass'], PacketHeader.CHAL, str(chal_decrypted+1)))
        print(self._parse_packet_secure(self.client_info['connpass'], self._s.recv(4096)))
        self._s.close()
        print("Done")

    def disconnect(self):
        pass

    def _load_server_public_key(self):
        pass

    def _get_server_banner(self):
        data = self._s.recv(4096).decode()
        if len(dspl := data.split(' ')) < 2:
            self._log("Invalid banner: Malformed packet. Dump:")
            self._log(data.decode())
            return False

        if dspl[0] != PacketHeader.BANNER:
            self._log(f"Invalid banner: Expected BANNER header, got {dspl[0]}")
            return False
        
        payload = b64d(dspl[1].encode()).decode()
        if len(pspl := payload.split(' ')) == 1:
            return b64d(pspl[0].encode()).decode()
        else:
            self.server_info['public_key'] = b64d(pspl[1].encode()).decode()
            return pspl[0]

    def _establish_conpass(self):
        pass
    
    def _default_log(self, message):
        print(message)

    def _log(self, message):
        self._f_log(message)

    def set_log_callback(self, callback):
        self._f_log = callback

    def _build_packet(self, header: PacketHeader, payload):
        return header.encode() + b' ' + b64e(payload.encode() if type(payload) != bytes else payload)
    
    def _build_packet_secure(self, conpass, header: PacketHeader, payload):
        enc = crypt.aes_encrypt(conpass, self._build_packet(header, payload))
        return b64e(enc['ciphertext'] + b' ' + enc['nonce'])

    def _parse_packet(self, packet: bytes):
        p = packet.decode().split(' ')
        return {
            'header': p[0],
            'payload': b64d(p[1])
        }
    
    def _parse_packet_secure(self, connpass, packet: bytes):
        p_enc = b64d(packet).decode().split(' ')

        p_dec = crypt.aes_decrypt(connpass,b64d(p_enc[0]),b64d(p_enc[1])).decode().split()
        return {
            'header': p_dec[0],
            'payload': b64d(p_dec[1]).decode()
        }

c = DeepRiver_Client()
c.connect("localhost", 10101, "asd")
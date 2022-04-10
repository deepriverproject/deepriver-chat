class ServerType:
    PUBLIC = "public"
    SEMIPUBLIC = "semipublic"
    SEMIPRIVATE = "semiprivate"
    PRIVATE = "private"

class PacketHeader:
    ERROR = "ERROR"
    STOP = "STOP"
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
    NICKNAME = "NICKNAME"

class ServerErrors:
    INVALID_PACKET_HEADER = "INVALID_PACKET_HEADER"
    INVALID_PUBLIC_KEY = "INVALID_PUBLIC_KEY"
    INVALID_NICKNAME = "INVALID_NICKNAME"
    NICKNAME_TAKEN = "NICKNAME_TAKEN"
    CHALLENGE_FAILED = "CHALLENGE_FAILED"
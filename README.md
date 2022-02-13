# Connection modes
- Public (no-password, public-key-banner)
    - Connection does not require a password for authentication and the public key is sent with the banner.
- Semi-Public (no-password, no-public-key-banner)
    - Connection does not require a password for authentication but the public key is not sent out in a banner. Instead, the public key needs to already be in client's possesion.
- Semi-Private (password, public-key-banner)
    - Connection requires a password but the public key is sent with the banner.
- Private (password, no-public-key-banner)
    - Connection requires a passwords and the public key needs to be in possesion of the client prior to connecting.

# Legend
- C = Client
- CName = Client Nickname
- S = Server
- B = Server Banner
- SPub = Server Public Key
- CPub = Client Public Key
- Chal = Challenge integer to check key integrity
- SPass = Server Passwords
- ConnPass = Connection cipher Key
- b64 = Base64 Encoding and Decoding Function

# Packet contruction

DeepRiver packet construction follows a simple template:

b64(`<HEADER> <PAYLOAD>`)

Before establishing ConnPass, the header part will be sent trough cleartext while the payload will be sent using CPub, SPub or ConnPass. This is to ensure readability in case of encryption errors. After ConnPass has been sucessfully initialized, both the `HEADER` and `PAYLOAD` will be encrypted.

Payload is the part of the packet where either the content or the description associated with the header lays. The payload will always be encoded using Base64, but will not always be encrypted. The payload will not be encrypted in case of errors before the ConnPass gets initialized. The error payload will not contain any sensitive content - only parts that the client needs to know about the error. After ConnPass is initialized, the payload will be encrypted using ConnPass.

NOTE: As previously shown, the combination of the header and the payload will be encoded using Base64 even if the payload has already been encoded.

# Diagram (Public)

```
C -> TCP_SYN -> S
C <- TCP_SYN_ACK <- S
C -> TCP_ACK -> S

C <- B(Info,SPub) <- S
C -> SPub(CPub) -> S
C <- CPub(Chal) <- S
C -> SPub(Chal + 1) -> S
C <- CPub(ConnPass) <- S
C <- ConnPass(Chal) <- S
C -> ConnPass(Chal + 1) -> S
C <- ConnPass("DONE") <- S
```

# Diagram (Semi-Public)

```
C -> TCP_SYN -> S
C <- TCP_SYN_ACK <- S
C -> TCP_ACK -> S

C <- B(Info) <- S
C -> SPub(CPub) -> S
C <- CPub(Chal) <- S
C -> SPub(Chal + 1) -> S
C <- CPub(ConnPass) <- S
C <- ConnPass(Chal) <- S
C -> ConnPass(Chal + 1) -> S
C <- ConnPass("DONE") <- S
```

# Diagram (Semi-Private)

```
C -> TCP_SYN -> S
C <- TCP_SYN_ACK <- S
C -> TCP_ACK -> S

C <- B(Info,SPub) <- S
C -> SPub(CPub) -> S
C <- CPub(Chal) <- S
C -> SPub(Chal + 1) -> S
C <- CPub("PASS") <- S
C -> SPub(SPass) -> S
C <- CPub(ConnPass) <- S
C <- ConnPass(Chal) <- S
C -> ConnPass(Chal + 1) -> S
C <- ConnPass("DONE") <- S
```

# Diagram (Private)

```
C -> TCP_SYN -> S
C <- TCP_SYN_ACK <- S
C -> TCP_ACK -> S

C <- B(Info) <- S
C -> SPub(CPub) -> S
C <- CPub(Chal) <- S
C -> SPub(Chal + 1) -> S
C <- CPub("PASS") <- S
C -> SPub(SPass) -> S
C <- CPub(ConnPass) <- S
C <- ConnPass(Chal) <- S
C -> ConnPass(Chal + 1) -> S
C <- ConnPass("DONE") <- S
```

# Server headers

|Header|Description|
|------|-----------|
|ERROR | This header notates a failure of some operation. It could be caused either by the client providing an invalid request or a server-side issue. More information about the error will be sent trough the payload. The payload will be encrypted if the ConnPass is initiated. Else, the payload will be sent in cleartext.|
|SUCCESS| This header notates that some operation has been processed succesfully.|
|BANNER|This header notates that the payload of the packet will be the server banner. If a client sends a packet using this header, it will cause and error and the connection to abrupt.|
|PUBLIC_KEY|This header notates that the payload of the packet contains a public key.|
|CONNPASS|This header notates that the payload of the packet contains a ConnPass that is encrypted using the server public key.|
|CHAL|This header notates that the payload of the packet contains an encrypted challenge. If the server sends a packet using this header, client needs to respond with the same header and incremented and encrypted payload to complete the challenge.|
|MSG_NORMAL|This header notates that the payload of the packet is a message. It can either be a chat message or a command.|
|MSG_CLIENT|This header notates that the payload of the packet is a client-side message. This type of message will ususally be sent by the server to the client.|
|MSG_SRV_SUCCESS|This header notates that the payload of the packet is a server message that is usually sent when something successful happens. This type of message will usually be sent by the server.|
|MSG_SRV_FAIL|This header notates that the payload of the packet is a server message that is usually sent when something unsuccessful happens. This type of message will usually be sent by the server.|
|DISCONNECT|This header notates that the client wants to disconnect. In that case, the server starts a soft-disconnect process to peacefully detatch the client connection from the server.|

# Errors
WIP
import socket
import json

def SockSendFile(Socket, FilePath):
    with open(FilePath, "rb") as f:
        data = f.read()
        byte_data = bytes(data)
        Socket.send(byte_data)
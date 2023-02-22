import socket
import json


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client = "127.0.0.1"
port = 9000
sock.connect((client, port))
print("Connected")

msg = {"Command": "start", "File": "swag.exe"}
data = bytes(json.dumps(msg), 'utf-8')

sock.send(data)
print("sent data")

data = sock.recv(1024)
print(data)

with open("C:\\Users\\Cole\\Documents\\service.txt", "rb") as f:
    data = f.read()
    byte_data = bytes(data)
    sock.send(byte_data)



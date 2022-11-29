from pwn import * # pip install pwntools
import json
import codecs
from Crypto.Util.number import *

r = remote('localhost', 9917, level = 'debug')

def json_recv():
    line = r.recv(1024)
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.send(request)

def decoder(encoding : str , encoded_str : str ):
    decoded_str = ""

    if encoding == "base64":
        decoded_str =  base64.b64decode(encoded_str.encode()).decode()
    elif encoding == "hex":
            decoded_str = bytes.fromhex(encoded_str).decode()
    elif encoding == "rot13":
            decoded_str = codecs.decode( encoded_str , 'rot_13')
    elif encoding == "bigint":
            decoded_str = bytes.fromhex(encoded_str[2:]).decode()
    elif encoding == "utf-8":
            decoded_str = "".join([chr(b) for b in encoded_str])
    
    return decoded_str



while True:
    received = json_recv()
    if "flag" in received.keys():
        break

    print("Received type: ")
    print(received["type"])
    print("Received encoded value: ")
    print(received["emessage"])

    to_send = {
        "dmessage": decoder(received["type"] , received["emessage"])
    }
    json_send(to_send)
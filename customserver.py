#!/usr/bin/env python3

from pwn import *
from Crypto.Util.number import bytes_to_long
import base64
import codecs
import random   

import socket
import threading
import json

FLAG = "crypto{why_not_king}"
ENCODINGS = [
    "base64",
    "hex",
    "rot13",
    "bigint",
    "utf-8",
]
with open('/usr/share/dict/words') as f:
    WORDS = [line.strip().replace("'", "") for line in f.readlines()]

class EncrypterChallenge():
    def __init__(self):
        self.challenge_words = ""
        self.stage = 0
        self.exit = False

    def create_level(self):
        self.stage += 1
        self.challenge_words = "_".join(random.choices(WORDS, k=4))
        encoding = random.choice(ENCODINGS)

        if encoding == "base64":
            encoded = base64.b64encode(self.challenge_words.encode()).decode() # wow so encode
        elif encoding == "hex":
            encoded = self.challenge_words.encode().hex()
        elif encoding == "rot13":
            encoded = codecs.encode(self.challenge_words, 'rot_13')
        elif encoding == "bigint":
            encoded = hex(bytes_to_long(self.challenge_words.encode()))
        elif encoding == "utf-8":
            encoded = [ord(b) for b in self.challenge_words]

        return {"type": encoding, "emessage": encoded}

    def challenge(self, your_input):
        if self.stage == 0:
            return self.create_level()
        elif self.stage == 111:
            self.exit = True
            return {"flag": FLAG}

        if self.challenge_words == your_input["dmessage"]:
            return self.create_level()

        return {"error": "wrong answer"}

def json_recv(r):
    line = r.recv(1024)
    return json.loads(line.decode())

def json_send(r , hsh):
    request = json.dumps(hsh).encode()
    r.send(request)

def NewClientSocketHandler(cli , ip):
    banner = """[Crypto Challenge by th3h04x]\n"""

    try:
        # cli.send(banner.encode())

        ec = EncrypterChallenge()
        first_challenge = ec.challenge("")

        json_send(cli , first_challenge)
        response =  json_recv(cli)

        while not ec.exit:
            challenge = ec.challenge(response)

            json_send(cli , challenge)
            if "error" in challenge.keys():
                cli.close()
                break

            if ec.exit:
                cli.close()
                break

            response = json_recv(cli)
    except:
        cli.send("\n{ error : 'expected json format' }\n".encode())
        cli.close()

def start_server(port : int):
    srvsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srvsocket.bind(('0.0.0.0', port))

    print("[+] Server Started on port : " , port)
    srvsocket.listen(500)

    while True:
        cli, ip = srvsocket.accept()
        threading._start_new_thread( NewClientSocketHandler, (cli, ip))
    
start_server(port=9917)

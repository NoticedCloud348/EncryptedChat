import socket
import ssl
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from threading import Thread

from time import sleep

from keys import generate_aes_key, generate_rsa_keys, export_public_key, import_public_key

class Server:
    def __init__(self):
        self.channels = {}
    
    def handler(self, addr, conn: ssl.SSLSocket):
        data = conn.recv(1024).decode()

        if data.split()[0] == 'C':
            print('Creating channel...')
            password = data.split()[1]
            while True:
                channel_id = os.urandom(10).hex()

                if channel_id not in self.channels:
                    break
            

            self.channels[channel_id] = {'password': password, 'host': [conn, addr], 'other': []}  
            conn.send(channel_id.encode())

            while True:
                if self.channels[channel_id]["other"] != []:
                    break
                
                sleep(1)
                
            conn.send(b"Other connected")

            while True:
                text = conn.recv(1024)
                self.channels[channel_id]['other'][0].send(text)
        else:
            if data in self.channels:
                conn.send(b"Y")

                data = conn.recv(1024).decode()

                if data.split()[0] == 'J':
                    channel_id = data.split()[1]
                
                    if channel_id in self.channels:
                        password = self.channels[channel_id]['password']

                        if data.split()[2] == password:
                            self.channels[channel_id]['other'] = [conn, addr]
                            conn.send(b"Y")

                            while True:
                                text = conn.recv(1024)
                                self.channels[channel_id]['host'][0].send(text)
    
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("localhost", 957))
        server_socket.listen(5)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=f"{os.getcwd()}/cert/cert.pem", keyfile=f"{os.getcwd()}/cert/key.pem")

        ssl_server_socket = context.wrap_socket(server_socket, server_side=True)

        print("Server listening in 0.0.0.0:957 (SSL)")

        while True:
            client_socket, addr = ssl_server_socket.accept()

            print(f"Connection entablished with: {addr}")
            Thread(target=self.handler, args=(addr, client_socket)).start()


server = Server()
server.start()
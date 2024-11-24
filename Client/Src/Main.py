import socket
import ssl
import os
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from threading import Thread

from time import sleep

from keys import generate_aes_key, generate_rsa_keys, export_public_key, import_public_key, decrypt_string, encrypt_string

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(f"{os.getcwd()}/cert/localhost-cert.pem")

client_socket = socket.create_connection(("localhost", 957))
ssl_client_socket = context.wrap_socket(client_socket, server_hostname="localhost")

conn = ssl_client_socket
def exchange(ssl_client_socket):
    aes_key = generate_aes_key()
    rsa_private_key, rsa_public_key = generate_rsa_keys()

    public_key = export_public_key(rsa_public_key)

    ssl_client_socket.sendall(public_key)

    other_rsa_public_key = ssl_client_socket.recv(2048)
    other_rsa_public_key = import_public_key(other_rsa_public_key)

    encrypted_aes_key = other_rsa_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    ssl_client_socket.sendall(encrypted_aes_key)

    other_aes_key = rsa_private_key.decrypt(
        ssl_client_socket.recv(2048),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key, other_aes_key, rsa_private_key, rsa_public_key

def recv(buffer, conn, key):
    encrypted_text = conn.recv(buffer).decode()
    decrypted_text = decrypt_string(encrypted_text, key)

    return decrypted_text

def send(text, conn, key):
    encrypted_text = encrypt_string(text, key)
    conn.sendall(encrypted_text.encode())

def chat(conn, key):
    while True:
        text = input("")

        if text.lower() == "/quit":
            send(text, conn, key)

            sleep(100)

            conn.close()
            break

        send(text, conn, key)

def receive(conn, key):
    while True:
        text = recv(1024, conn, key)

        if text.lower() == "/quit":
            break

        print(text)

while True:
    channel = input("Create a channel or join one(C/J)? ")
    if channel.upper() == "C":
        print("Creating channel...")
        password = input("Do you want to make your own password or generate one(M/G)? ")

        if password.upper() == "G":
            random_bytes = os.urandom(32)

            base64_password = base64.b64encode(random_bytes).decode('utf-8')
            base64_password = base64_password[:32]

            print(f"Generated password: {base64_password}")
            conn.send(b"C " + base64_password.encode())

            channel_id = conn.recv(1024).decode()

            print(f"Channel ID: {channel_id}")
            print("Waiting for other client connection...")
            print(conn.recv(1024))


            aes_key, other_aes_key, rsa_private_key, rsa_public_key = exchange(conn)
            Thread(target=receive, args=(conn, other_aes_key)).start()
            chat(conn, aes_key)
        else:
            password = input("Select a password: ")
            conn.send(b"C " + password.encode())
            channel_id = conn.recv(1024).decode()

            print(f"Channel ID: {channel_id}")
            print("Waiting for other client connection...")
            conn.recv(1024)
            
            aes_key, other_aes_key, rsa_private_key, rsa_public_key = exchange()
            Thread(target=receive, args=(conn, other_aes_key)).start()
            chat(conn, aes_key)
    
    elif channel.upper() == "J":
        channel_name = input("Enter channel id: ")
        conn.send(channel_name.encode())

        print(f"Joining channel: {channel_name}")
        exists = conn.recv(1024).decode()

        if exists.upper() == "Y":
            password = input("Enter password: ")
            conn.send(b"J " + channel_name.encode() + b" " + password.encode())
            print(b"J " + channel_name.encode() + b" " + password.encode())
            connected = conn.recv(1024).decode()

            if connected.upper() == "Y":
                print("Connected to channel")
                sleep(2)
                aes_key, other_aes_key, rsa_private_key, rsa_public_key = exchange(conn)
                Thread(target=receive, args=(conn, other_aes_key)).start()
                chat(conn, aes_key)
                
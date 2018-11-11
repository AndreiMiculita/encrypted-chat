#!/usr/bin/env python3
"""Async chat server"""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import re
import os


def generate_rsa_key():
    """Generates an RSA key"""
    secret_code = "Unguessable"
    key = RSA.generate(2048)
    encrypted_key = key.exportKey(passphrase=secret_code, pkcs=8, protection="scryptAndAES128-CBC")

    file_out = open("rsa_key.bin", "wb")
    file_out.write(encrypted_key)

    print(key.publickey().exportKey())


def get_public_rsa_key():
    """Read RSA key from file"""
    secret_code = "Unguessable"
    encoded_key = open("rsa_key.bin", "rb").read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)

    return key.publickey().exportKey()


def get_private_rsa_key():
    """Read RSA key from file"""
    secret_code = "Unguessable"
    encoded_key = open("rsa_key.bin", "rb").read()
    key = RSA.import_key(encoded_key, passphrase=secret_code)

    return key.exportKey()


def encrypt_data(data, client_address):
    """Encrypt data"""
    encrypted_data = bytearray(b'')
    print(f'encrypting pubk{client_address[0]}-{client_address[1]}')
    recipient_key = RSA.import_key(open(f'pubk{client_address[0]}-{client_address[1]}').read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_data += bytes(cipher_rsa.encrypt(session_key))

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    for x in (cipher_aes.nonce, tag, ciphertext):
        encrypted_data += bytes(x)

    return encrypted_data


def decrypt_msg(encrypted_data):
    """Decrypt message and return the decoded UTF8"""
    encrypted_data_bytes = bytearray(encrypted_data)
    secret_code = "Unguessable"
    encoded_key = open("rsa_key.bin", "rb").read()
    private_key = RSA.import_key(encoded_key, passphrase=secret_code)

    private_key_size = private_key.size_in_bytes()

    enc_session_key = bytes(encrypted_data_bytes[0:private_key_size])
    del encrypted_data_bytes[0:private_key_size]
    nonce = bytes(encrypted_data_bytes[0:16])
    del encrypted_data_bytes[0:16]
    tag = bytes(encrypted_data_bytes[0:16])
    del encrypted_data_bytes[0:16]
    ciphertext = bytes(encrypted_data_bytes)

    # Decrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return decrypted_data.decode("utf8")


def accept_client():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print(f"{client_address[0]}:{client_address[1]} connected. Sending public key")
        client.send(bytes(str(get_public_rsa_key()), "utf8"))
        client.send(bytes("Enter your username: ", "utf8"))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection."""

    encrypted_msg = client.recv(BUFSIZ)
    msg = decrypt_msg(encrypted_msg)
    print("Received public key %s" % msg)
    if msg.startswith("b'-----BEGIN PUBLIC KEY-----"):
        # Save public key to custom file
        file_name = f'pubk{addresses[client][0]}-{addresses[client][1]}'
        file_out = open(file_name, "w")
        file_out.write(msg[2:-1].replace("\\n", "\n"))
        file_out.close()
    # Receive, decrypt, store name
    get_username_thread = Thread(target=get_username, args=(client,))
    get_username_thread.start()
    get_username_thread.join()

    while True:
        encrypted_msg = client.recv(BUFSIZ)
        msg = decrypt_msg(encrypted_msg)
        if msg != "/quit":
            broadcast(msg, clients[client] + ": ")
        else:
            # if the client wants to quit
            os.remove(f'pubk{addresses[client][0]}-{addresses[client][1]}')
            client.close()
            leaver_name = clients[client]
            del clients[client]
            del addresses[client]
            del client
            broadcast("%s disconnected." % leaver_name)
            print("%s disconnected." % leaver_name)
            break


def get_username(client):
    name_ok = False
    while not name_ok:
        encrypted_msg = client.recv(BUFSIZ)
        msg = decrypt_msg(encrypted_msg)
        name = re.sub('[:\s]', '', msg[0:20])
        for n in clients:
            if name == clients[n]:
                welcome_message = '%s is already taken, enter another name:' % name
                encrypted_msg = encrypt_data(bytes(welcome_message, "utf8"), addresses[client])
                client.send(encrypted_msg)
                break
        else:
            welcome_message = 'Name set %s, type /quit to exit.' % name
            encrypted_msg = encrypt_data(bytes(welcome_message, "utf8"), addresses[client])
            client.send(encrypted_msg)

            broadcast("%s connected." % name)
            clients[client] = name
            print("hgeger")
            print(clients[client])
            name_ok = True


def broadcast(msg, prefix=""):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""

    for sock in clients:
        encrypted_msg = encrypt_data(bytes(prefix, "utf8") + bytes(msg.replace("\n", " "), "utf8"), addresses[sock])
        try:
            sock.send(encrypted_msg)
        except ConnectionResetError:
            print("connection to socket %s was reset" % socket)


clients = {}
addresses = {}

HOST = ''
PORT = 33000
BUFSIZ = 8192
ADDR = (HOST, PORT)

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    generate_rsa_key()
    print(get_public_rsa_key())
    SERVER.listen(5)
    print("No one connected.")
    ACCEPT_THREAD = Thread(target=accept_client)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
SERVER.close()

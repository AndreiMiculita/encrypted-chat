#!/usr/bin/env python3
"""Chat client"""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import tkinter
import re

from chatClient import message_widget

username = ""


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


def encrypt_data(data):
    """Encrypt data"""
    encrypted_data = bytearray(b'')

    recipient_key = RSA.import_key(open("publickey.pem").read())
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


def connect_to_server(event=None):
    """Connect to a chat server"""
    host = host_var.get()
    port = port_var.get()

    host_field.destroy()
    port_field.destroy()
    messages_frame.pack()

    if not port:
        port = 33000
    else:
        port = int(port)

    try:
        client_socket.connect((host, port))
        entry_field.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
        send_button.pack(side=tkinter.RIGHT, fill=tkinter.BOTH)
        top.protocol("WM_DELETE_WINDOW", on_closing)
        receive_thread = Thread(target=receive_msg)
        receive_thread.start()
    except ConnectionRefusedError:
        msg_list.insert(tkinter.END, "Connection refused\n")


def send_msg(event=None):
    """Send message"""
    msg = my_msg.get()
    if msg != "":
        my_msg.set("")  # Clears input field.
        encrypted_msg = encrypt_data(bytes(msg, "utf8"))
        client_socket.send(encrypted_msg)
        if msg == "/quit":
            client_socket.close()
            top.quit()


def receive_msg():
    """Receive message asynchronously"""
    while True:
        try:
            msg = client_socket.recv(BUFSIZ)
            try:
                # Decrypt, display
                decrypted_msg = decrypt_msg(msg)
                name_search = re.search('^Name set (.*), type /quit to exit.', decrypted_msg,
                                        re.IGNORECASE)

                if name_search:
                    global local_username
                    local_username = name_search.group(1)
                msg_list.insert(tkinter.END, "%s\n" % decrypted_msg)
                msg_list.highlight_pattern("^\\S+:", "username_style")
                msg_list.highlight_pattern(f'^{local_username}:', "local_username_style")
                msg_list.see(tkinter.END)
            except ValueError:  # if msg is plaintext
                msg = msg.decode("utf8")
                if msg.startswith("b'-----BEGIN PUBLIC KEY-----"):
                    # Save public key to file
                    file_out = open("publickey.pem", "w")
                    file_out.write(msg[2:-1].replace("\\n", "\n"))
                    file_out.close()
                    print("key received, sending own key ", msg)
                    encrypted_msg = encrypt_data(bytes(str(get_public_rsa_key()), "utf8"))
                    client_socket.send(encrypted_msg)
                else:
                    if msg.startswith("Enter your username: "):
                        msg_list.insert(tkinter.END, "%s\n" % msg)
        except OSError:  # Possibly client has left the chat.
            break


def on_closing(event=None):
    """Tell the server that the client is disconnecting"""
    my_msg.set("/quit")
    send_msg()


def character_limit(entry_text):
    if len(entry_text.get()) > 0:
        entry_text.set(entry_text.get()[:500])


def clear_entry(event, entry):
    """Clear placeholder text, then don't clear any future text"""
    entry.delete(0, tkinter.END)
    entry.unbind("<FocusIn>")


top = tkinter.Tk()
top.title("Chat")

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("Type your messages here.")

my_msg.trace("w", lambda *args: character_limit(my_msg))
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
msg_list = message_widget.CustomText(messages_frame, height=30, yscrollcommand=scrollbar.set,
                                     wrap=tkinter.WORD)
msg_list.tag_configure("username_style", foreground="blue")
msg_list.tag_configure("local_username_style", foreground="red")
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()

entry_field = tkinter.Entry(top, width=90, textvariable=my_msg)
entry_field.bind("<Return>", send_msg)
entry_field.bind("<FocusIn>", lambda event: clear_entry(event, entry_field))
send_button = tkinter.Button(top, width=10, text="Send", command=send_msg)

host_var = tkinter.StringVar()
port_var = tkinter.StringVar()

host_var.set("Host")
port_var.set("Port")

host_field = tkinter.Entry(top, textvariable=host_var)
host_field.bind("<FocusIn>", lambda event: clear_entry(event, host_field))
port_field = tkinter.Entry(top, textvariable=port_var)
port_field.bind("<FocusIn>", lambda event: clear_entry(event, port_field))
port_field.bind("<Return>", connect_to_server)

host_field.pack()
port_field.pack()

# main

BUFSIZ = 8192
client_socket = socket(AF_INET, SOCK_STREAM)
generate_rsa_key()
print(get_public_rsa_key())
tkinter.mainloop()

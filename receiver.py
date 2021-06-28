import sys
import socket
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from datetime import datetime

BUFFER_SIZE = 8192  # defining the buffer size of the sockets


def build_k(password, salt):
    """
    Given a password and salt, build the symmetric key k
    """
    salt_bytes = salt.encode()
    password_bytes = password.encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt_bytes,
                     iterations=100000)

    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    f = Fernet(key)
    return f


def decrypt_message(k, msg):
    """
    Given a key and a message - decrypts the message using the key and returns the decrypted message
    """
    p = k.decrypt(msg)
    p_decoded = p.decode()
    return p_decoded


def main():
    password = sys.argv[1]
    salt = sys.argv[2]
    k = build_k(password, salt)

    receiver_ip = '0.0.0.0'
    receiver_port = int(sys.argv[3])
    receiver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Defining a socket in order to connect to listen to clients
    receiver.bind((receiver_ip, receiver_port))
    receiver.listen()

    while True:
        # Opening a socket to the client
        client_socket, client_address = receiver.accept()
        # Receiving the user's request
        data = client_socket.recv(BUFFER_SIZE)
        now = datetime.now()
        dt_string = now.strftime("%H:%M:%S")  # H:M:S
        message = decrypt_message(k, data)

        print(message + " " + dt_string)

        # Close the socket after one request
        client_socket.close()


if __name__ == "__main__":
    main()
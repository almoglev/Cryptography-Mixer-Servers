import sys
import socket
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import threading

ROUND_TIME = 60


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


def encrypt_message(k, msg):
    """
    Given a message and a key - encrypts the message using the key and reutnrs the encrypted message
    """
    msg_bytes = msg.encode()

    c = k.encrypt(msg_bytes)

    return c


def build_layer(pk, ip, port, c):
    """
    Given an ip and port of the destination, the content of the message and the pk - encrypts the concatenation of
    ip port content, encrypts and returns it
    """
    content = ip + port + c
    layer = pk.encrypt(content, padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                     algorithm=hashes.SHA256(),
                                                     label=None))
    return layer


def get_ip_port_desired_format(dest_ip, dest_port):
    """
    Parses the input in order to return the ip and port in the desired format
    """
    dest_ip_octates = dest_ip.split(".")
    dest_ip_octates_int = [int(dest_ip_octate) for dest_ip_octate in dest_ip_octates]
    dest_ip_desired_format = bytes(dest_ip_octates_int)
    dest_port_int = int(dest_port)
    dest_port_desired_format = dest_port_int.to_bytes(length=2, byteorder="big")

    return dest_ip_desired_format, dest_port_desired_format


def get_params(line):
    """
    Parses the params of a line describing a message, returns the params
    """
    line = line.strip("\n")
    params = line.split(" ")

    msg = params[0]
    path = params[1].split(",")
    round = params[2]
    password = params[3]
    salt = params[4]
    dest_ip = params[5]
    dest_port = params[6]

    return msg, path, round, password, salt, dest_ip, dest_port


def build_encrypted_message(msg, path, round, password, salt, dest_ip, dest_port):
    """
    Given the parameters describing the message - builds the layered encrypted message and returns it
    """
    k = build_k(password, salt)
    c = encrypt_message(k, msg)

    dest_ip_desired_format, dest_port_desired_format = get_ip_port_desired_format(dest_ip, dest_port)

    with open("ips.txt") as ips_handler:
        ip_port_lines = ips_handler.readlines()

    prev_layer = c
    # for each mix server in the path, builds the encrypted level of the message according to the matching pem file
    for p in reversed(path):
        pem_file = "pk" + str(p) + ".pem"
        with open(pem_file, 'rb') as f:
            pem_file_data = f.read()
            pk = serialization.load_pem_public_key(pem_file_data,
                                                   backend=default_backend())

        layer = build_layer(pk, dest_ip_desired_format, dest_port_desired_format, prev_layer)
        prev_layer = layer

        ip_port_line = ip_port_lines[int(p) - 1]
        ip_port_line = ip_port_line.strip("\n")
        ip_port_list = ip_port_line.split(" ")
        dest_ip = ip_port_list[0]
        dest_port = ip_port_list[1]
        dest_ip_desired_format, dest_port_desired_format = get_ip_port_desired_format(dest_ip, dest_port)

    return layer


def connect_to_first_path_server(server_id):
    """
    Connect to the first mix server in the path
    """
    with open("ips.txt") as ips_handler:
        ip_port_lines = ips_handler.readlines()

    server_line = ip_port_lines[int(server_id) - 1]
    server_line = server_line.strip("\n")
    server_details = server_line.split(" ")
    server_ip = server_details[0]
    server_port = int(server_details[1])

    server = [server_ip, server_port]

    # Defining a socket in order to connect to the server
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server[0], server[1]))
        return s
    except Exception as e:
        print(str(e))


def handle_message_line(line):
    """
    Gets a line describing a message, parses the relevant argument, encrypts the message accordingly and sends the
    message
    """
    msg, path, round, password, salt, dest_ip, dest_port = get_params(line)

    socket = connect_to_first_path_server(path[0])
    encrypted_message = build_encrypted_message(msg, path, round, password, salt, dest_ip, dest_port)
    socket.send(encrypted_message)

    return encrypted_message


def build_round_dict(file_name):
    """
    Given a messages file - loads the message into a dictionary where the keys are the round number and the values are
    lists of lines from the file, describing messages to be sent in that round. Returns the round dictionary
    """
    round_dict = {}
    with open(file_name) as handler:
        lines = handler.readlines()
        for line in lines:
            line = line.strip("\n")
            params = line.split(" ")
            round = int(params[2])

            if round not in round_dict.keys():
                round_dict[round] = []
            round_dict[round].append(line)
    round_keys = list(round_dict.keys())

    for i in range(max(round_keys)):
        if i not in round_dict:
            round_dict[i] = []
    return round_dict


def send_round_messages(round_dict, round_key):
    """
    Sends the messages of this round
    """
    rounds_messages = round_dict[round_key]
    for message in rounds_messages:
        handle_message_line(message)


def main():
    file_msg_num = sys.argv[1]
    file_name = "messages" + str(file_msg_num) + ".txt"

    # key is int index indicating the round number,
    # value is list of messages to be sent in this round
    round_dict = build_round_dict(file_name)
    rounds = list(round_dict.keys())
    rounds.sort()

    time_to_wait = 5
    for round_key in rounds:
        threading.Timer(time_to_wait, send_round_messages, args=(round_dict, round_key)).start()
        time_to_wait += ROUND_TIME


if __name__ == "__main__":
    main()

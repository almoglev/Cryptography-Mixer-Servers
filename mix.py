import socket
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from threading import Timer, Lock
import random
from datetime import datetime, timedelta

# defining global program variables
ROUND_TIME = 60
BUFFER_SIZE = 8192
mutex = Lock()

messages_list = []
temp_messages_list = []
start_time = None


def parse_message_details(message):
    """
    Given a message, parses and return the ip and port of the next server in the loop (or of the receiver) and the
    message's content
    """
    next_server_ip = str(message[0]) + "." + str(message[1]) + "." + str(message[2]) + "." + str(message[3])
    next_server_port = int.from_bytes(message[4:6], byteorder='big')
    message_content = message[6:]

    return next_server_ip, next_server_port, message_content


def decrypt_message(data, server_number):
    """
    Given a decrypted message and a server number, decrypts the message using the relevant pem file
    and returns the decrypted message
    """
    sk_file = "sk" + str(server_number) + ".pem"
    with open(sk_file, 'rb') as f:
        sk_file_data = f.read()
        sk = serialization.load_pem_private_key(sk_file_data,
                                                backend=default_backend(), password=None)
    message = sk.decrypt(data, padding=padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                    algorithm=hashes.SHA256(),
                                                    label=None))
    return message


def connect_to_next(server_ip, server_port):
    """
    Given an ip and port - defines a socket in order to connect to the server, and returns the created socket
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((server_ip, server_port))
        return s
    except Exception as e:
        print(str(e))


def send_round_messages():
    """
    Sends the messages of this round
    """
    global messages_list
    global start_time

    # locks the mutes in order to avoid messages getting into the messages list which causes messages being sent in the
    # wrong round
    mutex.acquire()

    random.shuffle(messages_list)  # shuffles the messages

    # sends all the messages
    while len(messages_list) > 0:
        message = messages_list.pop(0)
        next_server_ip = message[0]
        next_server_port = message[1]
        message_content = message[2]
        next_socket = connect_to_next(next_server_ip, next_server_port)
        next_socket.send(message_content)

    # adds messages that arrived during the sent time - to the message list
    while len(temp_messages_list) > 0:
        messages_list.append(temp_messages_list.pop())

    mutex.release()  # releases the mutex to allow messages to be added to the message list

    if start_time is not None:
        start_time += timedelta(seconds=ROUND_TIME)

    Timer(ROUND_TIME, send_round_messages, args=()).start()  # schedules sending the messages of the next round


def main():
    global messages_list
    global temp_messages_list
    global start_time

    # Defining a socket in order to connect to listen to clients
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_number = int(sys.argv[1])
    with open("ips.txt") as ips_handler:
        lines = ips_handler.readlines()
    relevant_line = lines[server_number - 1].split(" ")
    server_ip = relevant_line[0]
    server_port = int(relevant_line[1])

    server.bind((server_ip, server_port))
    server.listen()

    Timer(ROUND_TIME, send_round_messages, args=()).start() # schedules sending the messages of the first round

    # receives new messages
    while True:
        # Accepting client
        client_socket, client_address = server.accept()
        data = client_socket.recv(BUFFER_SIZE)
        message = decrypt_message(data, server_number)

        now = datetime.now()
        if start_time is None:
            start_time = now

        next_server_ip, next_server_port, message_content = parse_message_details(message)

        mutex.acquire()  # tries to get the mutex in order to add a message to the messages list
        if start_time + timedelta(seconds=(ROUND_TIME - 1)) >= now:
            messages_list.append([next_server_ip, next_server_port, message_content])
        else:
            temp_messages_list.append([next_server_ip, next_server_port, message_content])
        mutex.release()  # releases the mutex upon finishing adding the message to the message list

        client_socket.close()  # Close the socket after one request.


if __name__ == "__main__":
    main()

import socket
import threading
from colorama import Fore, Style
from random import randint
from time import sleep
import sys
import requests


username = input('Type your name: ')


class Peers:
    peers = ['127.0.0.1']


def get_ip():
    try:
        raw = requests.get('https://api.duckduckgo.com/?q=ip&format=json')
        answer = raw.json()["Answer"].split()[4]
    except Exception as error:
        print(f'Couldn\'t retrieve IP address because... {error}')
    else:
        return answer


class Server:
    connections = []
    peers = []

    def __init__(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.host = '0.0.0.0'
        self.port = 9998
        sock.bind((self.host, self.port))
        print(Fore.LIGHTGREEN_EX, Style.BRIGHT + 'running server on ', self.host, self.port)
        sock.listen(2)
        while True:
            c, a = sock.accept()
            trd0 = threading.Thread(target=self.handler, args=(c, a))
            trd0.daemon = True
            trd0.start()
            self.connections.append(c)
            self.peers.append(a[0])
            print(Fore.LIGHTGREEN_EX, Style.BRIGHT + str(a[0]) + ':' + str(a[1]), 'connected')
            self.send_peers()

    def handler(self, conn, addr):
        while True:
            data = conn.recv(1024)
            for connection in self.connections:
                if conn == connection:
                    pass
                else:
                    connection.send(data)
            if not data:
                print(Fore.LIGHTGREEN_EX, Style.BRIGHT + str(addr[0]) + ':' + str(addr[1]), 'disconnected')
                self.peers.remove(addr[0])
                self.connections.remove(conn)
                conn.close()
                self.send_peers()
                break

    def send_peers(self):
        p = ''
        for pee in self.peers:
            p = p + pee + ','

        for conn in self.connections:
            conn.send(b'p'+bytes(p, 'utf-8'))


class Client:

    @staticmethod
    def send(sock, name, join=None):
        if join is None:
            try:
                while True:
                    msg = input()
                    sock.send(f'<{name}>: {msg}'.encode('utf-8'))
            except KeyboardInterrupt:
                sock.send(f'{name} disconnected')
                sys.exit(0)
        elif join is not None:
            sock.send(f'{name} connected'.encode('utf-8'))

    def __init__(self, address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((address, 9998))
        self.send(sock, username, join=True)
        print(Fore.LIGHTGREEN_EX, Style.BRIGHT + 'connected')
        trd1 = threading.Thread(target=self.send, args=(sock, username,))
        trd1.daemon = True
        trd1.start()

        while True:
            data = sock.recv(1024)
            if not data:
                break
            elif data[0:1] == b'p':
                self.update_peers(data[1:])
            else:
                print(Fore.LIGHTGREEN_EX, Style.BRIGHT + data.decode('utf-8'))

    @staticmethod
    def update_peers(pee):
        Peers.peers = str(pee, 'utf-8').split(',')[:-1]
# if len(argv) > 1:
#     client = Client()
# else:
#     server = Server()


while True:
    try:
        print('Trying to connect...')
        sleep(randint(1, 5))
        for peer in Peers.peers:
            try:
                client = Client(peer)
            except KeyboardInterrupt:
                print('Exiting...')
                sys.exit(0)
            except Exception as e:
                print(e)
                pass
            if randint(1, 10) == 1:
                try:
                    print('Failed to connect, running server...')
                    server = Server()
                except Exception as e:
                    print(f'Couldn\'t start the server because...{e}')

    except KeyboardInterrupt:
        print('Exiting...')
        sys.exit(0)

import socket
import stun
import threading
import sys

name = input('Type your name: ')

source_ip = '0.0.0.0'
source_port = 8547


class UDPClient:

    def __init__(self, ip, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('0.0.0.0', source_port))
        nat_type, nat = stun.get_nat_type(self.sock, source_ip, source_port, stun_host='stun.l.google.com', stun_port=19302)
        self.external_ip = nat['ExternalIP']
        self.external_port = nat['ExternalPort']
        self.message = f'{name} connected'.encode()
        self.remote = (ip, int(port))
        # creating thread
        trd0 = threading.Thread(target=self.handler)
        trd0.daemon = True
        trd0.start()
        while True:
            data, server = self.sock.recvfrom(1024)
            print(f'<{server}>: {data.decode()}')

    def handler(self):
        try:
            self.sock.sendto(f'{name} connected'.encode(), self.remote)
        except Exception as e:
            print(e)
        try:
            while True:
                msg = input('> ')
                self.sock.sendto(msg.encode(), self.remote)
        except Exception as e:
            print(f'closing socket because {e}')
            self.sock.sendto(f'{name} disconnected'.encode(), self.remote)
            self.sock.close()
            sys.exit(0)


remote_ip, remote_port = input('Your participant\'s address: ').split(':')
udp = UDPClient(remote_ip, remote_port)

# class UDPServer:
#
#     def __init__(self):
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     # Bind the socket to the port
#     server_address = ('localhost', 10000)
#     print('starting up on {} port {}'.format(*server_address))
#     sock.bind(server_address)
#     while True:
#         print('\nwaiting to receive message')
#         data, address = sock.recvfrom(4096)
#         print('received {} bytes from {}'.format(
#             len(data), address))
#         print(data)
#         if data:
#             sent = sock.sendto(data, address)
#             print('sent {} bytes back to {}'.format(
#                 sent, address))

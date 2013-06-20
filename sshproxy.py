import paramiko
import gevent
import gevent.server
import gevent.monkey
import socket
import struct
import select

SO_ORIGINAL_DST = 80

client = paramiko.SSHClient()
client.load_system_host_keys()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect('locvps.host.fqrouter.com', username='root', password='0eee2c4566')
transport = client.get_transport()

print(transport)
def handle(downstream_sock, address):
    dst_ip, dst_port = get_original_destination(downstream_sock)
    try:
        channel = transport.open_channel('direct-tcpip', (dst_ip, dst_port), address)
        print(channel)
        while True:
            r, w, x = select.select([downstream_sock, channel], [], [])
            if downstream_sock in r:
                data = downstream_sock.recv(1024)
                if len(data) == 0:
                    break
                channel.send(data)
            if channel in r:
                data = channel.recv(1024)
                if len(data) == 0:
                    break
                downstream_sock.send(data)
        channel.close()
    finally:
        downstream_sock.close()


def get_original_destination(sock):
    dst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    dst_port, dst_ip = struct.unpack("!2xH4s8x", dst)
    dst_ip = socket.inet_ntoa(dst_ip)
    return dst_ip, dst_port


gevent.monkey.patch_all()
server = gevent.server.StreamServer(('127.0.0.1', 12345), handle)
server.serve_forever()

client.close()
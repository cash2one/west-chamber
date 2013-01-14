import socket
import dpkt.ip

def main_loop(server_socket, raw_socket):
	while True:
		packet_bytes, from_ip = server_socket.recvfrom(4096)
		packet = dpkt.ip.IP(packet_bytes)
		dst = socket.inet_ntoa(packet.dst)
		print('%s:%s => %s:%s' % (socket.inet_ntoa(packet.src), packet.data.sport, dst, packet.data.dport))
		raw_socket.sendto(packet_bytes, (dst, 0))

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
	server_socket.bind(('0.0.0.0', 19840))
	raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	try:
		raw_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
		main_loop(server_socket, raw_socket)
	finally:
		raw_socket.close()
finally:
	server_socket.close()


import socket
import dpkt

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
sock.sendto(str(dpkt.dns.DNS(qd=[dpkt.dns.DNS.Q(name='proxy1.fqrouter.com', type=dpkt.dns.DNS_TXT)])), ('8.8.8.8', 53))
data, addr = sock.recvfrom(1024)
print(repr(dpkt.dns.DNS(data)))
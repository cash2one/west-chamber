import nfqueue
import socket
import dpkt

GATEWAY_IP = socket.inet_aton('x.x.x.x')
IMPERSONATOR_IP = 'y.y.y.y'
IMPERSONATOR_PORT = 19840

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

def smuggle_packet(dummy, payload):
    original_packet = payload.get_data()
    short_ttl_packet = dpkt.ip.IP(original_packet)
    short_ttl_packet.ttl = 3
    short_ttl_packet.sum = 0
    payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(short_ttl_packet), len(short_ttl_packet))
    src_modified_packet = dpkt.ip.IP(original_packet)
    src_modified_packet.src = GATEWAY_IP
    src_modified_packet.sum = 0
    src_modified_packet.tcp.sum = 0
    udp_socket.sendto(str(src_modified_packet), (IMPERSONATOR_IP, IMPERSONATOR_PORT))

q = nfqueue.queue()
q.open()
q.unbind(socket.AF_INET)
q.bind(socket.AF_INET)
q.set_callback(smuggle_packet)
q.create_queue(0)
q.try_run()
q.unbind(socket.AF_INET)

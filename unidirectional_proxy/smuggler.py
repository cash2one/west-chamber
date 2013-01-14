from netfilterqueue import NetfilterQueue
import subprocess
import signal
import traceback
import dpkt
import socket

JUST_SMUGGLE_SYN = False
GATEWAY_IP = socket.inet_aton('x.x.x.x')
IMPERSONATOR_IP = 'y.y.y.y'
IMPERSONATOR_PORT = 19840

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

def smuggle_packet(nfqueue_element):
    try:
        original_packet = nfqueue_element.get_payload()
        short_ttl_packet = dpkt.ip.IP(original_packet)
        short_ttl_packet.ttl = 3
        short_ttl_packet.sum = 0
        nfqueue_element.set_payload(str(short_ttl_packet))
        nfqueue_element.accept()
        src_modified_packet = dpkt.ip.IP(original_packet)
        src_modified_packet.src = GATEWAY_IP
        src_modified_packet.sum = 0
        src_modified_packet.tcp.sum = 0
        udp_socket.sendto(str(src_modified_packet), (IMPERSONATOR_IP, IMPERSONATOR_PORT))
    except:
        traceback.print_exc()
        nfqueue_element.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(0, smuggle_packet)

def clean_up(*args):
    # will be called twice, don't know why
    if JUST_SMUGGLE_SYN:
        subprocess.call(
            'iptables -D OUTPUT -p tcp -m owner --uid-owner stowaway --tcp-flags ALL SYN -j QUEUE', shell=True)
    else:
        subprocess.call('iptables -D OUTPUT -p tcp -m owner --uid-owner stowaway -j QUEUE', shell=True)
    subprocess.call('iptables -D INPUT -p icmp -m icmp --icmp-type 11 -j DROP', shell=True)

signal.signal(signal.SIGINT, clean_up)

try:
    if JUST_SMUGGLE_SYN:
        subprocess.call(
            'iptables -A OUTPUT -p tcp -m owner --uid-owner stowaway --tcp-flags ALL SYN -j QUEUE', shell=True)
    else:
        subprocess.call('iptables -A OUTPUT -p tcp -m owner --uid-owner stowaway -j QUEUE', shell=True)
    subprocess.call('iptables -A INPUT -p icmp -m icmp --icmp-type 11 -j DROP', shell=True)
    print('running..')
    nfqueue.run()
except KeyboardInterrupt:
    print('bye')
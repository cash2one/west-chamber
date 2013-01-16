from netfilterqueue import NetfilterQueue
import traceback
import subprocess
import signal
import dpkt
import socket

raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)

def split_ip_packet_to_overlapped_fragments(nfqueue_element):
    try:
        fragment1 = dpkt.ip.IP(nfqueue_element.get_payload())
        fragment1.off = 1 << 13 # Set More Fragment Flag
        fragment1.data = str(fragment1.data)[:16] + 3 * '0'
        fragment1.sum = 0
        fragment1.len = len(fragment1)
        fragment2 = dpkt.ip.IP(nfqueue_element.get_payload())
        fragment2.off = 2 # Offset is 2 * 8 bytes
        fragment2.data = str(fragment2.data)[16:]
        fragment2.sum = 0
        fragment2.len = len(fragment2)
        raw_socket.sendto(str(fragment1), ('pppoe-wan', 2048))
        raw_socket.sendto(str(fragment2), ('pppoe-wan', 2048))
        nfqueue_element.drop()
    except:
        traceback.print_exc()
        nfqueue_element.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, split_ip_packet_to_overlapped_fragments)

def clean_up(*args):
    subprocess.call('iptables -D OUTPUT -m owner --uid-owner stowaway -j QUEUE', shell=True)

signal.signal(signal.SIGINT, clean_up)

try:
    subprocess.call('iptables -I OUTPUT -m owner --uid-owner stowaway -j QUEUE', shell=True)
    print('running..')
    nfqueue.run()
except KeyboardInterrupt:
    print('bye')

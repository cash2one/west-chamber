from netfilterqueue import NetfilterQueue
import subprocess
import signal
import traceback
import socket

IMPERSONATOR_IP = 'x.x.x.x'
IMPERSONATOR_PORT = 19840

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

def smuggle_packet(nfqueue_element):
    try:
        original_packet = nfqueue_element.get_payload()
        print('smuggled')
        udp_socket.sendto(original_packet, (IMPERSONATOR_IP, IMPERSONATOR_PORT))
        nfqueue_element.drop()
    except:
        traceback.print_exc()
        nfqueue_element.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, smuggle_packet)

def clean_up(*args):
    subprocess.call('iptables -D OUTPUT -p udp --dst 8.8.8.8 --dport 53 -j QUEUE', shell=True)

signal.signal(signal.SIGINT, clean_up)

try:
    subprocess.call('iptables -I OUTPUT -p udp --dst 8.8.8.8 --dport 53 -j QUEUE', shell=True)
    print('running..')
    nfqueue.run()
except KeyboardInterrupt:
    print('bye')
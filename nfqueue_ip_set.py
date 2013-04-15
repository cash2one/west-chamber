from netfilterqueue import NetfilterQueue
import subprocess
import traceback
import signal
import dpkt
import socket

raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
raw_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

def handle_two_side_traffic(nfqueue_element):
    try:
        print('mark: %s' % nfqueue_element.get_mark())
        if nfqueue_element.get_mark():
            nfqueue_element.accept()
            return
        ip_packet = dpkt.ip.IP(nfqueue_element.get_payload())
        dst = socket.inet_ntoa(ip_packet.dst)
        nfqueue_element.set_mark(1)
        nfqueue_element.repeat()
    except:
        traceback.print_exc()
        nfqueue_element.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(0, handle_two_side_traffic)


def clean_up(*args):
    # will be called twice, don't know why
    subprocess.call('iptables -D OUTPUT -p tcp -j QUEUE', shell=True)


signal.signal(signal.SIGINT, clean_up)

try:
    subprocess.call('iptables -I OUTPUT -p tcp -j QUEUE', shell=True)
    print('running..')
    nfqueue.run()
except KeyboardInterrupt:
    print('bye')

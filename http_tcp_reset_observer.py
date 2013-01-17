from netfilterqueue import NetfilterQueue
import subprocess
import signal
import dpkt
import traceback
import socket
import sys

TARGET_IP = '173.252.110.27'

def observe_http_tcp_reset(nfqueue_element):
    try:
        ip_packet = dpkt.ip.IP(nfqueue_element.get_payload())
        tcp_packet = ip_packet.tcp
        print(repr(tcp_packet))
        if TARGET_IP == socket.inet_ntoa(ip_packet.src):
            if dpkt.tcp.TH_RST & tcp_packet.flags:
                sys.stdout.write('* ')
            print('ttl: %s, window: %s' % (ip_packet.ttl, tcp_packet.win))
        nfqueue_element.accept()
    except:
        traceback.print_exc()
        nfqueue_element.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, observe_http_tcp_reset)

def clean_up(*args):
    subprocess.call('iptables -D OUTPUT -p tcp --dst {} -j QUEUE'.format(TARGET_IP), shell=True)
    subprocess.call('iptables -D INPUT -p tcp --src {} -j QUEUE'.format(TARGET_IP), shell=True)

signal.signal(signal.SIGINT, clean_up)

try:
    subprocess.call('iptables -I INPUT -p tcp --src {} -j QUEUE'.format(TARGET_IP), shell=True)
    subprocess.call('iptables -I OUTPUT -p tcp --dst {} -j QUEUE'.format(TARGET_IP), shell=True)
    print('running..')
    nfqueue.run()
except KeyboardInterrupt:
    print('bye')

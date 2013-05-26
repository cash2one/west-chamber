from netfilterqueue import NetfilterQueue
import subprocess
import traceback
import signal
import socket
import dpkt


def handle_packet(nfqueue_element):
    try:
        ip_packet = dpkt.ip.IP(nfqueue_element.get_payload())
        dst = socket.inet_ntoa(ip_packet.dst)
        if dst.startswith('10.'):
            nfqueue_element.set_mark(0x1feed)
            print('matched', dst)
        else:
            nfqueue_element.set_mark(0x0feed)
            print('not matched', dst)
        nfqueue_element.repeat()
    except:
        traceback.print_exc()
        nfqueue_element.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(0, handle_packet)


def clean_up(*args):
    subprocess.call('iptables -D OUTPUT -p tcp -m mark ! --mark 0xfeed/0xffff -j NFQUEUE', shell=True)
    subprocess.call('iptables -D OUTPUT -p tcp -m mark --mark 0x0feed -j LOG --log-prefix "not matched"', shell=True)
    subprocess.call('iptables -D OUTPUT -p tcp -m mark --mark 0x1feed -j LOG --log-prefix "matched"', shell=True)


signal.signal(signal.SIGINT, clean_up)

try:
    subprocess.call('iptables -A OUTPUT -p tcp -m mark ! --mark 0xfeed/0xffff -j NFQUEUE', shell=True)
    subprocess.call('iptables -A OUTPUT -p tcp -m mark --mark 0x0feed -j LOG --log-prefix "not matched"', shell=True)
    subprocess.call('iptables -A OUTPUT -p tcp -m mark --mark 0x1feed -j LOG --log-prefix "matched"', shell=True)
    print('running..')
    nfqueue.run()
except KeyboardInterrupt:
    print('bye')

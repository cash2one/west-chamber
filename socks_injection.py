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
        ip_packet = dpkt.ip.IP(nfqueue_element.get_payload())
        if ip_packet.ttl in [255, 13]:
            nfqueue_element.accept()
            return
        else:
            dst = socket.inet_ntoa(ip_packet.dst)
            pos = ip_packet.tcp.data.find('Host:')
            if -1 == pos:
                nfqueue_element.accept()
                return
            pos += len('Host:')
            pos += 8
            if 'Host:' in ip_packet.tcp.data:
                first_part = ip_packet.tcp.data[:pos]
                second_part = ip_packet.tcp.data[pos:]

                second_packet = dpkt.ip.IP(str(ip_packet))
                second_packet.ttl = 255
                second_packet.tcp.seq += len(first_part)
                second_packet.tcp.data = second_part
                second_packet.sum = 0
                second_packet.tcp.sum = 0
                raw_socket.sendto(str(second_packet), (dst, 0))

                fake_first_packet = dpkt.ip.IP(str(ip_packet))
                fake_first_packet.ttl = 13
                fake_first_packet.tcp.data = (len(first_part) + 10) * '0'
                fake_first_packet.sum = 0
                fake_first_packet.tcp.sum = 0
                raw_socket.sendto(str(fake_first_packet), (dst, 0))

                fake_second_packet = dpkt.ip.IP(str(ip_packet))
                fake_second_packet.ttl = 13
                fake_second_packet.tcp.seq += len(first_part) + 10
                fake_second_packet.tcp.data = ': baidu.com\r\n\r\n'
                fake_second_packet.sum = 0
                fake_second_packet.tcp.sum = 0
                raw_socket.sendto(str(fake_second_packet), (dst, 0))

                first_packet = dpkt.ip.IP(str(ip_packet))
                first_packet.ttl = 255
                first_packet.tcp.data = first_part
                first_packet.sum = 0
                first_packet.tcp.sum = 0
                raw_socket.sendto(str(first_packet), (dst, 0))

            nfqueue_element.drop()
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
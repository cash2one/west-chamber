from netfilterqueue import NetfilterQueue
import socket
import traceback
import dpkt
import time
import subprocess
import signal

# It is working, although not working for ip blocked site as it is blocked in the layer below
# also for some downstream content still triggers RST

TTL_TO_GFW = 10

raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
raw_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

on_going_detections = {}
black_list = set()
white_list = set()

def handle_two_side_traffic(nfqueue_element):
    try:
        purge_time_out_detections()
        ip_packet = dpkt.ip.IP(nfqueue_element.get_payload())
        inject_same_seq_with_wrong_data(ip_packet)
        nfqueue_element.accept()
    except:
        traceback.print_exc()
        nfqueue_element.accept()


def inject_same_seq_with_wrong_data(ip_packet):
    tcp_packet = ip_packet.tcp
    connection = (
        socket.inet_ntoa(ip_packet.src), tcp_packet.sport,
        socket.inet_ntoa(ip_packet.dst), tcp_packet.dport)
    if socket.inet_ntoa(ip_packet.dst) in white_list:
        print('INJECT: {}'.format(connection))
        ip_packet.ttl = TTL_TO_GFW
        tcp_packet.data = 5 * '0'
        tcp_packet.sum = 0
        ip_packet.sum = 0
        raw_socket.sendto(str(ip_packet), (socket.inet_ntoa(ip_packet.dst), 0))
    elif socket.inet_ntoa(ip_packet.dst) in black_list or socket.inet_ntoa(ip_packet.src) in black_list:
        print('SKIP: {}'.format(connection))
    elif dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK == tcp_packet.flags:
        print('SYN ACK: {}'.format(connection))
        on_going_detections[connection] = {
            'signature': ip_packet.ttl, # the ttl tend to be consistent within one connection
            'started_at': time.time()
        }
        inject_wrong_ack_to_cause_rst_if_ttl_is_too_high(ip_packet)
        white_list.add(connection[0]) # assume we should inject by default
    elif dpkt.tcp.TH_RST & tcp_packet.flags:
        print('RST: {}'.format(connection))
        detection = on_going_detections.pop(connection, None)
        if not detection:
            return
        came_from_gfw = ip_packet.ttl != detection['signature']
        if came_from_gfw:
            print('GFW RST: {}'.format(connection))
            return
        duration = time.time() - detection['started_at']
        if duration > 1:
            print('RST, BUT TIMEOUT: {}'.format(connection))
            return
        print('TTL TOO HIGH FOR: {}'.format(connection))
        ip = connection[0]
        if ip in white_list:
            white_list.remove(ip)
        black_list.add(ip)


def inject_wrong_ack_to_cause_rst_if_ttl_is_too_high(syn_ack_packet):
    tcp_packet = dpkt.tcp.TCP(
        sport=syn_ack_packet.tcp.dport, dport=syn_ack_packet.tcp.sport,
        flags=dpkt.tcp.TH_ACK, seq=syn_ack_packet.tcp.ack - 2,
        data='', opts='')
    tcp_packet.ack = syn_ack_packet.tcp.seq
    ip_packet = dpkt.ip.IP(dst=syn_ack_packet.src, src=syn_ack_packet.dst, p=dpkt.ip.IP_PROTO_TCP)
    ip_packet.data = ip_packet.tcp = tcp_packet
    ip_packet.ttl = TTL_TO_GFW # if this packet reaches the end server, we can know from the RST
    raw_socket.sendto(str(ip_packet), (socket.inet_ntoa(ip_packet.dst), 0))


def purge_time_out_detections():
    time_out_checked_at = on_going_detections.get('time_out_checked_at', 0)
    if time.time() - time_out_checked_at < 5:
        return
    for connection, detection in on_going_detections.items():
        if isinstance(connection, tuple):
            if time.time() - detection['started_at'] > 1:
                on_going_detections.pop(connection)
    on_going_detections['time_out_checked_at'] = time.time()

nfqueue = NetfilterQueue()
nfqueue.bind(0, handle_two_side_traffic)


def clean_up(*args):
    # will be called twice, don't know why
    subprocess.call('iptables -D OUTPUT -p tcp -m owner --uid-owner 1001 -j QUEUE', shell=True)
    subprocess.call('iptables -D INPUT -p tcp --tcp-flags ALL SYN, ACK -j QUEUE', shell=True)
    subprocess.call('iptables -D INPUT -p tcp --tcp-flags RST RST -j QUEUE', shell=True)
    subprocess.call('iptables -D INPUT -p icmp -m icmp --icmp-type 11 -j DROP', shell=True)

signal.signal(signal.SIGINT, clean_up)

try:
    subprocess.call('iptables -A INPUT -p icmp -m icmp --icmp-type 11 -j DROP', shell=True)
    subprocess.call('iptables -A INPUT -p tcp --tcp-flags RST RST -j QUEUE', shell=True) # use RST to verify detection
    subprocess.call('iptables -A INPUT -p tcp --tcp-flags ALL SYN,ACK -j QUEUE', shell=True) # start injection & detection on SYN + ACK
    subprocess.call('iptables -A OUTPUT -p tcp -m owner --uid-owner 1001 -j QUEUE', shell=True)
    print('running..')
    nfqueue.run()
except KeyboardInterrupt:
    print('bye')

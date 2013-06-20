import socket
import ssl
import spdylay
import select
import time


def on_stream_close_cb(session, stream_id, status_code):
    print('close', stream_id)


def on_ctrl_recv_cb(session, frame):
    if frame.frame_type == spdylay.SYN_REPLY:
        print(frame.nv)


def on_data_chunk_recv_cb(session, flags, stream_id, data):
    print(data)


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock = ssl.wrap_socket(sock, npn_protocols=['spdy/3'])
    sock.connect(('198.52.103.140', 443))
    print(sock.selected_protocol())
    sock.setblocking(False)

    def send_cb(session, data):
        print('send cb')
        return sock.send(data)

    session = spdylay.Session(
        spdylay.CLIENT, spdylay.PROTO_SPDY3,
        send_cb=send_cb,
        on_ctrl_recv_cb=on_ctrl_recv_cb,
        on_data_chunk_recv_cb=on_data_chunk_recv_cb,
        on_stream_close_cb=on_stream_close_cb)
    session.submit_request(0,
                           [(':method', 'GET'),
                            (':scheme', 'http'),
                            (':path', '/'),
                            (':version', 'HTTP/1.1'),
                            (':host', 'www.baidu.com'),
                            ('accept', '*/*'),
                            ('user-agent', 'python-spdylay')])
    while True:
        if session.want_read():
            print('read')
            try:
                data = sock.recv(4096)
                if data:
                    session.recv(data)
                else:
                    break
            except ssl.SSLError:
                select.select([sock], [], [])
        if session.want_write():
            print('write')
            try:
                session.send()
            except ssl.SSLError:
                select.select([], [sock], [])
finally:
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()
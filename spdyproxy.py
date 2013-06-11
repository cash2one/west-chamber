import socket
import ssl
import spdylay

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('198.52.103.140', 443))
try:
    sock = ssl.wrap_socket(sock, server_side=False, do_handshake_on_connect=False)
    sock.do_handshake()
    sock.setblocking(False)
    session = spdylay.Session(spdylay.CLIENT, spdylay.PROTO_SPDY3)
    session.submit_request(0,
                           [(':method', 'GET'),
                            (':scheme', 'https'),
                            (':path', '/'),
                            (':version', 'HTTP/1.1'),
                            (':host', 'baidu.com:80'),
                            ('accept', '*/*'),
                            ('user-agent', 'python-spdylay')])
    session.send()
finally:
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()